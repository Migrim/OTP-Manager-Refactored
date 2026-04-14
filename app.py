from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, Response
import sqlite3
import json
import os
import uuid
from datetime import datetime
import time
from functools import wraps
from api import api_bp
from extensions import bcrypt
from logger import logger
import threading
from database import hourly_maintenance, acquire_lock, release_lock, get_missing_columns

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 900 
_login_attempts: dict = {}
_login_lock = threading.Lock()

app = Flask(__name__)
bcrypt.init_app(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join("instance", "otp.db")
SETTINGS_PATH = os.path.join(BASE_DIR, "settings.json")

def load_app_settings():
    defaults = {
        "host": "0.0.0.0",
        "port": 7440,
        "secret_key": "change-this-secret"
    }
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except:
        data = {}
    host = str(os.environ.get("OTP_HOST") or data.get("host") or defaults["host"]).strip() or defaults["host"]
    try:
        port = int(os.environ.get("OTP_PORT") or data.get("port") or defaults["port"])
    except:
        port = defaults["port"]
    secret_key = str(os.environ.get("OTP_SECRET_KEY") or data.get("secret_key") or defaults["secret_key"]).strip() or defaults["secret_key"]
    return {
        "host": host,
        "port": port,
        "secret_key": secret_key
    }

APP_SETTINGS = load_app_settings()

app.secret_key = APP_SETTINGS["secret_key"]
app.register_blueprint(api_bp, url_prefix="/api")

VERSION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
INDEX_TEMPLATE_PRESENT = os.path.isfile(os.path.join(app.template_folder or "templates", "index.html"))

_DB_MISSING_COLS = get_missing_columns()

def get_app_version():
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as f:
            version = f.read().strip()
            return version or "0.0.0"
    except FileNotFoundError:
        return "0.0.0"
    except Exception:
        return "0.0.0"

def user_ref(user_id=None, username=None):
    try:
        if user_id is not None and username is None:
            with sqlite3.connect(DB_PATH) as db:
                c = db.cursor()
                c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                r = c.fetchone()
                if r:
                    username = r[0]
        if username is not None and user_id is None:
            with sqlite3.connect(DB_PATH) as db:
                c = db.cursor()
                c.execute("SELECT id FROM users WHERE username = ?", (username,))
                r = c.fetchone()
                if r:
                    user_id = r[0]
    except:
        pass
    uname = username if username is not None else "unknown"
    uid = user_id if user_id is not None else "unknown"
    return f"{uname} with id {uid}"

def u(user_id):
    if getattr(g, "user_id", None) == user_id and getattr(g, "username", None):
        return user_ref(user_id=user_id, username=g.username)
    return user_ref(user_id=user_id)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.logged_in:
            logger.warning("Unauthorized access attempt (not logged in).")
            flash("You first need to Login.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.is_admin:
            logger.warning(f"{u(g.user_id)} attempted admin-only access.")
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

def has_permission(permission_name):
    if not getattr(g, "logged_in", False):
        return False
    if getattr(g, "is_admin", False):
        return True
    return bool(getattr(g, permission_name, False))

def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.logged_in:
                logger.warning("Unauthorized access attempt (not logged in).")
                flash("You first need to Login.", "warning")
                return redirect(url_for("login"))

            if not has_permission(permission_name):
                logger.warning(f"{u(g.user_id)} missing permission '{permission_name}'.")
                flash("Access denied.", "error")
                return redirect(url_for("home"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def row_to_settings(row):
    if not row:
        return {}
    return {
        "show_timer": int(row[7] or 0),
        "show_otp_type": int(row[8] or 0),
        "show_content_titles": int(row[9] or 0),
        "alert_color": row[10] or "#333333",
        "text_color": row[11] or "#FFFFFF",
        "show_emails": int(row[12] or 0),
        "show_company": int(row[13] or 0),
        "blur_on_inactive": int(row[14] or 0),
        "show_including_admin_on_top": int(row[15] or 0),
        "hide_codes_by_default": int(row[16] or 0),
        "hide_secret_field": int(row[17] or 0),
        "show_search_and_link": int(row[18] or 0),
    }

def _is_rate_limited(ip: str) -> float | None:
    with _login_lock:
        entry = _login_attempts.get(ip)
        if not entry:
            return None
        now = time.time()
        if entry["locked_until"] and now < entry["locked_until"]:
            return entry["locked_until"] - now
        if now - entry["window_start"] > _LOGIN_LOCKOUT_SECONDS:
            del _login_attempts[ip]
        return None

def _record_failed_login(ip: str):
    now = time.time()
    with _login_lock:
        entry = _login_attempts.get(ip)
        if not entry or now - entry["window_start"] > _LOGIN_LOCKOUT_SECONDS:
            _login_attempts[ip] = {"count": 1, "window_start": now, "locked_until": 0.0}
        else:
            entry["count"] += 1
            if entry["count"] >= _LOGIN_MAX_ATTEMPTS:
                entry["locked_until"] = now + _LOGIN_LOCKOUT_SECONDS

def _clear_login_attempts(ip: str):
    with _login_lock:
        _login_attempts.pop(ip, None)

@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Error: {request.path} not found.")
    return render_template("404.html"), 404

@app.before_request
def block_on_schema_mismatch():
    if _DB_MISSING_COLS and request.endpoint != "static":
        template_path = os.path.join(app.template_folder or "templates", "db_upgrade.html")
        with open(template_path, "r", encoding="utf-8") as f:
            html = f.read()
        return Response(html, status=503, mimetype="text/html")

@app.before_request
def load_user():
    g.user_id = session.get("user_id")
    g.is_admin = session.get("is_admin", False)
    g.logged_in = g.user_id is not None
    g.user_settings = {}
    g.username = None
    g.can_delete = False
    g.can_edit = False
    g.can_add_companies = False
    g.can_delete_companies = False
    g.can_add_secrets = False
    g.can_add_users = False

    if g.logged_in:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT
                    id, username, password, last_login_time, session_token,
                    is_admin, can_delete, can_edit, can_add_companies,
                    can_delete_companies, can_add_secrets, can_add_users,
                    pinned, show_timer, show_otp_type, show_content_titles,
                    alert_color, text_color, show_emails, show_company,
                    blur_on_inactive, show_including_admin_on_top, hide_codes_by_default, hide_secret_field,
                    show_search_and_link
                FROM users
                WHERE id = ?
            """, (g.user_id,))
            row = cursor.fetchone()

            if row:
                db_token = row[4]
                session_token = session.get("session_token")
                if db_token and session_token != db_token:
                    session.clear()
                    g.logged_in = False
                    g.user_id = None
                    return

                g.username = row[1]
                g.is_admin = bool(row[5])
                g.can_delete = bool(row[6]) or g.is_admin
                g.can_edit = bool(row[7]) or g.is_admin
                g.can_add_companies = bool(row[8]) or g.is_admin
                g.can_delete_companies = bool(row[9]) or g.is_admin
                g.can_add_secrets = bool(row[10]) or g.is_admin
                g.can_add_users = bool(row[11]) or g.is_admin
                g.user_settings = {
                    "show_timer": int(row[13] or 0),
                    "show_otp_type": int(row[14] or 0),
                    "show_content_titles": int(row[15] or 0),
                    "alert_color": row[16] or "#333333",
                    "text_color": row[17] or "#FFFFFF",
                    "show_emails": int(row[18] or 0),
                    "show_company": int(row[19] or 0),
                    "blur_on_inactive": int(row[20] or 0),
                    "show_including_admin_on_top": int(row[21] or 0),
                    "hide_codes_by_default": int(row[22] or 0),
                    "hide_secret_field": int(row[23] or 0),
                    "show_search_and_link": int(row[24] or 0),
                }

@app.context_processor
def inject_user():
    return dict(
        is_logged_in=g.logged_in,
        is_admin=g.is_admin,
        current_user_id=g.user_id,
        can_delete=g.can_delete,
        can_edit=g.can_edit,
        can_add_companies=g.can_add_companies,
        can_delete_companies=g.can_delete_companies,
        can_add_secrets=g.can_add_secrets,
        can_add_users=g.can_add_users,
        user_settings=g.user_settings,
        show_index_button=INDEX_TEMPLATE_PRESENT,
        app_version=get_app_version()
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    t0 = time.perf_counter()

    if g.logged_in:
        logger.info(f"{u(g.user_id)} attempted to access login while already logged in.")
        flash("You are already logged in.", "info")
        return redirect(url_for("home"))

    if request.method == "POST":
        ip = request.remote_addr
        remaining = _is_rate_limited(ip)
        if remaining is not None:
            wait_min = int(remaining // 60) + 1
            logger.warning(f"Rate limit hit on /login from IP={ip} ({remaining:.0f}s remaining)")
            flash(f"Too many failed login attempts. Try again in {wait_min} minute(s).", "error")
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        keep_logged_in = "keep_logged_in" in request.form

        logger.info(f"Login attempt start username='{username}' keep_logged_in={keep_logged_in}")

        try:
            with sqlite3.connect(DB_PATH) as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()

            if user:
                user_id = user[0]
                stored_password = user[2]
                is_admin = bool(user[5])
                logger.debug(f"Login: Found user id={user_id} admin={is_admin}")

                if stored_password == password or stored_password.strip() == "":
                    logger.warning(f"{user_ref(user_id=user_id, username=username)} using unhashed/empty password — migrating to hash.")
                    hashed = bcrypt.generate_password_hash(stored_password or password).decode("utf-8")
                    with sqlite3.connect(DB_PATH) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
                        db.commit()
                    stored_password = hashed
                    flash("Password has been migrated to a secure hash.", "info")

                if bcrypt.check_password_hash(stored_password, password):
                    _clear_login_attempts(ip)
                    session_token = str(uuid.uuid4())
                    session["user_id"] = user_id
                    session["is_admin"] = is_admin
                    session["session_token"] = session_token
                    session.permanent = keep_logged_in

                    with sqlite3.connect(DB_PATH) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE users SET session_token = ? WHERE id = ?", (session_token, user_id))
                        cursor.execute("UPDATE statistics SET logins_today = logins_today + 1")
                        db.commit()

                    logger.info(f"{user_ref(user_id=user_id, username=username)} login successful. permanent_session={keep_logged_in}")
                    if is_admin and password == "1234":
                        logger.warning(f"{user_ref(user_id=user_id, username=username)} logged in with default admin password.")
                        flash("You are using the default password. Please change it.", "warning")

                    dt = round((time.perf_counter() - t0) * 1000)
                    logger.debug(f"Login processing complete for {user_ref(user_id=user_id, username=username)} duration_ms={dt}")
                    return redirect(url_for("home"))
                else:
                    _record_failed_login(ip)
                    logger.warning(f"{user_ref(username=username)} failed login: invalid password.")
                    flash("Invalid credentials!", "error")
                    return redirect(url_for("login"))
            else:
                _record_failed_login(ip)
                logger.warning(f"Login failed: username='{username}' not found.")
                flash("User not found.", "error")
                return redirect(url_for("login"))

        except Exception as e:
            logger.exception(f"Login error for username='{username}': {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    logger.info(f"{u(user_id)} logged out.")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("home.html")

@app.route("/users")
@login_required
@permission_required("can_add_users")
def users():
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT
                id, username, is_admin,
                can_delete, can_edit, can_add_companies,
                can_delete_companies, can_add_secrets, can_add_users
            FROM users
            ORDER BY username ASC
        """)
        user_list = cursor.fetchall()

    return render_template("users.html", users=user_list, current_user_id=g.user_id)

@app.route("/companies")
@login_required
def companies():
    if not (has_permission("can_add_companies") or has_permission("can_delete_companies")):
        logger.warning(f"{u(g.user_id)} attempted to access /companies without permission.")
        flash("Access denied.", "error")
        return redirect(url_for("home"))

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT c.company_id,
                   c.name,
                   c.kundennummer,
                   COUNT(s.id) AS secret_count
            FROM companies c
            LEFT JOIN otp_secrets s ON s.company_id = c.company_id
            GROUP BY c.company_id, c.name, c.kundennummer
            ORDER BY c.name ASC
            """
        )
        company_list = cursor.fetchall()

    return render_template("companies.html", companies=company_list)

@app.route("/companies/json")
@login_required
def companies_json():
    if not has_permission("can_add_companies"):
        logger.warning(f"{u(g.user_id)} attempted to access /companies/json without permission.")
        return jsonify({"error": "Missing permission: can_add_companies"}), 403

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name FROM companies ORDER BY name ASC")
        company_list = cursor.fetchall()
    return jsonify([{"id": row[0], "name": row[1]} for row in company_list])

@app.route("/settings")
@login_required
def settings():
    if g.user_settings:
        return render_template("settings.html", user=g.user_settings)
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        row = cursor.fetchone()
        user = row_to_settings(row)
        return render_template("settings.html", user=user)

@app.route("/update-settings", methods=["POST"])
@login_required
def update_settings():
    payload = {
        "show_timer": 1 if request.form.get("show_timer") in ("on", "true", "1") else 0,
        "show_otp_type": 1 if request.form.get("show_otp_type") in ("on", "true", "1") else 0,
        "show_content_titles": 1 if request.form.get("show_content_titles") in ("on", "true", "1") else 0,
        "show_emails": 1 if request.form.get("show_emails") in ("on", "true", "1") else 0,
        "show_company": 1 if request.form.get("show_company") in ("on", "true", "1") else 0,
        "blur_on_inactive": 1 if request.form.get("blur_on_inactive") in ("on", "true", "1") else 0,
        "show_including_admin_on_top": 1 if request.form.get("show_including_admin_on_top") in ("on", "true", "1") else 0,
        "hide_codes_by_default": 1 if request.form.get("hide_codes_by_default") in ("on", "true", "1") else 0,
        "hide_secret_field": 1 if request.form.get("hide_secret_field") in ("on", "true", "1") else 0,
        "show_search_and_link": 1 if request.form.get("show_search_and_link") in ("on", "true", "1") else 0,
    }
    alert_color = request.form.get("alert_color")
    text_color = request.form.get("text_color")
    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute(
                """
                UPDATE users
                SET show_timer = ?,
                    show_otp_type = ?,
                    show_content_titles = ?,
                    show_emails = ?,
                    show_company = ?,
                    blur_on_inactive = ?,
                    show_including_admin_on_top = ?,
                    hide_codes_by_default = ?,
                    hide_secret_field = ?,
                    show_search_and_link = ?,
                    alert_color = COALESCE(?, alert_color),
                    text_color = COALESCE(?, text_color)
                WHERE id = ?
                """,
                (
                    payload["show_timer"],
                    payload["show_otp_type"],
                    payload["show_content_titles"],
                    payload["show_emails"],
                    payload["show_company"],
                    payload["blur_on_inactive"],
                    payload["show_including_admin_on_top"],
                    payload["hide_codes_by_default"],
                    payload["hide_secret_field"],
                    payload["show_search_and_link"],
                    alert_color,
                    text_color,
                    g.user_id,
                ),
            )
            db.commit()
        logger.info(f"Updated settings for {u(g.user_id)}: {payload}")
        flash("Settings saved.", "success")
    except Exception as e:
        logger.exception(f"Error updating settings for {u(g.user_id)}: {e}")
        flash("Could not save settings.", "error")
    return redirect(url_for("settings"))

@app.route("/add", methods=["GET", "POST"])
@login_required
@permission_required("can_add_secrets")
def add():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email", "none")
        secret = request.form.get("secret")
        otp_type = request.form.get("otp_type", "totp")
        refresh_time = int(request.form.get("refresh_time", 30))
        company_id = int(request.form.get("company_id", 1))

        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute(
                """
                INSERT INTO otp_secrets (name, email, secret, otp_type, refresh_time, company_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, email, secret, otp_type, refresh_time, company_id),
            )
            db.commit()

        logger.info(f"{u(g.user_id)} added new OTP entry: {name}")
        return redirect(url_for("home"))

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name FROM companies ORDER BY name ASC")
        companies = cursor.fetchall()

    return render_template("add.html", companies=companies)

@app.route("/toggle-pin", methods=["POST"])
@login_required
def toggle_pin():
    data = request.get_json()
    secret_id = str(data.get("secret_id"))
    user_id = session["user_id"]

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT pinned FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        pinned = set(filter(None, row[0].split(","))) if row and row[0] else set()

        if secret_id in pinned:
            pinned.remove(secret_id)
            new_state = False
        else:
            pinned.add(secret_id)
            new_state = True

        cursor.execute("UPDATE users SET pinned = ? WHERE id = ?", (",".join(pinned), user_id))
        db.commit()

    logger.info(f"{u(user_id)} {'pinned' if new_state else 'unpinned'} secret ID {secret_id}")
    return jsonify({"pinned": new_state})

@app.route("/api/user-pinned")
@login_required
def user_pinned():
    user_id = session["user_id"]
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT pinned FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return jsonify(row[0].split(","))
        return jsonify([])

@app.route("/search.html")
@login_required
def search_page():
    search_raw = request.args.get("search")
    if search_raw is None:
        search_raw = request.args.get("q", "")
    q_raw = search_raw
    q = q_raw.strip().lower()

    company_raw = request.args.get("company", "")
    company_q = company_raw.strip().lower()

    admin_on_top = g.user_settings.get("show_including_admin_on_top", 0)

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()

        if company_q:
            cursor.execute("SELECT company_id, name FROM companies WHERE LOWER(name) = ?", (company_q,))
            company = cursor.fetchone()
            if company:
                company_id, company_name = company
                if admin_on_top:
                    cursor.execute(
                        """
                        SELECT s.name, s.email, c.name
                        FROM otp_secrets s
                        LEFT JOIN companies c ON s.company_id = c.company_id
                        WHERE s.company_id = ?
                        ORDER BY CASE WHEN LOWER(s.name) LIKE '%admin%' THEN 0 ELSE 1 END ASC, s.name ASC
                        """,
                        (company_id,),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT s.name, s.email, c.name
                        FROM otp_secrets s
                        LEFT JOIN companies c ON s.company_id = c.company_id
                        WHERE s.company_id = ?
                        ORDER BY s.name ASC
                        """,
                        (company_id,),
                    )
                results = cursor.fetchall()
                logger.info(f"{u(g.user_id)} company-search '{company_name}' — {len(results)} results.")
                return render_template("search.html", query=company_name, results=results)

            logger.info(f"{u(g.user_id)} company-search '{company_raw}' — 0 results (company not found).")
            return render_template("search.html", query=company_raw, results=[])

        cursor.execute("SELECT company_id, name FROM companies WHERE LOWER(name) = ?", (q,))
        company = cursor.fetchone()
        if company and q:
            return redirect(url_for("search_page", company=search_raw.strip() if isinstance(search_raw, str) else q_raw.strip()))

        cursor.execute(
            """
            SELECT s.name, s.email, c.name
            FROM otp_secrets s
            LEFT JOIN companies c ON s.company_id = c.company_id
            WHERE LOWER(s.name) LIKE ? OR LOWER(s.email) LIKE ? OR LOWER(c.name) LIKE ?
            ORDER BY c.name ASC, s.name ASC
            """,
            (f"%{q}%", f"%{q}%", f"%{q}%"),
        )
        results = cursor.fetchall()

    logger.info(f"{u(g.user_id)} searched for '{search_raw if isinstance(search_raw, str) else q_raw}' — {len(results)} results.")
    return render_template("search.html", query=search_raw if isinstance(search_raw, str) else q_raw, results=results)

@app.route("/logs")
@login_required
@admin_required
def view_logs():
    if not g.is_admin:
        flash("Access denied.", "error")
        logger.warning(f"{u(g.user_id)} tried to access /logs without admin rights.")
        return redirect(url_for("home"))

    selected_day = request.args.get("day") or datetime.now().strftime("%Y-%m-%d")
    folder_path = os.path.join("logs", selected_day)
    log_file = os.path.join(folder_path, "app.log")

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()[-500:]
    except FileNotFoundError:
        lines = []

    log_folders = sorted(
        [name for name in os.listdir("logs") if os.path.isdir(os.path.join("logs", name))],
        reverse=True,
    )

    return render_template("logs.html", logs=lines, log_folders=log_folders, selected_day=selected_day)

def maintenance_loop():
    while True:
        try:
            if acquire_lock():
                try:
                    hourly_maintenance()
                finally:
                    release_lock()
            else:
                logger.warning("skip maintenance, lock present")
        except Exception as e:
            logger.critical(f"Database maintenance error: {e}")
        time.sleep(3600)

if __name__ == "__main__":
    start_thread = (os.environ.get("WERKZEUG_RUN_MAIN") == "true") or not app.debug
    if start_thread:
        t = threading.Thread(target=maintenance_loop, daemon=True)
        t.start()
    app.run(host=APP_SETTINGS["host"], port=APP_SETTINGS["port"], debug=True, use_reloader=True)
