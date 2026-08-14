from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, Response
import sqlite3
import json
import os
import sys
import shutil
import uuid
import urllib.request
import subprocess
import signal
import struct
from datetime import datetime
import time
from functools import wraps
from api import api_bp
from extensions import bcrypt
from logger import logger
import threading
from flask_socketio import SocketIO, emit, join_room, disconnect
from database import (
    hourly_maintenance, acquire_lock, release_lock, get_missing_columns,
    ensure_dirs, init_db, backup_db, load_state, save_state,
    normalize_secrets, check_orphans, BACKUP_DIR,
)

try:
    import pty
    import fcntl
    import termios
except ImportError:
    pty = fcntl = termios = None

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 900
_login_attempts: dict = {}
_login_lock = threading.Lock()

app = Flask(__name__)
bcrypt.init_app(app)
socketio = SocketIO(app, async_mode="threading")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join("instance", "otp.db")
SETTINGS_PATH = os.path.join(BASE_DIR, "settings.json")
AVATAR_DIR = os.path.join(BASE_DIR, "static", "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
AVATAR_EXTS = ("png", "jpg", "webp")
AVATAR_MAX_BYTES = 3 * 1024 * 1024
SERVER_START_TIME = time.time()
STATE_PATH = os.path.join(BASE_DIR, "otp-server.state.json")
UPDATE_STATUS_PATH = os.path.join(BASE_DIR, "otp-server.update-status.json")

def read_update_status():
    try:
        with open(UPDATE_STATUS_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def get_server_started_at():
    # otp-server.state.json is written by start.py when it launches this
    # process, so it reflects the real supervised uptime rather than
    # whenever this Python interpreter last happened to import app.py.
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        started_at = data.get("started_at")
        if started_at:
            return float(started_at)
    except Exception:
        pass
    return SERVER_START_TIME

# ---- remote console ----------------------------------------------------
# Bridges a single shared start.py dashboard, running in a real pty on the
# server, to admins connected over the /console websocket namespace. All
# connected admins see the same session (like `screen -x`) since the CLI is
# meant to be driven by one operator at a time.
CONSOLE_CMD = [sys.executable or "python3", os.path.join(BASE_DIR, "start.py")]
_CONSOLE_BUFFER_MAX = 200_000
_console_lock = threading.Lock()
_console = {"proc": None, "fd": None}
_console_buffer = bytearray()

def _console_reader(fd, proc):
    while True:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        with _console_lock:
            _console_buffer.extend(data)
            if len(_console_buffer) > _CONSOLE_BUFFER_MAX:
                del _console_buffer[: len(_console_buffer) - _CONSOLE_BUFFER_MAX]
        socketio.emit("output", data.decode("utf-8", "replace"), namespace="/console", room="console")
    proc.wait()
    with _console_lock:
        if _console["proc"] is proc:
            _console["proc"] = None
            _console["fd"] = None
    socketio.emit("exited", {}, namespace="/console", room="console")

def _console_start():
    if pty is None:
        return False, "Remote console isn't supported on this platform."
    with _console_lock:
        proc = _console["proc"]
        if proc is not None and proc.poll() is None:
            return True, None
        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        try:
            proc = subprocess.Popen(
                CONSOLE_CMD,
                cwd=BASE_DIR,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                preexec_fn=os.setsid,
                close_fds=True,
            )
        except Exception as e:
            os.close(master_fd)
            os.close(slave_fd)
            return False, f"Failed to start console: {e}"
        os.close(slave_fd)
        _console["proc"] = proc
        _console["fd"] = master_fd
        _console_buffer.clear()
        threading.Thread(target=_console_reader, args=(master_fd, proc), daemon=True).start()
        return True, None

def _console_write(data: bytes):
    with _console_lock:
        fd = _console["fd"]
    if fd is not None:
        try:
            os.write(fd, data)
        except OSError:
            pass

def _console_resize(rows, cols):
    with _console_lock:
        fd = _console["fd"]
        proc = _console["proc"]
    if fd is None or fcntl is None or termios is None:
        return
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        if proc is not None:
            os.killpg(os.getpgid(proc.pid), signal.SIGWINCH)
    except OSError:
        pass

def _console_stop():
    with _console_lock:
        proc = _console["proc"]
        fd = _console["fd"]
        _console["proc"] = None
        _console["fd"] = None
    if proc is not None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            pass
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass

def _console_authorized():
    load_user()
    return bool(g.logged_in and g.is_admin)

@socketio.on("connect", namespace="/console")
def console_connect():
    if not _console_authorized():
        logger.warning("rejected unauthorized remote console connection attempt")
        disconnect()
        return False
    join_room("console")
    ok, err = _console_start()
    if not ok:
        emit("error", {"message": err})
        return
    with _console_lock:
        snapshot = bytes(_console_buffer)
    if snapshot:
        emit("output", snapshot.decode("utf-8", "replace"))
    logger.info(f"{u(g.user_id)} opened the remote console")

@socketio.on("input", namespace="/console")
def console_input(data):
    if not _console_authorized() or not isinstance(data, str):
        return
    _console_write(data.encode("utf-8"))

@socketio.on("resize", namespace="/console")
def console_resize_evt(data):
    if not _console_authorized() or not isinstance(data, dict):
        return
    try:
        rows = int(data.get("rows", 24))
        cols = int(data.get("cols", 80))
    except (TypeError, ValueError):
        return
    _console_resize(rows, cols)

@socketio.on("stop_console", namespace="/console")
def console_stop_evt():
    if not _console_authorized():
        return
    logger.warning(f"{u(g.user_id)} ended the remote console session")
    _console_stop()
    socketio.emit("exited", {}, namespace="/console", room="console")

def sniff_avatar_ext(data):
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None

def get_avatar_url(user_id):
    if not user_id:
        return None
    for ext in AVATAR_EXTS:
        path = os.path.join(AVATAR_DIR, f"{user_id}.{ext}")
        if os.path.isfile(path):
            return url_for("static", filename=f"avatars/{user_id}.{ext}") + f"?v={int(os.path.getmtime(path))}"
    return None

def remove_avatar_files(user_id):
    for ext in AVATAR_EXTS:
        path = os.path.join(AVATAR_DIR, f"{user_id}.{ext}")
        if os.path.isfile(path):
            os.remove(path)

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
    company_name = str(data.get("company_name") or "").strip()
    return {
        "host": host,
        "port": port,
        "secret_key": secret_key,
        "company_name": company_name
    }

APP_SETTINGS = load_app_settings()

app.secret_key = APP_SETTINGS["secret_key"]
app.register_blueprint(api_bp, url_prefix="/api")

VERSION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
INDEX_TEMPLATE_PRESENT = os.path.isfile(os.path.join(app.template_folder or "templates", "index.html"))

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
            flash("You need to log in first.", "warning")
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
                flash("You need to log in first.", "warning")
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
        "show_timer": int(row[13] or 0),
        "show_otp_type": int(row[14] or 0),
        "show_emails": int(row[15] or 0),
        "show_company": int(row[16] or 0),
        "blur_on_inactive": int(row[17] or 0),
        "show_including_admin_on_top": int(row[18] or 0),
        "hide_codes_by_default": int(row[19] or 0),
        "hide_secret_field": int(row[20] or 0),
        "show_search_and_link": int(row[21] or 0),
        "show_pinned_in_sidebar": int(row[22] or 0),
        "only_pinned_in_sidebar": int(row[23] or 0),
        "bg_animation_style": row[24] or "turbulence",
        "bg_animation_intensity": int(row[25]) if row[25] is not None else 100,
        "blur_on_inactive_delay": int(row[26]) if row[26] is not None else 60,
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
    if request.endpoint == "static":
        return
    if get_missing_columns():
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
                    pinned, show_timer, show_otp_type, show_emails, show_company,
                    blur_on_inactive, show_including_admin_on_top, hide_codes_by_default, hide_secret_field,
                    show_search_and_link, show_pinned_in_sidebar, only_pinned_in_sidebar, bg_animation_style,
                    bg_animation_intensity, blur_on_inactive_delay
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
                    "show_emails": int(row[15] or 0),
                    "show_company": int(row[16] or 0),
                    "blur_on_inactive": int(row[17] or 0),
                    "show_including_admin_on_top": int(row[18] or 0),
                    "hide_codes_by_default": int(row[19] or 0),
                    "hide_secret_field": int(row[20] or 0),
                    "show_search_and_link": int(row[21] or 0),
                    "show_pinned_in_sidebar": int(row[22] or 0),
                    "only_pinned_in_sidebar": int(row[23] or 0),
                    "bg_animation_style": row[24] or "turbulence",
                    "bg_animation_intensity": int(row[25]) if row[25] is not None else 100,
                    "blur_on_inactive_delay": int(row[26]) if row[26] is not None else 60,
                }

@app.context_processor
def inject_user():
    return dict(
        is_logged_in=g.logged_in,
        is_admin=g.is_admin,
        current_user_id=g.user_id,
        username=g.username,
        avatar_url=get_avatar_url(g.user_id) if g.logged_in else None,
        can_delete=g.can_delete,
        can_edit=g.can_edit,
        can_add_companies=g.can_add_companies,
        can_delete_companies=g.can_delete_companies,
        can_add_secrets=g.can_add_secrets,
        can_add_users=g.can_add_users,
        user_settings=g.user_settings,
        show_index_button=INDEX_TEMPLATE_PRESENT,
        app_version=get_app_version(),
        current_year=datetime.now().year,
        company_brand=APP_SETTINGS.get("company_name", "")
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

    users_with_avatars = [tuple(u) + (get_avatar_url(u[0]),) for u in user_list]
    return render_template("users.html", users=users_with_avatars, current_user_id=g.user_id)

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
                   COUNT(s.id) AS secret_count,
                   c.login_enabled
            FROM companies c
            LEFT JOIN otp_secrets s ON s.company_id = c.company_id
            GROUP BY c.company_id, c.name, c.kundennummer, c.login_enabled
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
        cursor.execute("""
                SELECT
                    id, username, password, last_login_time, session_token,
                    is_admin, can_delete, can_edit, can_add_companies,
                    can_delete_companies, can_add_secrets, can_add_users,
                    pinned, show_timer, show_otp_type, show_emails, show_company,
                    blur_on_inactive, show_including_admin_on_top, hide_codes_by_default,
                    hide_secret_field, show_search_and_link, show_pinned_in_sidebar, only_pinned_in_sidebar,
                    bg_animation_style, bg_animation_intensity, blur_on_inactive_delay
                FROM users WHERE id = ?
            """, (session["user_id"],))
        row = cursor.fetchone()
        user = row_to_settings(row)
        return render_template("settings.html", user=user)

@app.route("/update-settings", methods=["POST"])
@login_required
def update_settings():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    data = request.get_json(silent=True) if request.is_json else None
    if data is None:
        data = request.form

    def flag(name):
        return 1 if data.get(name) in ("on", "true", "1", True, 1) else 0

    try:
        bg_animation_intensity = int(data.get("bg_animation_intensity", 100))
    except (TypeError, ValueError):
        bg_animation_intensity = 100
    bg_animation_intensity = max(0, min(200, bg_animation_intensity))

    try:
        blur_on_inactive_delay = int(data.get("blur_on_inactive_delay", 60))
    except (TypeError, ValueError):
        blur_on_inactive_delay = 60
    if blur_on_inactive_delay not in (0, 10, 30, 60):
        blur_on_inactive_delay = 60

    payload = {
        "show_timer": flag("show_timer"),
        "show_otp_type": flag("show_otp_type"),
        "show_emails": flag("show_emails"),
        "show_company": flag("show_company"),
        "blur_on_inactive": flag("blur_on_inactive"),
        "show_including_admin_on_top": flag("show_including_admin_on_top"),
        "hide_codes_by_default": flag("hide_codes_by_default"),
        "hide_secret_field": flag("hide_secret_field"),
        "show_search_and_link": flag("show_search_and_link"),
        "show_pinned_in_sidebar": flag("show_pinned_in_sidebar"),
        "only_pinned_in_sidebar": flag("only_pinned_in_sidebar"),
        "bg_animation_style": data.get("bg_animation_style")
            if data.get("bg_animation_style") in ("contours", "streaks", "turbulence") else "turbulence",
        "bg_animation_intensity": bg_animation_intensity,
        "blur_on_inactive_delay": blur_on_inactive_delay,
    }
    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute(
                """
                UPDATE users
                SET show_timer = ?,
                    show_otp_type = ?,
                    show_emails = ?,
                    show_company = ?,
                    blur_on_inactive = ?,
                    show_including_admin_on_top = ?,
                    hide_codes_by_default = ?,
                    hide_secret_field = ?,
                    show_search_and_link = ?,
                    show_pinned_in_sidebar = ?,
                    only_pinned_in_sidebar = ?,
                    bg_animation_style = ?,
                    bg_animation_intensity = ?,
                    blur_on_inactive_delay = ?
                WHERE id = ?
                """,
                (
                    payload["show_timer"],
                    payload["show_otp_type"],
                    payload["show_emails"],
                    payload["show_company"],
                    payload["blur_on_inactive"],
                    payload["show_including_admin_on_top"],
                    payload["hide_codes_by_default"],
                    payload["hide_secret_field"],
                    payload["show_search_and_link"],
                    payload["show_pinned_in_sidebar"],
                    payload["only_pinned_in_sidebar"],
                    payload["bg_animation_style"],
                    payload["bg_animation_intensity"],
                    payload["blur_on_inactive_delay"],
                    g.user_id,
                ),
            )
            db.commit()
        logger.info(f"Updated settings for {u(g.user_id)}: {payload}")
        if is_ajax:
            return jsonify({"message": "Settings saved."})
        flash("Settings saved.", "success")
    except Exception as e:
        logger.exception(f"Error updating settings for {u(g.user_id)}: {e}")
        if is_ajax:
            return jsonify({"error": "Could not save settings."}), 500
        flash("Could not save settings.", "error")
    return redirect(url_for("settings"))

@app.route("/api/account/avatar", methods=["POST"])
@login_required
def upload_avatar():
    file = request.files.get("avatar")
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400
    data = file.read(AVATAR_MAX_BYTES + 1)
    if len(data) > AVATAR_MAX_BYTES:
        return jsonify({"error": "Image must be 3MB or smaller"}), 400
    ext = sniff_avatar_ext(data)
    if not ext:
        return jsonify({"error": "Only PNG, JPEG, or WebP images are allowed"}), 400
    remove_avatar_files(g.user_id)
    with open(os.path.join(AVATAR_DIR, f"{g.user_id}.{ext}"), "wb") as f:
        f.write(data)
    logger.info(f"{u(g.user_id)} updated their profile photo")
    return jsonify({"avatar_url": get_avatar_url(g.user_id)})

@app.route("/api/account/avatar", methods=["DELETE"])
@login_required
def delete_avatar():
    remove_avatar_files(g.user_id)
    logger.info(f"{u(g.user_id)} removed their profile photo")
    return jsonify({"message": "Profile photo removed"})

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
    """Search now lives on the home screen — keep old links working."""
    q = (request.args.get("search") or request.args.get("q") or "").strip()
    company = (request.args.get("company") or "").strip()
    if company:
        return redirect(url_for("home", company=company))
    return redirect(url_for("home", q=q) if q else url_for("home"))

@app.route("/logs")
@login_required
@admin_required
def view_logs():
    today = datetime.now().strftime("%Y-%m-%d")
    selected_day = request.args.get("day") or today

    try:
        log_folders = sorted(
            [name for name in os.listdir("logs") if os.path.isdir(os.path.join("logs", name))],
            reverse=True,
        )
    except FileNotFoundError:
        log_folders = []
    if not log_folders:
        log_folders = [today]

    return render_template("logs.html", log_folders=log_folders, selected_day=selected_day, today=today)

def admin_required_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.logged_in:
            return jsonify({"error": "Authentication required"}), 401
        if not g.is_admin:
            logger.warning(f"{u(g.user_id)} attempted admin-only API access path={request.path}")
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/webaccess")
@login_required
@admin_required
def webaccess():
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name, login_enabled FROM companies ORDER BY name ASC")
        company_list = cursor.fetchall()
    return render_template("webaccess.html", companies=company_list)

@app.route("/api/toggle-web-access", methods=["POST"])
@admin_required_json
def toggle_web_access():
    data = request.get_json() or {}
    company_id = data.get("company_id")
    enabled = 1 if data.get("enabled") else 0
    if not company_id:
        return jsonify({"error": "Missing company_id"}), 400
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("UPDATE companies SET login_enabled = ? WHERE company_id = ?", (enabled, company_id))
        db.commit()
        if not cursor.rowcount:
            return jsonify({"error": "Company not found"}), 404
    logger.info(f"{u(g.user_id)} set web access enabled={bool(enabled)} for company id={company_id}")
    return jsonify({"enabled": bool(enabled)})

def _list_backups():
    backups = []
    try:
        for name in os.listdir(BACKUP_DIR):
            if not (name.startswith("otp_") and name.endswith(".db")):
                continue
            path = os.path.join(BACKUP_DIR, name)
            try:
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            backups.append({
                "name": name,
                "date": datetime.fromtimestamp(mtime).strftime("%b %d, %H:%M"),
                "size": f"{size / (1024 * 1024):.1f} MB",
                "mtime": mtime,
            })
    except FileNotFoundError:
        pass
    backups.sort(key=lambda b: b["mtime"], reverse=True)
    for b in backups:
        del b["mtime"]
    return backups

@app.route("/database")
@login_required
@admin_required
def database_page():
    try:
        size_bytes = os.path.getsize(DB_PATH)
    except OSError:
        size_bytes = 0
    size_mb = round(size_bytes / (1024 * 1024), 1)
    size_label = f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_mb} MB"
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = cursor.fetchone()[0]
        records = 0
        for table in ("otp_secrets", "users", "companies"):
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                records += cursor.fetchone()[0]
            except sqlite3.Error:
                pass

    backups = _list_backups()
    last_backup = backups[0]["date"] if backups else "Never"
    last_vacuum = load_state().get("last_vacuum") or "Unknown"
    if last_vacuum == datetime.now().strftime("%Y-%m-%d"):
        last_vacuum = "Today"

    stats = [
        {"label": "Database size", "value": size_label},
        {"label": "Tables", "value": tables},
        {"label": "Total records", "value": records},
        {"label": "Last backup", "value": last_backup},
        {"label": "Last vacuum", "value": last_vacuum},
    ]
    return render_template("database.html", stats=stats, backups=backups, size_bytes=size_bytes)

_SCHEMA_COLUMN_DEFAULTS = {
    "users.can_delete": "INTEGER DEFAULT 0",
    "users.can_edit": "INTEGER DEFAULT 0",
    "users.can_add_companies": "INTEGER DEFAULT 0",
    "users.can_delete_companies": "INTEGER DEFAULT 0",
    "users.can_add_secrets": "INTEGER DEFAULT 0",
    "users.can_add_users": "INTEGER DEFAULT 0",
    "users.blur_on_inactive": "INTEGER DEFAULT 1",
    "users.show_including_admin_on_top": "INTEGER DEFAULT 0",
    "users.hide_codes_by_default": "INTEGER DEFAULT 0",
    "users.hide_secret_field": "INTEGER DEFAULT 0",
    "users.show_search_and_link": "INTEGER DEFAULT 0",
    "users.show_pinned_in_sidebar": "INTEGER DEFAULT 0",
    "users.only_pinned_in_sidebar": "INTEGER DEFAULT 0",
    "users.bg_animation_style": "TEXT DEFAULT 'turbulence'",
    "users.bg_animation_intensity": "INTEGER DEFAULT 100",
    "users.blur_on_inactive_delay": "INTEGER DEFAULT 60",
    "companies.login_enabled": "INTEGER DEFAULT 0",
}

@app.route("/api/db/task", methods=["POST"])
@admin_required_json
def run_db_task():
    data = request.get_json() or {}
    task = data.get("task")
    logger.info(f"{u(g.user_id)} started database task '{task}'")

    try:
        if task == "vacuum":
            with sqlite3.connect(DB_PATH) as db:
                db.isolation_level = None
                db.execute("VACUUM")
                db.execute("PRAGMA optimize")
            state = load_state()
            state["last_vacuum"] = datetime.now().strftime("%Y-%m-%d")
            save_state(state)
            return jsonify({"message": "Vacuum & optimize completed"})

        if task == "schema":
            missing = get_missing_columns()
            if not missing:
                return jsonify({"message": "Schema is up to date"})
            with sqlite3.connect(DB_PATH) as db:
                cursor = db.cursor()
                for item in missing:
                    table, col = item.split(".", 1)
                    coldef = _SCHEMA_COLUMN_DEFAULTS.get(item, "INTEGER DEFAULT 0")
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coldef}")
                db.commit()
            return jsonify({"message": f"Schema updated — added {len(missing)} missing column(s)"})

        if task == "integrity":
            with sqlite3.connect(DB_PATH) as db:
                cursor = db.cursor()
                cursor.execute("PRAGMA integrity_check")
                integrity_ok = (cursor.fetchone() or ["error"])[0].lower() == "ok"
                cursor.execute("PRAGMA foreign_key_check")
                fk_issues = len(cursor.fetchall())
            orphans = check_orphans()
            result = f"{orphans} orphaned records · {fk_issues} broken foreign keys · schema {'OK' if integrity_ok else 'ISSUES FOUND'}"
            return jsonify({"message": "Integrity check completed", "result": result})

        if task == "repair":
            normalize_secrets()
            with sqlite3.connect(DB_PATH) as db:
                db.execute("REINDEX")
            return jsonify({"message": "Database repaired"})

        if task == "reset_sessions":
            with sqlite3.connect(DB_PATH) as db:
                cursor = db.cursor()
                cursor.execute("SELECT id FROM users")
                for (uid,) in cursor.fetchall():
                    cursor.execute("UPDATE users SET session_token = ? WHERE id = ?", (str(uuid.uuid4()), uid))
                db.commit()
            return jsonify({"message": "All sessions reset — every user will need to log in again"})

        if task == "backup":
            dest = backup_db()
            if not dest:
                return jsonify({"error": "No database file found"}), 500
            return jsonify({"message": "Backup created"})

        return jsonify({"error": "Unknown task"}), 400
    except Exception as e:
        logger.exception(f"database task '{task}' failed: {e}")
        return jsonify({"error": f"Task failed: {e}"}), 500

@app.route("/api/db/backups")
@admin_required_json
def db_backups():
    return jsonify(_list_backups())

@app.route("/api/db/load-backup", methods=["POST"])
@admin_required_json
def db_load_backup():
    data = request.get_json() or {}
    name = data.get("name") or ""
    valid_names = {b["name"] for b in _list_backups()}
    if name not in valid_names:
        return jsonify({"error": "Unknown backup"}), 400
    src = os.path.join(BACKUP_DIR, name)
    try:
        backup_db()
        shutil.copyfile(src, os.path.join(BASE_DIR, DB_PATH))
        for suffix in ("-wal", "-shm"):
            side = os.path.join(BASE_DIR, DB_PATH) + suffix
            if os.path.exists(side):
                os.remove(side)
        logger.warning(f"{u(g.user_id)} restored database backup {name}")
        return jsonify({"message": f"Loaded {name} — a safety backup of the previous database was created"})
    except Exception as e:
        logger.exception(f"restore of backup {name} failed: {e}")
        return jsonify({"error": f"Restore failed: {e}"}), 500

@app.route("/server")
@login_required
@admin_required
def server_page():
    # Show the persisted settings.json values (not env overrides) so saving
    # never accidentally persists a temporary override.
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            stored = json.load(f) or {}
    except Exception:
        stored = {}
    cli_command = f"cd {BASE_DIR} && {os.path.basename(sys.executable or 'python3')} start.py"
    return render_template(
        "server.html",
        server_port=stored.get("port", APP_SETTINGS.get("port", 7440)),
        server_secret=stored.get("secret_key", ""),
        company_brand=stored.get("company_name", APP_SETTINGS.get("company_name", "")),
        cli_command=cli_command,
        server_started_at=get_server_started_at(),
        github_url="https://github.com/Migrim/OTP-Manager-Refactored",
    )

@app.route("/api/server/check-update")
@admin_required_json
def server_check_update():
    url = "https://raw.githubusercontent.com/Migrim/OTP-Manager-Refactored/main/VERSION"
    current = get_app_version()
    try:
        with urllib.request.urlopen(url, timeout=8) as res:
            latest = res.read().decode("utf-8").strip()
    except Exception as e:
        logger.warning(f"update check failed: {e}")
        return jsonify({"error": "Could not reach the update server"}), 502

    def vtuple(v):
        parts = []
        for chunk in v.strip().lstrip("v").split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    available = vtuple(latest) > vtuple(current)
    logger.info(f"{u(g.user_id)} checked for updates: current={current} latest={latest} available={available}")
    return jsonify({"current": current, "latest": latest, "available": available})

@app.route("/api/server/config", methods=["POST"])
@admin_required_json
def server_config():
    data = request.get_json() or {}
    try:
        port = int(data.get("port"))
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid port"}), 400
    secret_key = str(data.get("secret_key") or "").strip()
    if not secret_key:
        return jsonify({"error": "Secret key cannot be empty"}), 400
    company_name = str(data.get("company_name") or "").strip()[:13]

    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f) or {}
    except Exception:
        settings = {}
    settings["port"] = port
    settings["secret_key"] = secret_key
    settings["company_name"] = company_name
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)

    APP_SETTINGS["company_name"] = company_name
    logger.info(f"{u(g.user_id)} updated server configuration (port={port})")
    changed_runtime = port != APP_SETTINGS.get("port") or secret_key != APP_SETTINGS.get("secret_key")
    msg = "Server configuration saved"
    if changed_runtime:
        msg += " — restart the server to apply port/secret changes"
    return jsonify({"message": msg})

def _restart_process():
    logger.warning("server restart requested from web UI")
    time.sleep(0.6)
    os.execv(sys.executable, [sys.executable] + sys.argv)

def _stop_process():
    logger.warning("server stop requested from web UI")
    time.sleep(0.6)
    os._exit(0)

@app.route("/api/server/restart", methods=["POST"])
@admin_required_json
def server_restart():
    logger.info(f"{u(g.user_id)} restarted the server")
    threading.Thread(target=_restart_process, daemon=True).start()
    return jsonify({"message": "Restarting"})

@app.route("/api/server/stop", methods=["POST"])
@admin_required_json
def server_stop():
    logger.info(f"{u(g.user_id)} stopped the server")
    threading.Thread(target=_stop_process, daemon=True).start()
    return jsonify({"message": "Stopping"})

@app.route("/api/server/update-now", methods=["POST"])
@admin_required_json
def server_update_now():
    logger.warning(f"{u(g.user_id)} triggered an update from the web UI")
    try:
        with open(UPDATE_STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "phase": "stopping",
                "ok": None,
                "message": "Stopping server for update...",
                "ts": time.time(),
            }, f)
    except Exception:
        pass
    # A detached process does the stop -> update -> start cycle so it survives
    # this process being killed as part of "stop". See start.py --run-update.
    subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, "start.py"), "--run-update"],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    return jsonify({"message": "Update started", "server_started_at": SERVER_START_TIME})

@app.route("/api/server/ping")
@admin_required_json
def server_ping():
    return jsonify({
        "ok": True,
        "version": get_app_version(),
        "started_at": SERVER_START_TIME,
        "last_update": read_update_status() or None,
    })

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
    ensure_dirs()
    init_db()
    start_thread = (os.environ.get("WERKZEUG_RUN_MAIN") == "true") or not app.debug
    if start_thread:
        t = threading.Thread(target=maintenance_loop, daemon=True)
        t.start()
    socketio.run(app, host=APP_SETTINGS["host"], port=APP_SETTINGS["port"], debug=True, use_reloader=True, allow_unsafe_werkzeug=True)
