from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
import sqlite3
import os
import uuid
from datetime import datetime
from functools import wraps
from api import api_bp
from extensions import bcrypt
from logger import logger

app = Flask(__name__)
bcrypt.init_app(app)
app.secret_key = "your-very-secret-key"
app.register_blueprint(api_bp, url_prefix="/api")
DB_PATH = os.path.join("instance", "otp.db")

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
            logger.warning(f"User {g.user_id} attempted admin-only access.")
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

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
    }

@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Error: {request.path} not found.")
    return render_template("404.html"), 404

@app.before_request
def load_user():
    g.user_id = session.get("user_id")
    g.is_admin = session.get("is_admin", False)
    g.logged_in = g.user_id is not None
    g.user_settings = {}
    if g.logged_in:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (g.user_id,))
            row = cursor.fetchone()
            g.user_settings = row_to_settings(row)

@app.context_processor
def inject_user():
    return dict(is_logged_in=g.logged_in, is_admin=g.is_admin, user_settings=g.user_settings)

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.logged_in:
        logger.info(f"User ID {g.user_id} attempted to access login while already logged in.")
        flash("You are already logged in.", "info")
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        keep_logged_in = "keep_logged_in" in request.form

        try:
            with sqlite3.connect(DB_PATH) as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()

            if user:
                user_id = user[0]
                stored_password = user[2]
                is_admin = bool(user[5])

                if stored_password == password or stored_password.strip() == "":
                    hashed = bcrypt.generate_password_hash(stored_password or password).decode("utf-8")
                    with sqlite3.connect(DB_PATH) as db:
                        cursor = db.cursor()
                        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
                        db.commit()
                    stored_password = hashed
                    flash("Password has been migrated to a secure hash.", "info")
                    logger.info(f"User {username}'s password was migrated to a hash.")

                if bcrypt.check_password_hash(stored_password, password):
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

                    logger.info(f"User {username} (ID: {user_id}) logged in.")
                    if is_admin and password == "1234":
                        flash("You are using the default password. Please change it.", "warning")

                    return redirect(url_for("home"))
                else:
                    logger.warning(f"Login failed for {username}: Invalid password.")
                    flash("Invalid credentials!", "error")
                    return redirect(url_for("login"))
            else:
                logger.warning(f"Login failed: User {username} not found.")
                flash("User not found.", "error")
                return redirect(url_for("login"))

        except Exception as e:
            logger.exception(f"Login error: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id", "Unknown")
    logger.info(f"User {user_id} logged out.")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    logger.info(f"User {g.user_id} accessed home page.")
    return render_template("home.html")

@app.route("/users")
@login_required
def users():
    if not g.is_admin:
        logger.warning(f"User {g.user_id} attempted to access /users without admin rights.")
        flash("Access denied.", "error")
        return redirect(url_for("home"))

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username, is_admin FROM users ORDER BY username ASC")
        user_list = cursor.fetchall()

    logger.info("Admin accessed user list.")
    return render_template("users.html", users=user_list)

@app.route("/companies")
@login_required
def companies():
    if not g.is_admin:
        logger.warning(f"User {g.user_id} attempted to access /companies without admin rights.")
        flash("Access denied.", "error")
        return redirect(url_for("home"))

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name, kundennummer FROM companies ORDER BY name ASC")
        company_list = cursor.fetchall()

    logger.info("Admin accessed company list.")
    return render_template("companies.html", companies=company_list)

@app.route("/companies/json")
@login_required
def companies_json():
    logger.debug(f"User {g.user_id} requested companies JSON.")
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT company_id, name FROM companies ORDER BY name ASC")
        company_list = cursor.fetchall()
    return jsonify([{"id": row[0], "name": row[1]} for row in company_list])

@app.route("/settings")
@login_required
def settings():
    logger.info(f"User {g.user_id} accessed settings.")
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
                    alert_color,
                    text_color,
                    g.user_id,
                ),
            )
            db.commit()
        logger.info(f"Updated settings for user {g.user_id}: {payload}")
        flash("Settings saved.", "success")
    except Exception as e:
        logger.exception(f"Error updating settings for user {g.user_id}: {e}")
        flash("Could not save settings.", "error")
    return redirect(url_for("settings"))

@app.route("/add", methods=["GET", "POST"])
@login_required
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

        logger.info(f"User {g.user_id} added new OTP entry: {name}")
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

    logger.info(f"User {user_id} {'pinned' if new_state else 'unpinned'} secret ID {secret_id}")
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
            logger.debug(f"User {user_id} fetched pinned secrets.")
            return jsonify(row[0].split(","))
        return jsonify([])

@app.route("/search.html")
@login_required
def search_page():
    q = request.args.get("q", "").lower()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT s.name, s.email, c.name
            FROM otp_secrets s
            LEFT JOIN companies c ON s.company_id = c.company_id
            WHERE LOWER(s.name) LIKE ? OR LOWER(s.email) LIKE ? OR LOWER(c.name) LIKE ?
            """,
            (f"%{q}%", f"%{q}%", f"%{q}%"),
        )
        results = cursor.fetchall()

    logger.info(f"User {g.user_id} searched for '{q}' — {len(results)} results.")
    return render_template("search.html", query=q, results=results)

@app.route("/logs")
@login_required
@admin_required
def view_logs():
    if not g.is_admin:
        flash("Access denied.", "error")
        logger.warning(f"User {g.user_id} tried to access /logs without admin rights.")
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7440, debug=True)