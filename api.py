from flask import Blueprint, request, jsonify, redirect, flash, url_for, g
from binascii import Error as BinasciiError
import sqlite3
import os
import pyotp
import time
from extensions import bcrypt
from logger import logger

api_bp = Blueprint("api", __name__)
DB_PATH = os.path.join("instance", "otp.db")

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

def sanitize_payload(d):
    if not isinstance(d, dict):
        return d
    redacted = {}
    for k, v in d.items():
        if k is None:
            continue
        kl = str(k).lower()
        if kl in {"secret", "password", "new_password"}:
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted

def get_company_name(cid):
    try:
        with sqlite3.connect(DB_PATH) as db:
            c = db.cursor()
            c.execute("SELECT name FROM companies WHERE company_id = ?", (cid,))
            r = c.fetchone()
            return r[0] if r else "Unknown Company"
    except:
        return "Unknown Company"

def get_username(uid):
    try:
        with sqlite3.connect(DB_PATH) as db:
            c = db.cursor()
            c.execute("SELECT username FROM users WHERE id = ?", (uid,))
            r = c.fetchone()
            return r[0] if r else None
    except:
        return None

@api_bp.route("/secrets", methods=["GET"])
def get_all_secrets():
    t0 = time.perf_counter()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                s.id, s.name, s.email, s.secret, s.otp_type, s.refresh_time, s.company_id,
                c.name AS company_name
            FROM otp_secrets s
            LEFT JOIN companies c ON s.company_id = c.company_id
        """)
        rows = cursor.fetchall()
    out = []
    now = int(time.time())
    for row in rows:
        code = ""
        remaining = 30 - (now % 30)
        try:
            code = pyotp.TOTP(row[3]).now()
        except Exception:
            code = ""
        out.append({
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "secret": row[3],
            "otp_type": row[4],
            "refresh_time": row[5],
            "company_id": row[6],
            "company_name": row[7],
            "current_code": code,
            "seconds_remaining": remaining
        })
    dt = round((time.perf_counter() - t0) * 1000)
    return jsonify(out)

@api_bp.route("/secrets/<int:secret_id>", methods=["GET"])
def get_single_secret(secret_id):
    t0 = time.perf_counter()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                otp_secrets.id,
                otp_secrets.name,
                otp_secrets.email,
                otp_secrets.secret,
                otp_secrets.otp_type,
                otp_secrets.refresh_time,
                otp_secrets.company_id,
                companies.name AS company_name
            FROM otp_secrets
            LEFT JOIN companies ON otp_secrets.company_id = companies.company_id
            WHERE otp_secrets.id = ?
        """, (secret_id,))
        row = cursor.fetchone()

    if not row:
        logger.warning(f"{u(getattr(g, 'user_id', None))} requested secret id={secret_id} result=not_found")
        return jsonify({"error": "Secret not found"}), 404

    secret = row[3]
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        time_left = totp.interval - (int(time.time()) % totp.interval)
    except (BinasciiError, ValueError) as e:
        logger.exception(f"{u(getattr(g, 'user_id', None))} requested secret id={secret_id} result=invalid_secret")
        return jsonify({
            "error": "Invalid secret format. Run a database integrity check.",
            "fix_hint": "Check for invalid secrets. Use the /admin tools to fix this entry."
        }), 400

    dt = round((time.perf_counter() - t0) * 1000)
    return jsonify({
        "id": row[0],
        "name": row[1],
        "email": row[2],
        "secret": row[3],
        "otp_type": row[4],
        "refresh_time": row[5],
        "company_id": row[6],
        "company_name": row[7],
        "current_code": code,
        "seconds_remaining": time_left
    })

@api_bp.route("/secrets", methods=["POST"])
def create_secret():
    t0 = time.perf_counter()
    data = request.json or {}
    payload = sanitize_payload(data)
    company_id = int(data.get("company_id", 1))
    company_name = get_company_name(company_id)
    logger.info(f"{u(getattr(g, 'user_id', None))} create_secret start payload={payload} company={company_name} [{company_id}]")
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO otp_secrets (name, email, secret, otp_type, refresh_time, company_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data.get("name"),
            data.get("email", "none"),
            data.get("secret"),
            data.get("otp_type", "totp"),
            int(data.get("refresh_time", 30)),
            company_id
        ))
        db.commit()
        new_id = cursor.lastrowid
    dt = round((time.perf_counter() - t0) * 1000)
    logger.info(f"{u(getattr(g, 'user_id', None))} create_secret done id={new_id} name={data.get('name')} company={company_name} duration_ms={dt}")
    return jsonify({"status": "created", "id": new_id}), 201

@api_bp.route("/secrets/<int:secret_id>", methods=["PUT"])
def update_secret(secret_id):
    t0 = time.perf_counter()
    data = request.json or {}
    payload = sanitize_payload(data)
    company_id = int(data.get("company_id", 1))
    company_name = get_company_name(company_id)
    logger.info(f"{u(getattr(g, 'user_id', None))} update_secret start id={secret_id} payload={payload} company={company_name} [{company_id}]")
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE otp_secrets SET
                name = ?,
                email = ?,
                secret = ?,
                otp_type = ?,
                refresh_time = ?,
                company_id = ?
            WHERE id = ?
        """, (
            data.get("name"),
            data.get("email", "none"),
            data.get("secret"),
            data.get("otp_type", "totp"),
            int(data.get("refresh_time", 30)),
            company_id,
            secret_id
        ))
        db.commit()
        if cursor.rowcount:
            dt = round((time.perf_counter() - t0) * 1000)
            logger.info(f"{u(getattr(g, 'user_id', None))} update_secret done id={secret_id} duration_ms={dt}")
            return jsonify({"status": "updated"})
        else:
            logger.warning(f"{u(getattr(g, 'user_id', None))} update_secret id={secret_id} result=not_found")
            return jsonify({"error": "Secret not found"}), 404

@api_bp.route("/create-user", methods=["POST"])
def create_user():
    t0 = time.perf_counter()
    data = request.form
    username = data.get("username")
    is_admin = int(data.get("is_admin") == "on")
    if not username or not data.get("password"):
        logger.warning(f"{u(getattr(g, 'user_id', None))} create_user result=missing_fields")
        return jsonify({"error": "Missing fields"}), 400
    hashed = bcrypt.generate_password_hash(data.get("password")).decode("utf-8")
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                       (username, hashed, is_admin))
        db.commit()
        new_id = cursor.lastrowid
    dt = round((time.perf_counter() - t0) * 1000)
    logger.info(f"{u(getattr(g, 'user_id', None))} created user {username} with id {new_id} admin={bool(is_admin)} duration_ms={dt}")
    return redirect("/users")

@api_bp.route("/reset-password", methods=["POST"])
def reset_password():
    t0 = time.perf_counter()
    target_id = request.form.get("user_id")
    if not target_id or not request.form.get("new_password"):
        logger.warning(f"{u(getattr(g, 'user_id', None))} reset_password result=missing_fields")
        return jsonify({"error": "Missing user_id or password"}), 400
    hashed = bcrypt.generate_password_hash(request.form.get("new_password")).decode("utf-8")
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, target_id))
        db.commit()
        if cursor.rowcount:
            target_name = get_username(target_id)
            dt = round((time.perf_counter() - t0) * 1000)
            logger.info(f"{u(getattr(g, 'user_id', None))} reset password for {user_ref(user_id=target_id, username=target_name)} duration_ms={dt}")
            return redirect("/users")
        else:
            logger.warning(f"{u(getattr(g, 'user_id', None))} reset_password id={target_id} result=not_found")
            return jsonify({"error": "User not found"}), 404

@api_bp.route("/delete-user", methods=["POST"])
def delete_user():
    t0 = time.perf_counter()
    target_id = request.form.get("user_id")
    if not target_id:
        logger.warning(f"{u(getattr(g, 'user_id', None))} delete_user result=missing_user_id")
        return jsonify({"error": "Missing user_id"}), 400
    target_name = get_username(target_id)
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (target_id,))
        db.commit()
        if cursor.rowcount:
            dt = round((time.perf_counter() - t0) * 1000)
            logger.info(f"{u(getattr(g, 'user_id', None))} deleted user {user_ref(user_id=target_id, username=target_name)} duration_ms={dt}")
            return redirect("/users")
        else:
            logger.warning(f"{u(getattr(g, 'user_id', None))} delete_user id={target_id} result=not_found")
            return jsonify({"error": "User not found"}), 404

@api_bp.route("/toggle-admin", methods=["POST"])
def toggle_admin():
    t0 = time.perf_counter()
    target_id = request.form.get("user_id")
    if not target_id:
        logger.warning(f"{u(getattr(g, 'user_id', None))} toggle_admin result=missing_user_id")
        return jsonify({"error": "Missing user_id"}), 400
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT is_admin, username FROM users WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        if not row:
            logger.warning(f"{u(getattr(g, 'user_id', None))} toggle_admin id={target_id} result=not_found")
            return jsonify({"error": "User not found"}), 404
        current_status = row[0]
        new_status = 0 if current_status else 1
        cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, target_id))
        db.commit()
    dt = round((time.perf_counter() - t0) * 1000)
    logger.info(f"{u(getattr(g, 'user_id', None))} toggled admin for {user_ref(user_id=target_id, username=row[1])} to={bool(new_status)} duration_ms={dt}")
    return redirect("/users")

@api_bp.route("/create-company", methods=["POST"])
def create_company():
    t0 = time.perf_counter()
    name = request.form.get("name")
    kundennummer = request.form.get("kundennummer")
    if not name:
        logger.warning(f"{u(getattr(g, 'user_id', None))} create_company result=missing_name")
        return jsonify({"error": "Missing name"}), 400
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        if kundennummer:
            cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (name, kundennummer))
        else:
            cursor.execute("INSERT INTO companies (name) VALUES (?)", (name,))
        db.commit()
        new_id = cursor.lastrowid
    dt = round((time.perf_counter() - t0) * 1000)
    logger.info(f"{u(getattr(g, 'user_id', None))} created company {name} with id {new_id} duration_ms={dt}")
    return redirect("/companies")

@api_bp.route("/delete-company", methods=["POST"])
def delete_company():
    t0 = time.perf_counter()
    company_id = request.form.get("company_id")
    if not company_id:
        logger.warning(f"{u(getattr(g, 'user_id', None))} delete_company result=missing_company_id")
        return jsonify({"error": "Missing company_id"}), 400
    cname = get_company_name(company_id)
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))
        db.commit()
        if cursor.rowcount:
            dt = round((time.perf_counter() - t0) * 1000)
            logger.info(f"{u(getattr(g, 'user_id', None))} deleted company {cname} [{company_id}] duration_ms={dt}")
            return redirect("/companies")
        else:
            logger.warning(f"{u(getattr(g, 'user_id', None))} delete_company id={company_id} result=not_found")
            return jsonify({"error": "Company not found"}), 404

@api_bp.route("/edit-company", methods=["POST"])
def edit_company():
    t0 = time.perf_counter()
    company_id = request.form.get("company_id")
    name = request.form.get("name")
    kundennummer = request.form.get("kundennummer")
    password = request.form.get("password")
    if not company_id or not name:
        logger.warning(f"{u(getattr(g, 'user_id', None))} edit_company result=missing_fields")
        return jsonify({"error": "Missing fields"}), 400
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        if kundennummer == "":
            kundennummer = None
        if password:
            cursor.execute("UPDATE companies SET name = ?, kundennummer = ?, password = ? WHERE company_id = ?",
                           (name, kundennummer, password, company_id))
        else:
            cursor.execute("UPDATE companies SET name = ?, kundennummer = ? WHERE company_id = ?",
                           (name, kundennummer, company_id))
        db.commit()
    dt = round((time.perf_counter() - t0) * 1000)
    logger.info(f"{u(getattr(g, 'user_id', None))} updated company {get_company_name(company_id)} [{company_id}] duration_ms={dt}")
    return redirect("/companies")

@api_bp.route("/delete-secret", methods=["POST"])
def delete_secret():
    t0 = time.perf_counter()
    secret_id = request.form.get("secret_id")
    if not secret_id:
        logger.warning(f"{u(getattr(g, 'user_id', None))} delete_secret result=missing_secret_id")
        flash("No secret ID provided.", "error")
        return redirect(url_for("home"))
    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute("SELECT name, email, company_id, secret FROM otp_secrets WHERE id = ?", (secret_id,))
            meta = cursor.fetchone()
            cursor.execute("DELETE FROM otp_secrets WHERE id = ?", (secret_id,))
            db.commit()
        if meta:
            cname = get_company_name(meta[2])
            dt = round((time.perf_counter() - t0) * 1000)
            logger.info(
                f"{u(getattr(g, 'user_id', None))} deleted secret id={secret_id} "
                f"name={meta[0]} email={meta[1]} company={cname} secret={meta[3]} duration_ms={dt}"
            )
        else:
            logger.warning(f"{u(getattr(g, 'user_id', None))} delete_secret id={secret_id} result=not_found")
        flash("Secret deleted successfully.", "success")
        return redirect(url_for("home"))
    except Exception:
        logger.exception(f"{u(getattr(g, 'user_id', None))} delete_secret id={secret_id} result=error")
        flash("An error occurred while deleting the secret.", "error")
        return redirect(url_for("home"))

@api_bp.route("/logs")
def live_logs():
    day = request.args.get("day")
    if not day:
        return jsonify(logs=[])
    log_file = os.path.join("logs", day, "app.log")
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()[-500:]
    except FileNotFoundError:
        lines = []
        logger.warning(f"{u(getattr(g, 'user_id', None))} live_logs day={day} result=file_not_found")
    return jsonify(logs=lines)