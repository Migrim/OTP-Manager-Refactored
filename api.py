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


@api_bp.route("/secrets", methods=["GET"])
def get_all_secrets():
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
        code = None
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
    return jsonify(out)

@api_bp.route("/secrets/<int:secret_id>", methods=["GET"])
def get_single_secret(secret_id):
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
        logger.warning(f"Secret ID {secret_id} not found.")
        return jsonify({"error": "Secret not found"}), 404

    secret = row[3]
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        time_left = totp.interval - (int(time.time()) % totp.interval)
    except (BinasciiError, ValueError) as e:
        logger.exception(f"Invalid secret for ID {secret_id}: {e}")
        return jsonify({
            "error": "Invalid secret format. Run a database integrity check.",
            "fix_hint": "Check for invalid secrets. Use the /admin tools to fix this entry."
        }), 400

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
    data = request.json
    logger.info(f"Creating new secret for {data.get('name')}...")
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
            int(data.get("company_id", 1))
        ))
        db.commit()
    logger.info(f"Secret created for {data.get('name')}.")
    return jsonify({"status": "created"}), 201


@api_bp.route("/secrets/<int:secret_id>", methods=["PUT"])
def update_secret(secret_id):
    data = request.json
    logger.info(f"Updating secret ID {secret_id}...")
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
            int(data.get("company_id", 1)),
            secret_id
        ))
        db.commit()
        if cursor.rowcount:
            logger.info(f"Secret ID {secret_id} updated successfully.")
            return jsonify({"status": "updated"})
        else:
            logger.warning(f"Secret ID {secret_id} not found.")
            return jsonify({"error": "Secret not found"}), 404


@api_bp.route("/create-user", methods=["POST"])
def create_user():
    data = request.form
    username = data.get("username")
    password = data.get("password")
    is_admin = int(data.get("is_admin") == "on")

    if not username or not password:
        logger.warning("User creation failed: missing fields.")
        return jsonify({"error": "Missing fields"}), 400

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                       (username, hashed, is_admin))
        db.commit()

    logger.info(f"User '{username}' created. Admin: {bool(is_admin)}")
    return redirect("/users")


@api_bp.route("/reset-password", methods=["POST"])
def reset_password():
    user_id = request.form.get("user_id")
    new_password = request.form.get("new_password")

    if not user_id or not new_password:
        logger.warning("Password reset failed: missing user_id or password.")
        return jsonify({"error": "Missing user_id or password"}), 400

    hashed = bcrypt.generate_password_hash(new_password).decode("utf-8")

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
        db.commit()
        if cursor.rowcount:
            logger.info(f"Password reset for user ID {user_id}")
            return redirect("/users")
        else:
            logger.warning(f"Password reset failed: user ID {user_id} not found.")
            return jsonify({"error": "User not found"}), 404


@api_bp.route("/delete-user", methods=["POST"])
def delete_user():
    user_id = request.form.get("user_id")
    if not user_id:
        logger.warning("Delete user failed: no user_id provided.")
        return jsonify({"error": "Missing user_id"}), 400

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        if cursor.rowcount:
            logger.info(f"User ID {user_id} deleted.")
            return redirect("/users")
        else:
            logger.warning(f"Delete failed: user ID {user_id} not found.")
            return jsonify({"error": "User not found"}), 404


@api_bp.route("/toggle-admin", methods=["POST"])
def toggle_admin():
    user_id = request.form.get("user_id")
    if not user_id:
        logger.warning("Toggle admin failed: no user_id provided.")
        return jsonify({"error": "Missing user_id"}), 400

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()

        if not row:
            logger.warning(f"User ID {user_id} not found for admin toggle.")
            return jsonify({"error": "User not found"}), 404

        current_status = row[0]
        new_status = 0 if current_status else 1
        cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        db.commit()

    logger.info(f"User ID {user_id} admin status toggled to {new_status}.")
    return redirect("/users")


@api_bp.route("/create-company", methods=["POST"])
def create_company():
    name = request.form.get("name")
    kundennummer = request.form.get("kundennummer")

    if not name:
        logger.warning("Company creation failed: missing name.")
        return jsonify({"error": "Missing name"}), 400

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        if kundennummer:
            cursor.execute("INSERT INTO companies (name, kundennummer) VALUES (?, ?)", (name, kundennummer))
        else:
            cursor.execute("INSERT INTO companies (name) VALUES (?)", (name,))
        db.commit()

    logger.info(f"Company '{name}' created.")
    return redirect("/companies")


@api_bp.route("/delete-company", methods=["POST"])
def delete_company():
    company_id = request.form.get("company_id")
    if not company_id:
        logger.warning("Delete company failed: no company_id provided.")
        return jsonify({"error": "Missing company_id"}), 400

    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))
        db.commit()
        if cursor.rowcount:
            logger.info(f"Company ID {company_id} deleted.")
            return redirect("/companies")
        else:
            logger.warning(f"Delete failed: company ID {company_id} not found.")
            return jsonify({"error": "Company not found"}), 404


@api_bp.route("/edit-company", methods=["POST"])
def edit_company():
    company_id = request.form.get("company_id")
    name = request.form.get("name")
    kundennummer = request.form.get("kundennummer")
    password = request.form.get("password")

    if not company_id or not name:
        logger.warning("Edit company failed: missing fields.")
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

    logger.info(f"Company ID {company_id} updated.")
    return redirect("/companies")


@api_bp.route("/delete-secret", methods=["POST"])
def delete_secret():
    secret_id = request.form.get("secret_id")
    if not secret_id:
        logger.warning("Delete secret failed: no secret_id provided.")
        flash("No secret ID provided.", "error")
        return redirect(url_for("home"))

    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM otp_secrets WHERE id = ?", (secret_id,))
            db.commit()

        logger.info(f"Secret ID {secret_id} deleted successfully.")
        flash("Secret deleted successfully.", "success")
        return redirect(url_for("home"))

    except Exception as e:
        logger.exception(f"Error while deleting secret ID {secret_id}: {e}")
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
    return jsonify(logs=lines)