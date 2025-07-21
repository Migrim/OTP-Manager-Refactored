from flask import Blueprint, request, jsonify
import sqlite3
import os
import pyotp
import time

api_bp = Blueprint("api", __name__)
DB_PATH = os.path.join("instance", "otp.db")


@api_bp.route("/secrets", methods=["GET"])
def get_all_secrets():
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
        """)
        rows = cursor.fetchall()

    secrets = [
        {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "secret": row[3],
            "otp_type": row[4],
            "refresh_time": row[5],
            "company_id": row[6],
            "company_name": row[7]
        }
        for row in rows
    ]
    return jsonify(secrets)


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

    if row:
        secret = row[3]
        totp = pyotp.TOTP(secret)
        code = totp.now()
        time_left = totp.interval - (int(time.time()) % totp.interval)

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

    return jsonify({"error": "Secret not found"}), 404

@api_bp.route("/secrets", methods=["POST"])
def create_secret():
    data = request.json
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
        return jsonify({"status": "created"}), 201


@api_bp.route("/secrets/<int:secret_id>", methods=["PUT"])
def update_secret(secret_id):
    data = request.json
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
            return jsonify({"status": "updated"})
        else:
            return jsonify({"error": "Secret not found"}), 404


@api_bp.route("/secrets/<int:secret_id>", methods=["DELETE"])
def delete_secret(secret_id):
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM otp_secrets WHERE id = ?", (secret_id,))
        db.commit()
        if cursor.rowcount:
            return jsonify({"status": "deleted"})
        else:
            return jsonify({"error": "Secret not found"}), 404