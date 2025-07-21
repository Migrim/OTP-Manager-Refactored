from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os
from api import api_bp  # new import

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/api")  # register your API routes
DB_PATH = os.path.join("instance", "otp.db")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/add", methods=["GET", "POST"])
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
            cursor.execute("""
                INSERT INTO otp_secrets (name, email, secret, otp_type, refresh_time, company_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, email, secret, otp_type, refresh_time, company_id))
            db.commit()

        return redirect(url_for("home"))

    return render_template("add.html")

if __name__ == "__main__":
    app.run(port=7440, debug=True)