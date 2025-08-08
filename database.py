import os
import sqlite3
import shutil
import re
import time
from datetime import datetime

def init_db():
    try:
        instance_folder = "instance"
        db_filename = "otp.db"
        db_path = os.path.join(instance_folder, db_filename)
        is_new_database = not os.path.exists(db_path)

        if not os.path.exists(instance_folder):
            os.makedirs(instance_folder)

        backup_folder = "backup"
        current_date = datetime.now().strftime("%Y-%m-%d")
        backup_filename = f"otp_{current_date}.db"
        backup_path = os.path.join(backup_folder, backup_filename)

        if not os.path.exists(backup_path):
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
            if os.path.exists(db_path):
                shutil.copy(db_path, backup_path)

        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS companies (
                    company_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    kundennummer INTEGER UNIQUE,
                    password TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_secrets (
                    id INTEGER PRIMARY KEY UNIQUE,
                    name TEXT NOT NULL DEFAULT 'none' UNIQUE,
                    email TEXT DEFAULT 'none',
                    secret TEXT NOT NULL,
                    otp_type TEXT NOT NULL DEFAULT 'totp',
                    refresh_time INTEGER NOT NULL,
                    company_id INTEGER,
                    FOREIGN KEY (company_id) REFERENCES companies (company_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY,
                    logins_today INTEGER NOT NULL,
                    times_refreshed INTEGER NOT NULL,
                    date TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    last_login_time INTEGER,
                    session_token TEXT,
                    is_admin INTEGER DEFAULT 0,
                    pinned TEXT DEFAULT '',
                    show_timer INTEGER DEFAULT 0,
                    show_otp_type INTEGER DEFAULT 1,
                    show_content_titles INTEGER DEFAULT 1,
                    alert_color TEXT DEFAULT '#333333',
                    text_color TEXT DEFAULT '#FFFFFF',
                    show_emails INTEGER DEFAULT 0,
                    show_company INTEGER DEFAULT 0,
                )
            """)
            db.commit()

            if is_new_database:
                cursor.execute("INSERT INTO companies (name) VALUES ('Public'), ('Private')")
                db.commit()

            cursor.execute("SELECT id FROM users WHERE id = 1")
            if cursor.fetchone() is None:
                cursor.execute("INSERT INTO users (id, username, password, is_admin) VALUES (1, 'admin', '1234', 1)")
                db.commit()

            cursor.execute("PRAGMA foreign_key_check")
            consistency_result = cursor.fetchall()

            cursor.execute("SELECT id, secret FROM otp_secrets")
            secrets = cursor.fetchall()
            for id, secret in secrets:
                if not re.match('^[A-Z0-9]+$', secret):
                    cleaned_secret = re.sub('[^A-Z0-9]', '', secret.upper())
                    cursor.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned_secret, id))

            forbidden_words = [
                'INVALID', 'FORBIDDEN', 'ERROR', 'SELECT', 'DROP', 'INSERT', 'DELETE',
                'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'TRIGGER', 'GRANT', 'REVOKE', 'COMMIT',
                'ROLLBACK', 'SAVEPOINT', 'FLUSH', 'SHUTDOWN', 'UNION', 'INTERSECT', 'EXCEPT',
                'SCRIPT', 'SCRIPTING', 'NULL', 'TRUE', 'FALSE', 'LIMIT', 'TABLE',
                'VIEW', 'KEY', 'INDEX', 'DISTINCT', 'JOIN', 'WHERE', 'ORDER BY', 'GROUP BY',
                'HAVING', 'DECLARE', 'CURSOR', 'FETCH', 'LOCK'
            ]
            cursor.execute("SELECT id, name FROM otp_secrets")
            names = cursor.fetchall()
            for id, name in names:
                if name.strip() == "" or any(word in name.upper() for word in forbidden_words):
                    pass  

            db.commit()

    except sqlite3.Error:
        pass

if __name__ == "__main__":
    while True:
        init_db()
        time.sleep(3600)