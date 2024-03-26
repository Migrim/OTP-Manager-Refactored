import os
from flask import Blueprint, Flask
import sqlite3

db_blueprint = Blueprint('db_blueprint', __name__)

DATABASE_NAME = "otp.db"

@db_blueprint.cli.command('init_db')
def init_db():
    """Initialize the database."""
    if not os.path.exists(DATABASE_NAME):
        print("Database does not exist. Creating now.")
        create_database()
    else:
        print("Database already exists.")

def create_database():
    """Create the database tables."""
    with sqlite3.connect(DATABASE_NAME) as db:
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS otp_secrets (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT DEFAULT 'none',
                secret TEXT NOT NULL,
                otp_type TEXT NOT NULL,
                refresh_time INTEGER NOT NULL,
                company_id INTEGER,
                FOREIGN KEY (company_id) REFERENCES companies (id)
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                last_login_time TEXT,
                session_token TEXT,
                is_admin INTEGER DEFAULT 0,
                enable_pagination INTEGER DEFAULT 0,
                show_timer INTEGER DEFAULT 0,
                show_otp_type INTEGER DEFAULT 1,
                show_content_titles INTEGER DEFAULT 1,
                alert_color TEXT DEFAULT 'alert-primary',
                text_color TEXT DEFAULT '#FFFFFF',
                show_emails INTEGER DEFAULT 0,
                show_company INTEGER DEFAULT 0
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kundennummer TEXT
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                logins_today INTEGER NOT NULL,
                times_refreshed INTEGER NOT NULL,
                date TEXT NOT NULL
            );
        """)

        db.commit()
        print("Database and tables created successfully.")

@db_blueprint.route('/check_db')
def check_db():
    """Check if the database exists and create it if it doesn't."""
    if not os.path.exists(DATABASE_NAME):
        print("Database not found. Creating now.")
        create_database()
        return "Database created."
    else:
        print("Database exists.")
        return "Database already exists."

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.register_blueprint(db_blueprint)

if __name__ == '__main__':
    app.run(debug=True)
