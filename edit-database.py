import os
import sys
import sqlite3
import shutil
import argparse
from datetime import datetime
import pyotp
from binascii import Error as BinasciiError

INSTANCE_PATH = os.path.join("instance", "otp.db")
BACKUP_PATH = os.path.join("backup", f"otp_{datetime.now().strftime('%Y-%m-%d')}.db")


def get_connection():
    print(f"→ Connecting to database at '{INSTANCE_PATH}'...")
    if not os.path.exists(INSTANCE_PATH):
        print("✗ Error: Database not found at instance/otp.db")
        sys.exit(1)
    return sqlite3.connect(INSTANCE_PATH)


def check_integrity():
    print("\n[🧠 Deep Integrity Check Starting...]\n")
    conn = get_connection()
    cur = conn.cursor()

    # PRAGMA integrity check
    print("→ Running PRAGMA integrity_check...")
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchone()[0]
    if integrity == "ok":
        print("✓ SQLite structure is OK")
    else:
        print(f"✗ Integrity check failed: {integrity}")

    # Foreign key check
    print("→ Running PRAGMA foreign_key_check...")
    cur.execute("PRAGMA foreign_key_check;")
    fk_issues = cur.fetchall()
    if fk_issues:
        print(f"✗ Found {len(fk_issues)} foreign key issues:")
        for issue in fk_issues:
            print("   -", issue)
    else:
        print("✓ Foreign keys are consistent")

    # Check all secrets
    print("\n→ Validating all OTP secrets...")
    cur.execute("SELECT id, secret, name FROM otp_secrets")
    secrets = cur.fetchall()
    bad_secrets = 0
    for id_, secret, name in secrets:
        cleaned = ''.join(c for c in secret.upper() if c.isalnum())
        try:
            pyotp.TOTP(cleaned).now()
        except Exception as e:
            print(f"✗ Secret ID {id_} ({name}) is invalid → {e}")
            bad_secrets += 1
    if bad_secrets == 0:
        print("✓ All OTP secrets are valid")
    else:
        print(f"✗ {bad_secrets} invalid OTP secrets found")

    # Check users
    print("\n→ Validating user records...")
    cur.execute("SELECT id, username FROM users")
    users = cur.fetchall()
    usernames = set()
    user_issues = 0
    for user_id, username in users:
        if not username:
            print(f"✗ User ID {user_id} has empty username!")
            user_issues += 1
        elif username in usernames:
            print(f"✗ Duplicate username found: {username}")
            user_issues += 1
        else:
            usernames.add(username)
    if user_issues == 0:
        print("✓ All user records are valid")
    else:
        print(f"✗ {user_issues} user issues found")

    conn.close()
    print("\n🧠 Deep Integrity Check Complete.\n")


def repair_database():
    print("\n[Repairing secrets...]")
    conn = get_connection()
    cur = conn.cursor()
    repaired = 0

    print("→ Selecting all secrets from otp_secrets...")
    cur.execute("SELECT id, secret, name FROM otp_secrets")
    rows = cur.fetchall()
    print(f"→ Found {len(rows)} secrets.")

    for id_, secret, name in rows:
        cleaned = ''.join(c for c in secret.upper() if c.isalnum())

        try:
            pyotp.TOTP(cleaned).now()
        except (ValueError, TypeError, BinasciiError):
            print(f"✗ Secret ID {id_} is invalid → replacing with placeholder.")
            placeholder = pyotp.random_base32()
            new_name = name + " (placeholder)" if "(placeholder)" not in name else name
            cur.execute("UPDATE otp_secrets SET secret = ?, name = ? WHERE id = ?", (placeholder, new_name, id_))
            repaired += 1
            continue

        if cleaned != secret:
            print(f"→ Fixing formatting of secret ID {id_}")
            cur.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned, id_))
            repaired += 1

    conn.commit()
    conn.close()
    print(f"✓ Repaired {repaired} OTP secrets")
    print("→ Done.\n")


def upgrade_database():
    print("\n[Upgrading database schema...]")
    conn = get_connection()
    cur = conn.cursor()

    print("→ Backing up database...")
    if not os.path.exists("backup"):
        os.makedirs("backup")
    if not os.path.exists(BACKUP_PATH):
        shutil.copy(INSTANCE_PATH, BACKUP_PATH)
        print(f"✓ Backup saved to {BACKUP_PATH}")
    else:
        print("✓ Backup already exists for today.")

    print("→ Checking current 'users' schema...")
    cur.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cur.fetchall()]

    required_columns = [
        "pinned",
        "can_delete",
        "can_edit",
        "can_add_companies",
        "can_delete_companies",
        "can_add_secrets",
        "can_add_users",
        "blur_on_inactive",
        "show_including_admin_on_top"
    ]

    if any(col not in columns for col in required_columns):
        print("→ Outdated schema detected, performing full users table migration...")
        print("→ Renaming old 'users' table to 'users_old'...")
        cur.execute("ALTER TABLE users RENAME TO users_old")

        print("→ Reading old 'users' columns...")
        cur.execute("PRAGMA table_info(users_old)")
        old_columns = [col[1] for col in cur.fetchall()]

        print("→ Creating new 'users' table with latest schema...")
        cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                last_login_time INTEGER,
                session_token TEXT,
                is_admin INTEGER DEFAULT 0,
                can_delete INTEGER DEFAULT 0,
                can_edit INTEGER DEFAULT 0,
                can_add_companies INTEGER DEFAULT 0,
                can_delete_companies INTEGER DEFAULT 0,
                can_add_secrets INTEGER DEFAULT 0,
                can_add_users INTEGER DEFAULT 0,
                pinned TEXT DEFAULT '',
                show_timer INTEGER DEFAULT 0,
                show_otp_type INTEGER DEFAULT 1,
                show_content_titles INTEGER DEFAULT 1,
                alert_color TEXT DEFAULT '#333333',
                text_color TEXT DEFAULT '#FFFFFF',
                show_emails INTEGER DEFAULT 0,
                show_company INTEGER DEFAULT 0,
                blur_on_inactive INTEGER DEFAULT 1,
                show_including_admin_on_top INTEGER DEFAULT 0
            )
        """)

        print("→ Migrating user data into new schema...")
        cur.execute("SELECT * FROM users_old")
        old_rows = cur.fetchall()

        insert_sql = """
            INSERT INTO users (
                id, username, password, last_login_time, session_token,
                is_admin, can_delete, can_edit, can_add_companies,
                can_delete_companies, can_add_secrets, can_add_users,
                pinned, show_timer, show_otp_type, show_content_titles,
                alert_color, text_color, show_emails, show_company,
                blur_on_inactive, show_including_admin_on_top
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        migrated = 0
        for row in old_rows:
            data = dict(zip(old_columns, row))
            is_admin_value = int(data.get("is_admin", 0) or 0)
            cur.execute(insert_sql, (
                data.get("id"),
                data.get("username"),
                data.get("password"),
                data.get("last_login_time"),
                data.get("session_token"),
                is_admin_value,
                int(data.get("can_delete", is_admin_value) or is_admin_value),
                int(data.get("can_edit", is_admin_value) or is_admin_value),
                int(data.get("can_add_companies", is_admin_value) or is_admin_value),
                int(data.get("can_delete_companies", is_admin_value) or is_admin_value),
                int(data.get("can_add_secrets", is_admin_value) or is_admin_value),
                int(data.get("can_add_users", is_admin_value) or is_admin_value),
                data.get("pinned", "") or "",
                int(data.get("show_timer", 0) or 0),
                int(data.get("show_otp_type", 1) or 1),
                int(data.get("show_content_titles", 1) or 1),
                data.get("alert_color", "#333333") or "#333333",
                data.get("text_color", "#FFFFFF") or "#FFFFFF",
                int(data.get("show_emails", 0) or 0),
                int(data.get("show_company", 0) or 0),3
                int(data.get("blur_on_inactive", 1) or 1),
                int(data.get("show_including_admin_on_top", 0) or 0)
            ))
            migrated += 1

        print(f"✓ Migrated {migrated} users.")
        print("→ Dropping old 'users_old' table...")
        cur.execute("DROP TABLE users_old")
        conn.commit()
        conn.close()
        print("✓ Upgrade complete. Schema now includes all new permission columns and options.")
        print("→ Done.\n")
        return

    print("→ Core schema exists. Checking for any missing current columns...")
    changed = False

    additions = [
        ("can_delete", "ALTER TABLE users ADD COLUMN can_delete INTEGER DEFAULT 0"),
        ("can_edit", "ALTER TABLE users ADD COLUMN can_edit INTEGER DEFAULT 0"),
        ("can_add_companies", "ALTER TABLE users ADD COLUMN can_add_companies INTEGER DEFAULT 0"),
        ("can_delete_companies", "ALTER TABLE users ADD COLUMN can_delete_companies INTEGER DEFAULT 0"),
        ("can_add_secrets", "ALTER TABLE users ADD COLUMN can_add_secrets INTEGER DEFAULT 0"),
        ("can_add_users", "ALTER TABLE users ADD COLUMN can_add_users INTEGER DEFAULT 0"),
        ("blur_on_inactive", "ALTER TABLE users ADD COLUMN blur_on_inactive INTEGER DEFAULT 0"),
        ("show_including_admin_on_top", "ALTER TABLE users ADD COLUMN show_including_admin_on_top INTEGER DEFAULT 0")
    ]

    for column_name, sql in additions:
        if column_name not in columns:
            print(f"→ Adding '{column_name}' column to users...")
            cur.execute(sql)
            changed = True
        else:
            print(f"✓ '{column_name}' column already exists.")

    if not changed:
        print("✓ Database schema is already up to date.")

    print("→ Ensuring admin users have all permissions...")
    cur.execute("""
        UPDATE users
        SET can_delete = 1,
            can_edit = 1,
            can_add_companies = 1,
            can_delete_companies = 1,
            can_add_secrets = 1,
            can_add_users = 1
        WHERE is_admin = 1
    """)
    conn.commit()
    conn.close()
    print("→ Done.\n")


def menu():
    while True:
        print("\n--------------------------")
        print("One-Auth OTP Database CLI")
        print("--------------------------")
        print("1. ✅ Check Integrity")
        print("2. 🔧 Repair Database")
        print("3. 🚀 Upgrade to Newest Version")
        print("4. ❌ Exit")

        choice = input("\nEnter choice [1-4]: ").strip()

        if choice == "1":
            check_integrity()
        elif choice == "2":
            repair_database()
        elif choice == "3":
            upgrade_database()
        elif choice == "4":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One-Auth OTP DB CLI")
    parser.add_argument("command", nargs="?", help="Command: check, repair, upgrade")
    args = parser.parse_args()

    if not args.command:
        menu()
    elif args.command == "check":
        check_integrity()
    elif args.command == "repair":
        repair_database()
    elif args.command == "upgrade":
        upgrade_database()
    else:
        print("✗ Invalid command. Use: check, repair, upgrade")