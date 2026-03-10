import os
import sys
import sqlite3
import shutil
from datetime import datetime
import pyotp
from binascii import Error as BinasciiError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_PATH = os.path.join(BASE_DIR, "instance", "otp.db")
BACKUP_PATH = os.path.join(BASE_DIR, "backup", f"otp_{datetime.now().strftime('%Y-%m-%d')}.db")

_ANSI = sys.stdout.isatty()
def _c(s, code): return f"\x1b[{code}m{s}\x1b[0m" if _ANSI else s
def bold(s):   return _c(s, "1")
def dim(s):    return _c(s, "2")
def red(s):    return _c(s, "31")
def green(s):  return _c(s, "32")
def yellow(s): return _c(s, "33")
def gray(s):   return _c(s, "90")


def get_connection():
    print(dim(f"  Connecting to {INSTANCE_PATH}"))
    if not os.path.exists(INSTANCE_PATH):
        raise FileNotFoundError(f"Database not found at {INSTANCE_PATH}")
    return sqlite3.connect(INSTANCE_PATH)


def _table_exists(cur, name):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def check_integrity():
    print(bold("\n  Integrity Check\n"))
    conn = get_connection()
    cur = conn.cursor()
    issues = 0

    # SQLite structural check
    print(dim("  Running PRAGMA integrity_check..."))
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchone()[0]
    if integrity == "ok":
        print(f"  {green('✓')} SQLite structure OK")
    else:
        print(f"  {red('✗')} Integrity check failed: {gray(integrity)}")
        issues += 1

    # Built-in FK check
    print(dim("  Running PRAGMA foreign_key_check..."))
    cur.execute("PRAGMA foreign_key_check;")
    fk_issues = cur.fetchall()
    if fk_issues:
        print(f"  {red('✗')} Found {len(fk_issues)} foreign key issue(s):")
        for issue in fk_issues:
            print(f"     {gray(str(issue))}")
        issues += len(fk_issues)
    else:
        print(f"  {green('✓')} PRAGMA foreign keys consistent")

    print("")

    # OTP secrets
    if _table_exists(cur, "otp_secrets"):
        print(dim("  Validating OTP secrets..."))
        cur.execute("SELECT id, secret, name, otp_type FROM otp_secrets")
        secrets = cur.fetchall()
        bad_secrets = 0
        bad_types = 0
        for id_, secret, name, otp_type in secrets:
            if not secret or not secret.strip():
                print(f"  {red('✗')} Secret ID {id_} ({name}): empty secret")
                bad_secrets += 1
                continue
            cleaned = ''.join(c for c in secret.upper() if c.isalnum())
            try:
                pyotp.TOTP(cleaned).now()
            except Exception as e:
                print(f"  {red('✗')} Secret ID {id_} ({name}): {gray(str(e))}")
                bad_secrets += 1
            if otp_type not in ("totp", "hotp"):
                print(f"  {red('✗')} Secret ID {id_} ({name}): invalid otp_type {gray(repr(otp_type))}")
                bad_types += 1
        if bad_secrets == 0 and bad_types == 0:
            print(f"  {green('✓')} All {len(secrets)} OTP secret(s) valid")
        else:
            if bad_secrets:
                print(f"  {red('✗')} {bad_secrets} invalid secret value(s)")
            if bad_types:
                print(f"  {red('✗')} {bad_types} invalid otp_type value(s)")
        issues += bad_secrets + bad_types

        # Orphaned secrets (company_id points to missing company)
        if _table_exists(cur, "companies"):
            cur.execute("""
                SELECT s.id, s.name FROM otp_secrets s
                WHERE s.company_id IS NOT NULL
                  AND s.company_id NOT IN (SELECT company_id FROM companies)
            """)
            orphans = cur.fetchall()
            if orphans:
                print(f"  {red('✗')} {len(orphans)} orphaned secret(s) reference missing companies:")
                for oid, oname in orphans:
                    print(f"     {gray(f'ID {oid} ({oname})')}")
                issues += len(orphans)
            else:
                print(f"  {green('✓')} No orphaned company references")
    else:
        print(f"  {yellow('!')} Table 'otp_secrets' not found")

    print("")

    # Companies
    if _table_exists(cur, "companies"):
        print(dim("  Validating companies..."))
        cur.execute("SELECT company_id, name FROM companies")
        companies = cur.fetchall()
        company_issues = 0
        names_seen = set()
        for cid, cname in companies:
            if not cname or not cname.strip():
                print(f"  {red('✗')} Company ID {cid}: empty name")
                company_issues += 1
            elif cname in names_seen:
                print(f"  {red('✗')} Duplicate company name: {gray(cname)}")
                company_issues += 1
            else:
                names_seen.add(cname)
        if company_issues == 0:
            print(f"  {green('✓')} All {len(companies)} company record(s) valid")
        else:
            issues += company_issues
    else:
        print(f"  {yellow('!')} Table 'companies' not found")

    print("")

    # Users
    if _table_exists(cur, "users"):
        print(dim("  Validating users..."))
        cur.execute("SELECT id, username FROM users")
        users = cur.fetchall()
        usernames = set()
        user_issues = 0
        for user_id, username in users:
            if not username or not username.strip():
                print(f"  {red('✗')} User ID {user_id}: empty username")
                user_issues += 1
            elif username in usernames:
                print(f"  {red('✗')} Duplicate username: {gray(username)}")
                user_issues += 1
            else:
                usernames.add(username)
        if user_issues == 0:
            print(f"  {green('✓')} All {len(users)} user record(s) valid")
        else:
            issues += user_issues
    else:
        print(f"  {yellow('!')} Table 'users' not found")

    print("")
    if issues == 0:
        print(f"  {green('✓')} All checks passed — no issues found")
    else:
        print(f"  {red('✗')} {issues} issue(s) found — consider running Repair or Upgrade")

    conn.close()
    print(f"\n  {bold('Done.')}\n")


def repair_database():
    print(bold("\n  Repair Database\n"))
    conn = get_connection()
    cur = conn.cursor()
    repaired = 0

    print(dim("  Scanning OTP secrets..."))
    cur.execute("SELECT id, secret, name FROM otp_secrets")
    rows = cur.fetchall()
    print(f"  {gray(str(len(rows)))} secret(s) found")

    for id_, secret, name in rows:
        cleaned = ''.join(c for c in secret.upper() if c.isalnum())
        try:
            pyotp.TOTP(cleaned).now()
        except (ValueError, TypeError, BinasciiError):
            placeholder = pyotp.random_base32()
            new_name = name + " (placeholder)" if "(placeholder)" not in name else name
            cur.execute("UPDATE otp_secrets SET secret = ?, name = ? WHERE id = ?", (placeholder, new_name, id_))
            print(f"  {yellow('!')} Secret ID {id_} replaced with placeholder")
            repaired += 1
            continue
        if cleaned != secret:
            cur.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned, id_))
            print(f"  {yellow('!')} Secret ID {id_} formatting fixed")
            repaired += 1

    conn.commit()
    conn.close()
    if repaired == 0:
        print(f"  {green('✓')} No repairs needed")
    else:
        print(f"  {green('✓')} Repaired {repaired} secret(s)")
    print(f"\n  {bold('Done.')}\n")


def upgrade_database():
    print(bold("\n  Upgrade Database Schema\n"))
    conn = get_connection()
    cur = conn.cursor()

    print(dim("  Backing up database..."))
    backup_dir = os.path.join(BASE_DIR, "backup")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    if not os.path.exists(BACKUP_PATH):
        shutil.copy(INSTANCE_PATH, BACKUP_PATH)
        print(f"  {green('✓')} Backup saved to {gray(BACKUP_PATH)}")
    else:
        print(f"  {green('✓')} Backup already exists for today")

    print(dim("  Checking users schema..."))
    cur.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cur.fetchall()]

    required_columns = [
        "pinned", "can_delete", "can_edit", "can_add_companies",
        "can_delete_companies", "can_add_secrets", "can_add_users",
        "blur_on_inactive", "show_including_admin_on_top"
    ]

    if any(col not in columns for col in required_columns):
        print(f"  {yellow('!')} Outdated schema — performing full migration")
        cur.execute("ALTER TABLE users RENAME TO users_old")
        cur.execute("PRAGMA table_info(users_old)")
        old_columns = [col[1] for col in cur.fetchall()]

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
                int(data.get("show_company", 0) or 0),
                int(data.get("blur_on_inactive", 1) or 1),
                int(data.get("show_including_admin_on_top", 0) or 0)
            ))
            migrated += 1

        cur.execute("DROP TABLE users_old")
        conn.commit()
        conn.close()
        print(f"  {green('✓')} Migrated {migrated} user(s) to new schema")
        print(f"\n  {bold('Done.')}\n")
        return

    changed = False
    if "blur_on_inactive" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN blur_on_inactive INTEGER DEFAULT 0")
        print(f"  {green('✓')} Added column: {gray('blur_on_inactive')}")
        changed = True
    if "show_including_admin_on_top" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN show_including_admin_on_top INTEGER DEFAULT 0")
        print(f"  {green('✓')} Added column: {gray('show_including_admin_on_top')}")
        changed = True
    if not changed:
        print(f"  {green('✓')} Schema is already up to date")

    conn.commit()
    conn.close()
    print(f"\n  {bold('Done.')}\n")


def database_stats():
    print(bold("\n  Database Statistics\n"))
    conn = get_connection()
    cur = conn.cursor()

    def safe_count(query):
        try:
            cur.execute(query)
            return cur.fetchone()[0]
        except Exception:
            return "n/a"

    # Users
    if _table_exists(cur, "users"):
        total_users = safe_count("SELECT COUNT(*) FROM users")
        admin_users = safe_count("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        active_sessions = safe_count("SELECT COUNT(*) FROM users WHERE session_token IS NOT NULL AND session_token != ''")
        print(f"  {bold('Users')}")
        print(f"    Total         : {gray(str(total_users))}")
        print(f"    Admins        : {gray(str(admin_users))}")
        print(f"    Active sessions: {gray(str(active_sessions))}")
    else:
        print(f"  {yellow('!')} Table 'users' not found")

    print("")

    # OTP secrets
    if _table_exists(cur, "otp_secrets"):
        total_secrets = safe_count("SELECT COUNT(*) FROM otp_secrets")
        totp_count = safe_count("SELECT COUNT(*) FROM otp_secrets WHERE otp_type = 'totp'")
        hotp_count = safe_count("SELECT COUNT(*) FROM otp_secrets WHERE otp_type = 'hotp'")
        unassigned = safe_count("SELECT COUNT(*) FROM otp_secrets WHERE company_id IS NULL")
        print(f"  {bold('OTP Secrets')}")
        print(f"    Total         : {gray(str(total_secrets))}")
        print(f"    TOTP          : {gray(str(totp_count))}")
        print(f"    HOTP          : {gray(str(hotp_count))}")
        print(f"    No company    : {gray(str(unassigned))}")
    else:
        print(f"  {yellow('!')} Table 'otp_secrets' not found")

    print("")

    # Companies
    if _table_exists(cur, "companies"):
        total_companies = safe_count("SELECT COUNT(*) FROM companies")
        print(f"  {bold('Companies')}")
        print(f"    Total         : {gray(str(total_companies))}")
    else:
        print(f"  {yellow('!')} Table 'companies' not found")

    print("")

    # Statistics
    if _table_exists(cur, "statistics"):
        total_logins = safe_count("SELECT SUM(logins_today) FROM statistics")
        total_refreshes = safe_count("SELECT SUM(times_refreshed) FROM statistics")
        days_tracked = safe_count("SELECT COUNT(*) FROM statistics")
        print(f"  {bold('Usage Statistics')}")
        print(f"    Days tracked  : {gray(str(days_tracked))}")
        print(f"    Total logins  : {gray(str(total_logins))}")
        print(f"    Total refreshes: {gray(str(total_refreshes))}")
    else:
        print(f"  {yellow('!')} Table 'statistics' not found")

    print("")

    # File size
    try:
        size_bytes = os.path.getsize(INSTANCE_PATH)
        if size_bytes >= 1024 * 1024:
            size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            size_str = f"{size_bytes / 1024:.1f} KB"
        print(f"  {bold('Database file')}")
        print(f"    Size          : {gray(size_str)}")
    except Exception:
        pass

    conn.close()
    print(f"\n  {bold('Done.')}\n")


def vacuum_database():
    print(bold("\n  Vacuum Database\n"))
    conn = get_connection()

    try:
        size_before = os.path.getsize(INSTANCE_PATH)
    except Exception:
        size_before = None

    print(dim("  Running VACUUM..."))
    conn.execute("VACUUM")
    conn.close()

    try:
        size_after = os.path.getsize(INSTANCE_PATH)
    except Exception:
        size_after = None

    if size_before is not None and size_after is not None:
        saved = size_before - size_after
        def fmt(b):
            return f"{b / 1024:.1f} KB" if b < 1024 * 1024 else f"{b / (1024 * 1024):.2f} MB"
        print(f"  {green('✓')} Vacuum complete")
        print(f"    Before : {gray(fmt(size_before))}")
        print(f"    After  : {gray(fmt(size_after))}")
        if saved > 0:
            print(f"    Saved  : {green(fmt(saved))}")
        else:
            print(f"    {dim('No space reclaimed — database was already compact')}")
    else:
        print(f"  {green('✓')} Vacuum complete")

    print(f"\n  {bold('Done.')}\n")


def reset_sessions():
    print(bold("\n  Reset All Sessions\n"))
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users WHERE session_token IS NOT NULL AND session_token != ''")
    active = cur.fetchone()[0]

    if active == 0:
        print(f"  {green('✓')} No active sessions to clear")
        conn.close()
        print(f"\n  {bold('Done.')}\n")
        return

    print(dim(f"  Clearing {active} active session(s)..."))
    cur.execute("UPDATE users SET session_token = NULL")
    conn.commit()
    conn.close()
    print(f"  {green('✓')} {active} session(s) invalidated — all users will need to log in again")
    print(f"\n  {bold('Done.')}\n")


def check_schema_needs_update():
    """Returns True if the users table is missing any required columns."""
    if not os.path.exists(INSTANCE_PATH):
        return False
    required = [
        "pinned", "can_delete", "can_edit", "can_add_companies",
        "can_delete_companies", "can_add_secrets", "can_add_users",
        "blur_on_inactive", "show_including_admin_on_top"
    ]
    try:
        conn = sqlite3.connect(INSTANCE_PATH)
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cur.fetchall()]
        conn.close()
        return any(col not in columns for col in required)
    except Exception:
        return False


def create_backup():
    print(bold("\n  Create Backup\n"))
    backup_dir = os.path.join(BASE_DIR, "backup")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        print(f"  {dim('Created backup directory')}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dest = os.path.join(backup_dir, f"otp_{timestamp}.db")

    if not os.path.exists(INSTANCE_PATH):
        raise FileNotFoundError(f"Database not found at {INSTANCE_PATH}")

    print(dim("  Creating consistent backup via SQLite backup API..."))
    src_conn = sqlite3.connect(INSTANCE_PATH)
    dst_conn = sqlite3.connect(dest)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    size_bytes = os.path.getsize(dest)
    size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_bytes / (1024 * 1024):.2f} MB"
    print(f"  {green('✓')} Backup saved: {gray(os.path.basename(dest))}  {dim(size_str)}")
    print(f"\n  {bold('Done.')}\n")


def list_backups():
    print(bold("\n  Backup Files\n"))
    backup_dir = os.path.join(BASE_DIR, "backup")
    if not os.path.exists(backup_dir):
        print(f"  {dim('No backup directory found.')}")
        print(f"\n  {bold('Done.')}\n")
        return

    files = [f for f in os.listdir(backup_dir) if f.endswith(".db")]
    if not files:
        print(f"  {dim('No backup files found.')}")
        print(f"\n  {bold('Done.')}\n")
        return

    entries = []
    for name in files:
        path = os.path.join(backup_dir, name)
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except Exception:
            mtime, size = 0, 0
        entries.append((mtime, name, size))

    entries.sort(reverse=True)

    def fmt_size(b):
        return f"{b / 1024:.1f} KB" if b < 1024 * 1024 else f"{b / (1024 * 1024):.2f} MB"

    def fmt_age(mtime):
        delta = int(datetime.now().timestamp() - mtime)
        if delta < 60:
            return f"{delta}s ago"
        if delta < 3600:
            return f"{delta // 60}m ago"
        if delta < 86400:
            return f"{delta // 3600}h ago"
        return f"{delta // 86400}d ago"

    print(f"  {gray(str(len(entries)))} backup(s) found\n")
    for i, (mtime, name, size) in enumerate(entries):
        age = fmt_age(mtime) if mtime else "?"
        marker = green("▶") if i == 0 else " "
        print(f"  {marker} {name}  {dim(fmt_size(size))}  {gray(age)}")

    print(f"\n  {bold('Done.')}\n")


def get_backup_entries():
    """Return list of (mtime, name, size, path) sorted newest-first."""
    backup_dir = os.path.join(BASE_DIR, "backup")
    if not os.path.exists(backup_dir):
        return []
    entries = []
    for name in os.listdir(backup_dir):
        if not name.endswith(".db"):
            continue
        path = os.path.join(backup_dir, name)
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except Exception:
            mtime, size = 0, 0
        entries.append((mtime, name, size, path))
    entries.sort(reverse=True)
    return entries


def restore_backup_file(path):
    print(bold("\n  Restore Backup\n"))

    if not os.path.exists(path):
        raise FileNotFoundError(f"Backup file not found: {path}")

    def fmt(b):
        return f"{b / 1024:.1f} KB" if b < 1024 * 1024 else f"{b / (1024 * 1024):.2f} MB"

    # Auto-save a security backup of the current DB before overwriting
    if os.path.exists(INSTANCE_PATH):
        backup_dir = os.path.join(BASE_DIR, "backup")
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        safety_ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safety_path = os.path.join(backup_dir, f"otp_security-backup_{safety_ts}.db")
        print(dim("  Saving security backup of current database..."))
        src_conn = sqlite3.connect(INSTANCE_PATH)
        saf_conn = sqlite3.connect(safety_path)
        try:
            src_conn.backup(saf_conn)
        finally:
            saf_conn.close()
            src_conn.close()
        print(f"  {green('✓')} Security backup: {gray(os.path.basename(safety_path))}  {dim(fmt(os.path.getsize(safety_path)))}")

    print(dim(f"  Restoring {os.path.basename(path)} → otp.db..."))
    bak_conn = sqlite3.connect(path)
    dst_conn = sqlite3.connect(INSTANCE_PATH)
    try:
        bak_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        bak_conn.close()

    # Remove stale WAL/SHM files so SQLite doesn't replay the old session
    for ext in ("-wal", "-shm"):
        stale = INSTANCE_PATH + ext
        if os.path.exists(stale):
            os.remove(stale)
            print(f"  {dim(f'Removed stale {os.path.basename(stale)}')}")

    size = os.path.getsize(INSTANCE_PATH)
    print(f"  {green('✓')} Database restored  {dim(fmt(size))}")
    print(f"\n  {bold('Done.')}\n")
