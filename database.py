import os
import sqlite3
import shutil
import re
import time
import json
from datetime import datetime
from logger import logger

INSTANCE_DIR = "instance"
BACKUP_DIR = "backup"
STATE_PATH = os.path.join(INSTANCE_DIR, "maintenance_state.json")
DB_NAME = "otp.db"
DB_PATH = os.path.join(INSTANCE_DIR, DB_NAME)
LOCK_PATH = os.path.join(INSTANCE_DIR, "db_maint.lock")
LOCK_STALE_SECONDS = 5400

FORBIDDEN_WORDS = [
    "INVALID","FORBIDDEN","ERROR","SELECT","DROP","INSERT","DELETE",
    "CREATE","ALTER","EXEC","EXECUTE","TRIGGER","GRANT","REVOKE","COMMIT",
    "ROLLBACK","SAVEPOINT","FLUSH","SHUTDOWN","UNION","INTERSECT","EXCEPT",
    "SCRIPT","SCRIPTING","NULL","TRUE","FALSE","LIMIT","TABLE","VIEW","KEY",
    "INDEX","DISTINCT","JOIN","WHERE","ORDER BY","GROUP BY","HAVING","DECLARE",
    "CURSOR","FETCH","LOCK"
]

def ensure_dirs():
    if not os.path.exists(INSTANCE_DIR):
        os.makedirs(INSTANCE_DIR)
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def connect():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA synchronous=NORMAL")
    return db

def backup_db():
    if not os.path.exists(DB_PATH):
        return None
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"otp_{ts}_{os.getpid()}.db")
    shutil.copyfile(DB_PATH, dest)
    backups = sorted(
        [os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.startswith("otp_") and f.endswith(".db")],
        key=os.path.getmtime,
        reverse=True
    )
    for old_backup in backups[3:]:
        try:
            os.remove(old_backup)
            logger.info("old backup removed: %s", old_backup)
        except Exception as e:
            logger.critical("could not remove old backup %s: %s", old_backup, e)
    return dest

def load_state():
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except:
        return {}

def save_state(s):
    try:
        with open(STATE_PATH, "w") as f:
            json.dump(s, f)
    except:
        pass

def init_db():
    created = not os.path.exists(DB_PATH)
    with connect() as db:
        c = db.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                company_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kundennummer INTEGER UNIQUE,
                password TEXT
            )
        """)
        c.execute("""
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
        c.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                logins_today INTEGER NOT NULL,
                times_refreshed INTEGER NOT NULL,
                date TEXT NOT NULL
            )
        """)
        c.execute("""
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
                show_company INTEGER DEFAULT 0
            )
        """)
        db.commit()
        if created:
            c.execute("INSERT OR IGNORE INTO companies (name) VALUES ('Public'), ('Private')")
            db.commit()
        c.execute("SELECT id FROM users WHERE id = 1")
        if c.fetchone() is None:
            c.execute("INSERT INTO users (id, username, password, is_admin) VALUES (1, 'admin', '1234', 1)")
            db.commit()
        c.execute("SELECT COUNT(*) FROM statistics")
        if (c.fetchone() or [0])[0] == 0:
            c.execute("INSERT INTO statistics (id, logins_today, times_refreshed, date) VALUES (1, 0, 0, ?)", (datetime.now().strftime("%Y-%m-%d"),))
            db.commit()
    if created:
        logger.info("database initialized at %s", DB_PATH)

def normalize_secrets():
    updated = 0
    with connect() as db:
        c = db.cursor()
        c.execute("SELECT id, secret FROM otp_secrets")
        rows = c.fetchall()
        for rid, secret in rows:
            if not secret:
                continue
            cleaned = re.sub(r"[^A-Z2-7]", "", secret.upper())
            if cleaned != secret:
                c.execute("UPDATE otp_secrets SET secret = ? WHERE id = ?", (cleaned, rid))
                updated += 1
        if updated:
            db.commit()
    if updated:
        logger.warning("normalized %d otp secrets to base32 charset A–Z2–7", updated)

def check_names():
    issues = []
    with connect() as db:
        c = db.cursor()
        c.execute("SELECT id, name FROM otp_secrets")
        for rid, name in c.fetchall():
            n = (name or "").strip()
            if n == "":
                issues.append(("empty_name", rid))
            else:
                up = n.upper()
                if any(w in up for w in FORBIDDEN_WORDS):
                    issues.append(("forbidden_word", rid))
    for kind, rid in issues:
        if kind == "empty_name":
            logger.warning("otp_secrets id=%s has empty name", rid)
        else:
            logger.warning("otp_secrets id=%s contains forbidden word in name", rid)
    return len(issues)

def check_orphans():
    with connect() as db:
        c = db.cursor()
        c.execute("""
            SELECT s.id, s.company_id
            FROM otp_secrets s
            LEFT JOIN companies c ON c.company_id = s.company_id
            WHERE s.company_id IS NOT NULL AND c.company_id IS NULL
        """)
        rows = c.fetchall()
    for rid, cid in rows:
        logger.error("orphan secret id=%s references missing company_id=%s", rid, cid)
    return len(rows)

def pragma_checks():
    fk_issues = 0
    with connect() as db:
        c = db.cursor()
        c.execute("PRAGMA integrity_check")
        result = c.fetchone()
        if not result or result[0].lower() != "ok":
            logger.critical("integrity_check failed: %s", (result or ["none"])[0])
        else:
            logger.info("integrity_check ok")
        c.execute("PRAGMA foreign_key_check")
        rows = c.fetchall()
        fk_issues = len(rows)
        if fk_issues:
            for row in rows[:50]:
                logger.error("foreign_key_check issue: %s", row)
            if fk_issues > 50:
                logger.error("foreign_key_check additional issues: %d", fk_issues - 50)
        else:
            logger.info("foreign_key_check ok")
    return fk_issues

def optimize_if_needed():
    st = load_state()
    today = datetime.now().strftime("%Y-%m-%d")
    if st.get("last_vacuum") != today:
        try:
            with connect() as db:
                db.isolation_level = None
                db.execute("VACUUM")
                db.execute("PRAGMA optimize")
            st["last_vacuum"] = today
            save_state(st)
            logger.info("vacuum and optimize completed")
        except Exception as e:
            logger.exception("vacuum/optimize failed: %s", e)
    else:
        try:
            with connect() as db:
                db.execute("PRAGMA optimize")
            logger.info("optimize completed")
        except Exception as e:
            logger.exception("optimize failed: %s", e)

def acquire_lock():
    try:
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return True
    except FileExistsError:
        try:
            age = time.time() - os.path.getmtime(LOCK_PATH)
        except FileNotFoundError:
            return acquire_lock()
        if age >= LOCK_STALE_SECONDS:
            try:
                os.unlink(LOCK_PATH)
                return acquire_lock()
            except:
                return False
        return False
    except:
        return False

def release_lock():
    try:
        if os.path.exists(LOCK_PATH):
            os.unlink(LOCK_PATH)
    except:
        pass

def _already_ran_this_hour():
    st = load_state()
    hour_key = datetime.now().strftime("%Y-%m-%d %H")
    return st.get("last_maintenance_hour") == hour_key, hour_key, st

def hourly_maintenance():
    ran, hour_key, st = _already_ran_this_hour()
    if ran:
        logger.info("maintenance skipped, already ran this hour (%s)", hour_key)
        return
    logger.info("Starting scheduled database maintenance...")
    t0 = time.perf_counter()
    ensure_dirs()
    init_db()
    b = backup_db()
    if b:
        logger.info("database backup created at %s", b)
    normalize_secrets()
    name_issues = check_names()
    orphan_issues = check_orphans()
    fk_issues = pragma_checks()
    optimize_if_needed()
    st["last_maintenance_hour"] = hour_key
    save_state(st)
    dt = round((time.perf_counter() - t0) * 1000)
    if any([name_issues, orphan_issues, fk_issues]):
        logger.warning("maintenance finished with issues names=%d orphans=%d fk=%d duration_ms=%d", name_issues, orphan_issues, fk_issues, dt)
    else:
        logger.info("maintenance finished ok duration_ms=%d", dt)