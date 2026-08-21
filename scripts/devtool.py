#!/usr/bin/env python3
"""
Dev CLI for testing the OTP manager at scale.

Seeds/clears fake OTP secrets (and companies/pins), and measures the
server-side cost of building the /api/secrets response at the current
vault size. Fake data is always name-tagged with a prefix so `clear`
can never touch real secrets.

Usage:
    python3 scripts/devtool.py seed 700
    python3 scripts/devtool.py seed 700 --companies 12 --pin 5
    python3 scripts/devtool.py stats
    python3 scripts/devtool.py bench
    python3 scripts/devtool.py clear
"""
import argparse
import json
import os
import random
import re
import sqlite3
import sys
import time

import pyotp

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(BASE_DIR, "instance", "otp.db")

# tracks which company_ids this tool created, since fake companies get
# realistic-looking names (no "[TEST]" tag) and so can't be found by name
FAKE_STATE_PATH = os.path.join(SCRIPT_DIR, ".devtool_state.json")

DEFAULT_PREFIX = "[TEST] "

SERVICES = [
    "Microsoft 365", "Google Workspace", "AWS Root", "Azure AD", "GitHub Org",
    "GitLab", "Cloudflare", "VPN Portal", "Domain Admin", "Exchange Admin",
    "Firewall Admin", "Backup Console", "RDP Gateway", "Server Login",
    "Monitoring", "Ticketing System", "Password Manager", "CRM Admin",
    "Billing Portal", "DNS Admin",
]
DOMAINS = ["example.com", "test-client.com", "devmail.io", "example.org", "sandbox.dev"]

COMPANY_WORDS = [
    "Acme", "Globex", "Initech", "Umbrella", "Stark", "Wayne", "Hooli", "Soylent",
    "Cyberdyne", "Wonka", "Oscorp", "Vandelay", "Northwind", "Contoso", "Fabrikam",
    "Tailspin", "Woodgrove", "Massive Dynamic", "Gringotts", "Prestige Worldwide",
]
COMPANY_SUFFIXES = ["Inc.", "LLC", "Ltd.", "GmbH", "Corp.", "Group", "Holdings", "& Co."]

# ---------------------------------------------------------------------------
# color / style helpers — same palette + convention as start.py / edit-database.py
# ---------------------------------------------------------------------------
ANSI = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def c(s, code):
    return f"\x1b[{code}m{s}\x1b[0m" if ANSI else s


def bold(s): return c(s, "1")
def dim(s): return c(s, "2")
def red(s): return c(s, "31")
def green(s): return c(s, "32")
def yellow(s): return c(s, "33")
def cyan(s): return c(s, "36")
def gray(s): return c(s, "90")
def lavender(s): return c(s, "38;5;183")


def visible_len(s):
    return len(ANSI_RE.sub("", s))


def pad(s, width):
    return s + " " * max(0, width - visible_len(s))


SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def ok(msg): print(f"{green('✓')} {msg}")
def warn(msg): print(f"{yellow('⚠')} {msg}")
def err(msg): print(f"{red('✗')} {msg}")
def info(msg): print(f"{cyan('ℹ')} {msg}")


def header(title):
    print(f"\n{lavender(bold('▸ ' + title))}")
    print(gray("─" * (visible_len(title) + 2)))


def box(title, lines):
    inner_w = max([visible_len(title)] + [visible_len(l) for l in lines] + [30])
    top = lavender("┌─ ") + bold(title) + lavender(" " + "─" * (inner_w - visible_len(title) - 1) + "┐")
    bottom = lavender("└" + "─" * (inner_w + 2) + "┘")
    print(top)
    for line in lines:
        print(lavender("│ ") + pad(line, inner_w + 1) + lavender("│"))
    print(bottom)


def progress(done, total, label="working"):
    if not ANSI or total <= 0:
        return
    width = 28
    frac = min(1.0, done / total)
    filled = int(width * frac)
    bar = lavender("█" * filled) + gray("░" * (width - filled))
    frame = SPINNER_FRAMES[int(time.time() * 10) % len(SPINNER_FRAMES)]
    sys.stdout.write(f"\r{cyan(frame)} {label} {bar} {bold(str(done))}/{total}")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# same normalization api.py applies before handing a secret to pyotp
# ---------------------------------------------------------------------------
def normalize_secret(s):
    s = (s or "").strip().upper()
    s = re.sub(r"\s+", "", s)
    s = re.sub(r"=+$", "", s)
    s = re.sub(r"[^A-Z2-7]", "", s)
    return s


def connect():
    if not os.path.exists(DB_PATH):
        err(f"Database not found at {DB_PATH}")
        sys.exit(1)
    info(f"Using database {dim(DB_PATH)}")
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.execute("PRAGMA busy_timeout = 30000")
    db.execute("PRAGMA foreign_keys = ON")
    return db


def load_fake_company_ids(db):
    ids = []
    if os.path.exists(FAKE_STATE_PATH):
        try:
            with open(FAKE_STATE_PATH) as f:
                ids = json.load(f).get("fake_company_ids", [])
        except (json.JSONDecodeError, OSError):
            ids = []
    if not ids:
        return []
    cur = db.cursor()
    placeholders = ",".join("?" * len(ids))
    existing = {r[0] for r in cur.execute(
        f"SELECT company_id FROM companies WHERE company_id IN ({placeholders})", ids
    ).fetchall()}
    pruned = [i for i in ids if i in existing]
    if pruned != ids:
        save_fake_company_ids(pruned)
    return pruned


def save_fake_company_ids(ids):
    try:
        with open(FAKE_STATE_PATH, "w") as f:
            json.dump({"fake_company_ids": ids}, f)
    except OSError:
        pass


def fake_company_name(existing_names):
    for _ in range(200):
        name = f"{random.choice(COMPANY_WORDS)} {random.choice(COMPANY_SUFFIXES)}"
        if name not in existing_names:
            return name
    i = 1
    while True:
        name = f"{random.choice(COMPANY_WORDS)} {random.choice(COMPANY_SUFFIXES)} {i}"
        if name not in existing_names:
            return name
        i += 1


def ensure_fake_companies(db, count):
    if count <= 0:
        return [None]
    cur = db.cursor()
    ids = load_fake_company_ids(db)
    if len(ids) >= count:
        return ids[:count]
    existing_names = {r[0] for r in cur.execute("SELECT name FROM companies").fetchall()}
    while len(ids) < count:
        name = fake_company_name(existing_names)
        cur.execute(
            "INSERT INTO companies (name, kundennummer, password, login_enabled) VALUES (?, NULL, NULL, 0)",
            (name,),
        )
        ids.append(cur.lastrowid)
        existing_names.add(name)
    db.commit()
    save_fake_company_ids(ids)
    return ids


def cmd_seed(args):
    header(f"Seeding {args.count} fake secrets")
    db = connect()
    prefix = args.prefix
    cur = db.cursor()

    company_ids = ensure_fake_companies(db, args.companies)

    start_idx = cur.execute(
        "SELECT COUNT(*) FROM otp_secrets WHERE name LIKE ?", (prefix + "%",)
    ).fetchone()[0]

    rows = []
    for i in range(args.count):
        idx = start_idx + i + 1
        service = random.choice(SERVICES)
        name = f"{prefix}{service} #{idx}"
        email = f"user{idx}@{random.choice(DOMAINS)}"
        secret = pyotp.random_base32()
        company_id = random.choice(company_ids)
        rows.append((name, email, secret, "totp", 30, company_id))
        if (i + 1) % 25 == 0 or i + 1 == args.count:
            progress(i + 1, args.count, "generating")

    t0 = time.perf_counter()
    try:
        cur.executemany(
            """INSERT INTO otp_secrets (name, email, secret, otp_type, refresh_time, company_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        db.rollback()
        err(f"Insert failed ({e}).")
        info("Leftover test data with the same prefix may be numbered unexpectedly — run 'clear' first, then retry.")
        sys.exit(1)
    dt = round((time.perf_counter() - t0) * 1000)

    pinned_n = 0
    if args.pin > 0:
        pinned_n = pin_new_secrets(db, args.user_id, [r[0] for r in rows], args.pin)

    total = cur.execute("SELECT COUNT(*) FROM otp_secrets").fetchone()[0]
    db.close()

    lines = [
        f"Inserted     {bold(green(str(len(rows))))} secrets in {bold(str(dt))}ms",
        f"Companies    {bold(str(len(company_ids)))} fake companies used",
    ]
    if args.pin > 0:
        lines.append(f"Pinned       {bold(str(pinned_n))} secrets for user_id={args.user_id}")
    lines.append(f"Vault total  {bold(cyan(str(total)))} secrets")
    box("seed complete", lines)


def pin_new_secrets(db, user_id, names, n):
    cur = db.cursor()
    placeholders = ",".join("?" * len(names))
    ids = [str(r[0]) for r in cur.execute(
        f"SELECT id FROM otp_secrets WHERE name IN ({placeholders})", names
    ).fetchall()]
    n = min(n, len(ids))
    if n <= 0:
        return 0
    chosen = random.sample(ids, n)

    row = cur.execute("SELECT pinned FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        warn(f"No user with id={user_id}, skipping pin step.")
        return 0
    current = set(filter(None, (row[0] or "").split(",")))
    current.update(chosen)
    cur.execute("UPDATE users SET pinned = ? WHERE id = ?", (",".join(current), user_id))
    db.commit()
    return n


def cmd_clear(args):
    header("Clearing fake data")
    db = connect()
    prefix = args.prefix
    cur = db.cursor()

    secret_rows = cur.execute("SELECT id, name FROM otp_secrets WHERE name LIKE ?", (prefix + "%",)).fetchall()
    fake_company_ids = load_fake_company_ids(db)
    company_rows = []
    if fake_company_ids:
        placeholders = ",".join("?" * len(fake_company_ids))
        company_rows = cur.execute(
            f"SELECT company_id, name FROM companies WHERE company_id IN ({placeholders})", fake_company_ids
        ).fetchall()

    if not secret_rows and not company_rows:
        info(f"Nothing found matching prefix {prefix!r}.")
        return

    warn(f"Found {bold(str(len(secret_rows)))} fake secrets and {bold(str(len(company_rows)))} fake companies matching prefix {prefix!r}.")
    if not args.yes:
        resp = input(f"  {yellow('Delete these? Type')} {bold('yes')} {yellow('to confirm:')} ")
        if resp.strip().lower() != "yes":
            info("Aborted.")
            return

    secret_ids = [r[0] for r in secret_rows]
    if secret_ids:
        placeholders = ",".join("?" * len(secret_ids))
        cur.execute(f"DELETE FROM otp_secrets WHERE id IN ({placeholders})", secret_ids)

        id_strs = {str(i) for i in secret_ids}
        for uid, pinned in cur.execute(
            "SELECT id, pinned FROM users WHERE pinned IS NOT NULL AND pinned != ''"
        ).fetchall():
            current = set(filter(None, pinned.split(",")))
            cleaned = current - id_strs
            if cleaned != current:
                cur.execute("UPDATE users SET pinned = ? WHERE id = ?", (",".join(cleaned), uid))

    removed_companies = 0
    removed_ids = []
    for cid, _cname in company_rows:
        remaining = cur.execute("SELECT COUNT(*) FROM otp_secrets WHERE company_id = ?", (cid,)).fetchone()[0]
        if remaining == 0:
            cur.execute("DELETE FROM companies WHERE company_id = ?", (cid,))
            removed_companies += 1
            removed_ids.append(cid)

    db.commit()
    db.close()
    save_fake_company_ids([i for i in fake_company_ids if i not in removed_ids])
    ok(f"Deleted {bold(str(len(secret_ids)))} secrets and {bold(str(removed_companies))} companies.")


def cmd_stats(args):
    header("Vault stats")
    db = connect()
    cur = db.cursor()
    total = cur.execute("SELECT COUNT(*) FROM otp_secrets").fetchone()[0]
    fake = cur.execute("SELECT COUNT(*) FROM otp_secrets WHERE name LIKE ?", (args.prefix + "%",)).fetchone()[0]
    companies = cur.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
    fake_companies = len(load_fake_company_ids(db))
    db.close()

    def row(label, n, fake_n, fake_label):
        real = n - fake_n
        count_str = pad(bold(cyan(str(n))), 6)
        return f"{pad(label, 11)} {count_str} ({green(str(real))} real, {lavender(str(fake_n))} {fake_label})"

    box("stats", [
        row("Secrets", total, fake, f"tagged {args.prefix!r}"),
        row("Companies", companies, fake_companies, "fake (tracked)"),
    ])


def cmd_bench(args):
    header("Benchmarking /api/secrets cost")
    db = connect()
    cur = db.cursor()

    t0 = time.perf_counter()
    cur.execute("""
        SELECT s.id, s.name, s.email, s.secret, s.otp_type, s.refresh_time, s.company_id, c.name
        FROM otp_secrets s
        LEFT JOIN companies c ON s.company_id = c.company_id
    """)
    rows = cur.fetchall()
    t_query = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    now = int(time.time())
    out = []
    errors = 0
    for row in rows:
        try:
            code = pyotp.TOTP(normalize_secret(row[3])).now()
        except Exception:
            code = ""
            errors += 1
        out.append({
            "id": row[0], "name": row[1], "email": row[2], "secret": row[3],
            "otp_type": row[4], "refresh_time": row[5], "company_id": row[6],
            "company_name": row[7], "current_code": code,
            "seconds_remaining": 30 - (now % 30),
        })
    t_compute = (time.perf_counter() - t1) * 1000

    t2 = time.perf_counter()
    payload = json.dumps(out)
    t_serialize = (time.perf_counter() - t2) * 1000
    db.close()

    total_ms = t_query + t_compute + t_serialize
    kb = len(payload) / 1024

    def bar_line(label, ms):
        width = 24
        frac = 0 if total_ms == 0 else min(1.0, ms / total_ms)
        filled = int(width * frac)
        bar = cyan("█" * filled) + gray("░" * (width - filled))
        return f"{pad(label, 15)} {bar} {bold(f'{ms:.2f}ms')}"

    lines = [
        f"Rows            {bold(str(len(rows)))}",
        bar_line("SQL query", t_query),
        bar_line("TOTP compute", t_compute) + (f"  {red(str(errors) + ' invalid')}" if errors else ""),
        bar_line("JSON encode", t_serialize),
        f"Payload size    {bold(yellow(f'{kb:.1f} KB') if kb > 200 else green(f'{kb:.1f} KB'))}",
        f"Total           {bold(green(f'{total_ms:.2f}ms') if total_ms < 100 else yellow(f'{total_ms:.2f}ms'))}",
    ]
    box("bench (one /api/secrets call)", lines)
    print(dim("  polled roughly every 30s per open tab/sidebar"))


def ask(msg, default=None, cast=str):
    label = msg + (f" [{default}]" if default is not None else "")
    raw = input(f"  {cyan('?')} {label}: ").strip()
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        warn(f"Invalid value, using default ({default}).")
        return default


def clear_screen():
    if ANSI:
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
    else:
        os.system("cls" if os.name == "nt" else "clear")


def interactive_menu():
    options = [
        ("1", "Seed fake secrets", cmd_seed),
        ("2", "Show vault stats", cmd_stats),
        ("3", "Benchmark /api/secrets", cmd_bench),
        ("4", "Clear fake data", cmd_clear),
    ]
    ran_command = False
    while True:
        if ran_command:
            input(f"\n{dim('Press Enter to continue...')}")
            ran_command = False
        clear_screen()
        print(f"{lavender(bold('▸ OTP Manager — Dev Tool'))}")
        print(gray("─" * 26))
        for key, label, _ in options:
            print(f"  {bold(key)}  {label}")
        print(f"  {bold('q')}  Quit")
        choice = input(f"\n{cyan('>')} ").strip().lower()

        if choice in ("q", "quit", "exit", ""):
            break
        elif choice == "1":
            count = ask("How many fake secrets?", 100, int)
            companies = ask("How many fake companies to spread them across?", 8, int)
            pin = ask("Pin how many of them (sidebar test)?", 0, int)
            cmd_seed(argparse.Namespace(count=count, prefix=DEFAULT_PREFIX, companies=companies, pin=pin, user_id=1))
            ran_command = True
        elif choice == "2":
            cmd_stats(argparse.Namespace(prefix=DEFAULT_PREFIX))
            ran_command = True
        elif choice == "3":
            cmd_bench(argparse.Namespace())
            ran_command = True
        elif choice == "4":
            cmd_clear(argparse.Namespace(prefix=DEFAULT_PREFIX, yes=False))
            ran_command = True
        else:
            warn("Unknown option.")
            ran_command = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=False)

    p_seed = sub.add_parser("seed", help="add N fake secrets")
    p_seed.add_argument("count", type=int, help="number of fake secrets to create")
    p_seed.add_argument("--prefix", default=DEFAULT_PREFIX, help=f"name tag for fake data (default: {DEFAULT_PREFIX!r})")
    p_seed.add_argument("--companies", type=int, default=8, help="fake companies to spread secrets across (0 = none)")
    p_seed.add_argument("--pin", type=int, default=0, help="pin N of the new secrets, to test the sidebar/pinned widget")
    p_seed.add_argument("--user-id", type=int, default=1, help="user id to pin for (default: 1)")
    p_seed.set_defaults(func=cmd_seed)

    p_clear = sub.add_parser("clear", help="remove all fake secrets/companies created by this tool")
    p_clear.add_argument("--prefix", default=DEFAULT_PREFIX)
    p_clear.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompt")
    p_clear.set_defaults(func=cmd_clear)

    p_stats = sub.add_parser("stats", help="show secret/company counts")
    p_stats.add_argument("--prefix", default=DEFAULT_PREFIX)
    p_stats.set_defaults(func=cmd_stats)

    p_bench = sub.add_parser("bench", help="measure server-side cost of building /api/secrets at current vault size")
    p_bench.set_defaults(func=cmd_bench)

    parser.add_argument("--no-color", action="store_true", help="disable colored output")

    args = parser.parse_args()
    if args.no_color:
        global ANSI
        ANSI = False
    if args.command is None:
        interactive_menu()
    else:
        args.func(args)


if __name__ == "__main__":
    main()
