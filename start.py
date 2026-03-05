import os
import sys
import time
import json
import signal
import shutil
import zipfile
import tempfile
import subprocess
from datetime import datetime
import re
import socket
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PID_PATH = os.path.join(BASE_DIR, "otp-server.pid")
STATE_PATH = os.path.join(BASE_DIR, "otp-server.state.json")
LOG_PATH = os.path.join(BASE_DIR, "otp-server.output.log")
APP_PY_PATH = os.path.join(BASE_DIR, "app.py")
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
SETTINGS_PATH = os.path.join(BASE_DIR, "settings.json")

PYTHON = sys.executable or "python3"
APP_CMD = [PYTHON, os.path.join(BASE_DIR, "app.py")]

GITHUB_OWNER = "Migrim"
GITHUB_REPO = "OTP-Manager-Refactored"
GITHUB_BRANCH = "main"

REMOTE_VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}/VERSION"
REMOTE_ZIP_URL = f"https://codeload.github.com/{GITHUB_OWNER}/{GITHUB_REPO}/zip/refs/heads/{GITHUB_BRANCH}"

PROTECTED_NAMES = {
    "instance",
    "logs",
    ".git",
    "__pycache__",
    ".venv",
    "venv"
}

PROTECTED_FILES = {
    os.path.basename(PID_PATH),
    os.path.basename(STATE_PATH),
    os.path.basename(LOG_PATH),
    os.path.basename(SETTINGS_PATH)
}

ANSI = sys.stdout.isatty()

def c(s, code):
    if not ANSI:
        return s
    return f"\x1b[{code}m{s}\x1b[0m"

def bold(s): return c(s, "1")
def dim(s): return c(s, "2")
def red(s): return c(s, "31")
def green(s): return c(s, "32")
def yellow(s): return c(s, "33")
def lavender(s): return c(s, "38;5;183")
def cyan(s): return c(s, "36")
def gray(s): return c(s, "90")

def clear():
    if not ANSI:
        return
    os.system("cls" if os.name == "nt" else "clear")

def get_default_settings():
    return {
        "host": "0.0.0.0",
        "port": 7440,
        "secret_key": "change-this-secret"
    }

def read_settings():
    defaults = get_default_settings()
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except:
        data = {}
    host = str(data.get("host") or defaults["host"]).strip() or defaults["host"]
    try:
        port = int(data.get("port", defaults["port"]))
    except:
        port = defaults["port"]
    secret_key = str(data.get("secret_key") or defaults["secret_key"]).strip() or defaults["secret_key"]
    return {
        "host": host,
        "port": port,
        "secret_key": secret_key
    }

def write_settings(data):
    current = get_default_settings()
    current.update(data or {})
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)

def ensure_settings_file():
    if not os.path.exists(SETTINGS_PATH):
        write_settings(get_default_settings())

def mask_secret(secret):
    secret = str(secret or "")
    if not secret:
        return "-"
    if len(secret) <= 4:
        return "*" * len(secret)
    return secret[:2] + ("*" * (len(secret) - 4)) + secret[-2:]

def valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except:
        return False

def port_in_use(host, port):
    targets = []
    host = str(host or "").strip()
    try:
        port = int(port)
    except:
        return False

    if host in ("0.0.0.0", "::", ""):
        targets = ["127.0.0.1"]
    elif host == "localhost":
        targets = ["127.0.0.1"]
    else:
        targets = [host]

    for target in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                return True
        except:
            pass
    return False

def read_pid():
    try:
        with open(PID_PATH, "r", encoding="utf-8") as f:
            v = f.read().strip()
        return int(v) if v else None
    except:
        return None

def write_pid(pid):
    with open(PID_PATH, "w", encoding="utf-8") as f:
        f.write(str(int(pid)))

def remove_pid():
    try:
        os.remove(PID_PATH)
    except:
        pass

def read_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except:
        return {}

def write_state(d):
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except:
        pass

def remove_state():
    try:
        os.remove(STATE_PATH)
    except:
        pass

def pid_alive(pid):
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except:
        return False

def configured_port_in_use():
    cfg = read_settings()
    return port_in_use(cfg.get("host"), cfg.get("port"))

def cleanup_if_stale():
    pid = read_pid()
    if not pid:
        return False
    if pid_alive(pid):
        return False
    if configured_port_in_use():
        return False
    remove_pid()
    remove_state()
    return True

def fmt_uptime(start_ts):
    if not start_ts:
        return "-"
    try:
        delta = int(time.time() - float(start_ts))
    except:
        return "-"
    if delta < 0:
        delta = 0
    d = delta // 86400
    h = (delta % 86400) // 3600
    m = (delta % 3600) // 60
    s = delta % 60
    if d > 0:
        return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"

def status():
    cleanup_if_stale()
    pid = read_pid()
    st = read_state()

    if pid and pid_alive(pid):
        return {
            "running": True,
            "pid": pid,
            "started_at": st.get("started_at"),
            "cmd": st.get("cmd"),
            "log": LOG_PATH
        }

    if configured_port_in_use():
        return {
            "running": True,
            "pid": pid,
            "started_at": st.get("started_at"),
            "cmd": st.get("cmd"),
            "log": LOG_PATH
        }

    if pid:
        remove_pid()
    remove_state()
    return {
        "running": False,
        "pid": None,
        "started_at": None,
        "cmd": st.get("cmd"),
        "log": LOG_PATH
    }

def ensure_log_file():
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("")
    except:
        pass

def parse_app_bind():
    cfg = read_settings()
    host = cfg["host"]
    port = cfg["port"]
    return host, port

def detect_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

def server_urls():
    host, port = parse_app_bind()
    if host in ("0.0.0.0", "::"):
        lan = detect_lan_ip()
        urls = [f"http://127.0.0.1:{port}"]
        if lan:
            urls.append(f"http://{lan}:{port}")
        return urls
    if host in ("127.0.0.1", "localhost"):
        return [f"http://{host}:{port}"]
    return [f"http://{host}:{port}"]

def start_server():
    s = status()
    if s["running"]:
        return True, f"Already running (PID {s['pid']})."

    ensure_log_file()
    ensure_settings_file()

    cfg = read_settings()
    host = cfg["host"]
    port = cfg["port"]
    secret_key = cfg["secret_key"]

    if not valid_port(port):
        return False, f"Invalid port: {port}"

    if port_in_use("127.0.0.1", port):
        return False, f"Port {port} is already in use."

    try:
        logf = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    except Exception as e:
        return False, f"Could not open log file: {e}"

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    env["OTP_HOST"] = str(host)
    env["OTP_PORT"] = str(port)
    env["OTP_SECRET_KEY"] = str(secret_key)

    try:
        p = subprocess.Popen(
            APP_CMD,
            cwd=BASE_DIR,
            stdout=logf,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True
        )
    except Exception as e:
        try:
            logf.close()
        except:
            pass
        return False, f"Failed to start: {e}"

    write_pid(p.pid)
    write_state({
        "started_at": time.time(),
        "cmd": APP_CMD,
        "log": LOG_PATH,
        "host": host,
        "port": port
    })
    return True, f"Started (PID {p.pid}) on port {port}."

def stop_server(grace_seconds=6):
    pid = read_pid()

    if not pid and not configured_port_in_use():
        remove_state()
        return True, "Already stopped."

    if pid and not pid_alive(pid) and not configured_port_in_use():
        remove_pid()
        remove_state()
        return True, "Already stopped."

    def kill_term(target_pid):
        try:
            if os.name != "nt":
                os.killpg(int(target_pid), signal.SIGTERM)
            else:
                os.kill(int(target_pid), signal.SIGTERM)
            return True, None
        except ProcessLookupError:
            return True, None
        except PermissionError:
            return False, "Permission denied while sending SIGTERM."
        except Exception as e:
            return False, str(e)

    def kill_kill(target_pid):
        try:
            if os.name != "nt":
                os.killpg(int(target_pid), signal.SIGKILL)
            else:
                os.kill(int(target_pid), signal.SIGKILL)
            return True, None
        except ProcessLookupError:
            return True, None
        except PermissionError:
            return False, "Permission denied while sending SIGKILL."
        except Exception as e:
            return False, str(e)

    if pid and pid_alive(pid):
        ok, err = kill_term(pid)
        if not ok:
            if not configured_port_in_use():
                remove_pid()
                remove_state()
                return True, "Stopped."
            return False, f"Could not send SIGTERM: {err}"

    t0 = time.time()
    while time.time() - t0 < grace_seconds:
        if not configured_port_in_use() and (not pid or not pid_alive(pid)):
            remove_pid()
            remove_state()
            return True, "Stopped."
        time.sleep(0.2)

    if pid and pid_alive(pid):
        ok, err = kill_kill(pid)
        if not ok:
            if not configured_port_in_use():
                remove_pid()
                remove_state()
                return True, "Stopped."
            return False, f"Could not force stop (SIGKILL): {err}"

    t1 = time.time()
    while time.time() - t1 < 3:
        if not configured_port_in_use() and (not pid or not pid_alive(pid)):
            remove_pid()
            remove_state()
            return True, "Stopped (forced)."
        time.sleep(0.2)

    if not configured_port_in_use():
        remove_pid()
        remove_state()
        return True, "Stopped."

    return False, "Stop failed: process still alive."

def read_local_version():
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as f:
            return f.read().strip() or "0.0.0"
    except:
        return "0.0.0"

def normalize_version(v):
    v = str(v or "").strip()
    if v.startswith("v") or v.startswith("V"):
        v = v[1:]
    return v

def version_tuple(v):
    v = normalize_version(v)
    parts = re.findall(r"\d+", v)
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts)

def fetch_text(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "OTP-Tool-Updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        charset = r.headers.get_content_charset() or "utf-8"
        return r.read().decode(charset, errors="replace")

def download_file(url, dest_path, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "OTP-Tool-Updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest_path, "wb") as f:
        shutil.copyfileobj(r, f)

def get_remote_version():
    txt = fetch_text(REMOTE_VERSION_URL, timeout=10).strip()
    if not txt:
        raise RuntimeError("Remote VERSION file is empty.")
    return txt

def check_for_update():
    local_v = read_local_version()
    remote_v = get_remote_version()
    is_newer = version_tuple(remote_v) > version_tuple(local_v)
    return {
        "local": local_v,
        "remote": remote_v,
        "update_available": is_newer
    }

def is_protected_rel_path(rel_path):
    rel_path = rel_path.replace("\\", "/").strip("/")
    if not rel_path:
        return True
    parts = [p for p in rel_path.split("/") if p not in ("", ".")]
    if not parts:
        return True
    if parts[0] in PROTECTED_NAMES:
        return True
    if any(p in PROTECTED_NAMES for p in parts):
        return True
    if len(parts) == 1 and parts[0] in PROTECTED_FILES:
        return True
    return False

def safe_rel_path(path, root):
    rel = os.path.relpath(path, root)
    rel = rel.replace("\\", "/")
    if rel.startswith("../") or rel == "..":
        raise RuntimeError("Unsafe path detected.")
    return rel

def collect_update_files(source_root):
    items = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in PROTECTED_NAMES and not d.startswith(".git")]
        for name in files:
            src = os.path.join(root, name)
            if os.path.islink(src):
                continue
            rel = safe_rel_path(src, source_root)
            if is_protected_rel_path(rel):
                continue
            items.append((src, rel))
    return items

def extract_repo_root(zip_path, temp_dir):
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(temp_dir)
    dirs = [os.path.join(temp_dir, x) for x in os.listdir(temp_dir)]
    dirs = [d for d in dirs if os.path.isdir(d)]
    if len(dirs) != 1:
        raise RuntimeError("Could not detect extracted repository root.")
    return dirs[0]

def backup_existing_files(file_list, backup_root):
    backed_up = []
    for _, rel in file_list:
        dst = os.path.join(BASE_DIR, rel)
        if os.path.exists(dst):
            backup_dst = os.path.join(backup_root, rel)
            os.makedirs(os.path.dirname(backup_dst), exist_ok=True)
            shutil.copy2(dst, backup_dst)
            backed_up.append(rel)
    return backed_up

def restore_backup(backup_root, backed_up):
    for rel in backed_up:
        src = os.path.join(backup_root, rel)
        dst = os.path.join(BASE_DIR, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

def apply_update_files(file_list):
    for src, rel in file_list:
        dst = os.path.join(BASE_DIR, rel)
        parent = os.path.dirname(dst)
        if parent:
            os.makedirs(parent, exist_ok=True)
        shutil.copy2(src, dst)

def update_from_github():
    if status()["running"]:
        return False, "Stop the server before updating."
    info = check_for_update()
    if not info["update_available"]:
        return True, f"Already up to date ({info['local']})."

    with tempfile.TemporaryDirectory(prefix="otp_update_") as temp_dir:
        zip_path = os.path.join(temp_dir, "update.zip")
        backup_root = os.path.join(temp_dir, "backup")

        download_file(REMOTE_ZIP_URL, zip_path, timeout=60)
        repo_root = extract_repo_root(zip_path, temp_dir)
        file_list = collect_update_files(repo_root)

        if not file_list:
            return False, "No update files found in downloaded archive."

        backed_up = []
        try:
            backed_up = backup_existing_files(file_list, backup_root)
            apply_update_files(file_list)
        except Exception as e:
            try:
                restore_backup(backup_root, backed_up)
            except:
                pass
            return False, f"Update failed and rollback was attempted: {e}"

        new_local = read_local_version()
        if version_tuple(new_local) < version_tuple(info["remote"]):
            try:
                restore_backup(backup_root, backed_up)
            except:
                pass
            return False, "Update aborted because local VERSION did not update correctly."

        return True, f"Updated from {info['local']} to {info['remote']}."

ASCII_TITLE = r"""
  ░██████   ░██████████░█████████     ░██████████                      ░██ 
 ░██   ░██      ░██    ░██     ░██        ░██                          ░██ 
░██     ░██     ░██    ░██     ░██        ░██     ░███████   ░███████  ░██ 
░██     ░██     ░██    ░█████████         ░██    ░██    ░██ ░██    ░██ ░██ 
░██     ░██     ░██    ░██                ░██    ░██    ░██ ░██    ░██ ░██ 
 ░██   ░██      ░██    ░██                ░██    ░██    ░██ ░██    ░██ ░██ 
  ░██████       ░██    ░██                ░██     ░███████   ░███████  ░██ 
""".strip("\n")

TITLE_WIDTH = max((len(r) for r in ASCII_TITLE.splitlines()), default=0)
LINE_WIDTH = max(72, TITLE_WIDTH + 10)

def draw_header():
    ensure_settings_file()
    s = status()
    st = read_state()
    cfg = read_settings()
    started_at = st.get("started_at") if s["running"] else None
    up = fmt_uptime(started_at)
    line = "─" * LINE_WIDTH

    stat = green("RUNNING") if s["running"] else red("STOPPED")
    pid_txt = f"{s['pid']}" if s["running"] else "-"
    log_txt = LOG_PATH
    version_txt = read_local_version()

    print(lavender(line))
    for row in ASCII_TITLE.splitlines():
        print(lavender(row.center(LINE_WIDTH)))
    print(lavender(line))
    print(f"{bold('Status')}   : {stat}    {bold('PID')}: {pid_txt}    {bold('Uptime')}: {up}")
    print(f"{bold('Version')}  : {gray(version_txt)}")
    print(f"{bold('Port')}     : {gray(str(cfg['port']))}    {bold('Secret')}: {gray(mask_secret(cfg['secret_key']))}")
    print(f"{bold('Log')}      : {gray(log_txt)}")
    print(lavender(line))

def toast(msg, ok=True):
    tag = green("✓") if ok else red("✗")
    print("")
    print(f"{tag} {msg}")
    print(dim("Press Enter to continue..."), end="")
    input()

def read_last_lines(path, n=60):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") <= n + 5:
                take = min(block, size)
                size -= take
                f.seek(size)
                data = f.read(take) + data
        text = data.decode("utf-8", errors="replace")
        return text.splitlines()[-n:]
    except:
        return []

def select_readable(timeout):
    try:
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        return r
    except:
        time.sleep(timeout)
        return []

def print_urls_line():
    urls = server_urls()
    if not urls:
        return
    print(lavender("─" * LINE_WIDTH))
    print(bold("URL") + "      : " + gray("  ".join(urls)))

def follow_log(path):
    ensure_log_file()
    mode = "tail"

    def show_tail():
        clear()
        print(bold("Peek terminal output"))
        print(dim("q = back, f = follow (live)"))
        print(lavender("─" * LINE_WIDTH))
        for ln in read_last_lines(path, 60):
            print(ln)
        print_urls_line()
        return input(dim("Command: ")).strip().lower()

    def show_follow():
        clear()
        print(bold("Peek terminal output"))
        print(dim("Following... type q + Enter to stop"))
        print(lavender("─" * LINE_WIDTH))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        print(line.rstrip("\n"))
                        continue
                    if sys.stdin in select_readable(0.25):
                        cmd = sys.stdin.readline().strip().lower()
                        if cmd == "q":
                            return "q"
        except Exception as e:
            print(red(str(e)))
            print(dim("Press Enter..."), end="")
            input()
            return "q"

    while True:
        if mode == "tail":
            cmd = show_tail()
            if cmd == "q":
                return
            if cmd == "f":
                mode = "follow"
                continue
        else:
            cmd = show_follow()
            mode = "tail"
            if cmd == "q":
                continue

def settings_menu():
    ensure_settings_file()

    while True:
        clear()
        cfg = read_settings()
        print(bold("Settings"))
        print(lavender("─" * LINE_WIDTH))
        print(f"{bold('1)')} Set port              {gray(str(cfg['port']))}")
        print(f"{bold('2)')} Set secret            {gray(mask_secret(cfg['secret_key']))}")
        print(f"{bold('3)')} Reset to defaults")
        print(f"{bold('0)')} Back")
        print("")
        choice = input(bold("Select: ")).strip()

        if choice == "1":
            value = input("New port: ").strip()
            if not valid_port(value):
                toast("Invalid port. Use 1 to 65535.", False)
                continue
            value = int(value)
            if status()["running"] and read_settings().get("port") != value:
                toast("Stop the server before changing the port.", False)
                continue
            cfg["port"] = value
            write_settings(cfg)
            toast(f"Port saved: {value}", True)
            continue

        if choice == "2":
            value = input("New secret: ").strip()
            if len(value) < 8:
                toast("Secret should be at least 8 characters long.", False)
                continue
            cfg["secret_key"] = value
            write_settings(cfg)
            toast("Secret saved.", True)
            continue

        if choice == "3":
            if status()["running"]:
                toast("Stop the server before resetting settings.", False)
                continue
            write_settings(get_default_settings())
            toast("Settings reset.", True)
            continue

        if choice == "0":
            return

        toast("Invalid selection.", False)

def menu_action(choice):
    if choice == "1":
        ok, msg = start_server()
        toast(msg, ok)
        return
    if choice == "2":
        ok, msg = stop_server()
        toast(msg, ok)
        return
    if choice == "3":
        follow_log(LOG_PATH)
        return
    if choice == "4":
        try:
            info = check_for_update()
            if info["update_available"]:
                toast(f"Update available: {info['local']} -> {info['remote']}", True)
            else:
                toast(f"Already up to date: {info['local']}", True)
        except Exception as e:
            toast(f"Version check failed: {e}", False)
        return
    if choice == "5":
        if status()["running"]:
            toast("Stop the server before updating.", False)
            return
        ans = input(yellow("Type update to continue: ")).strip().lower()
        if ans != "update":
            toast("Update cancelled.", False)
            return
        try:
            ok, msg = update_from_github()
            toast(msg, ok)
        except Exception as e:
            toast(f"Update failed: {e}", False)
        return
    if choice == "6":
        settings_menu()
        return
    if choice == "0":
        clear()
        raise SystemExit
    toast("Invalid selection.", False)

def show_menu_once():
    clear()
    draw_header()
    print(f"{bold('1)')} Start server")
    print(f"{bold('2)')} Stop server")
    print(f"{bold('3)')} Peek terminal output")
    print(f"{bold('4)')} Check for updates")
    print(f"{bold('5)')} Update from GitHub")
    print(f"{bold('6)')} Settings")
    print(f"{bold('0)')} Exit")
    print("")
    return input(bold("Select: ")).strip()

def main():
    ensure_settings_file()
    while True:
        clear()
        draw_header()
        print(dim("Auto refresh every 5s. Press Enter to open menu."))
        r = select_readable(5.0)
        if r:
            _ = sys.stdin.readline()
            choice = show_menu_once()
            try:
                menu_action(choice)
            except SystemExit:
                return

if __name__ == "__main__":
    main()