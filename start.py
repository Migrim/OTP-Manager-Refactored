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
    os.path.basename(LOG_PATH)
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
    if pid and not pid_alive(pid):
        remove_pid()
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
    host = "127.0.0.1"
    port = 7440
    try:
        with open(APP_PY_PATH, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()

        m_port = re.search(r"app\.run\([\s\S]*?\bport\s*=\s*([0-9]{2,6})", src)
        if m_port:
            port = int(m_port.group(1))

        m_host = re.search(r"app\.run\([\s\S]*?\bhost\s*=\s*(['\"])(.*?)\1", src)
        if m_host:
            host = m_host.group(2).strip()
    except:
        pass
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

    try:
        logf = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    except Exception as e:
        return False, f"Could not open log file: {e}"

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

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
        "log": LOG_PATH
    })
    return True, f"Started (PID {p.pid})."

def stop_server(grace_seconds=6):
    pid = read_pid()
    if not pid:
        remove_state()
        return True, "Already stopped."

    if not pid_alive(pid):
        remove_pid()
        remove_state()
        return True, "Already stopped."

    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        return False, f"Could not send SIGTERM: {e}"

    t0 = time.time()
    while time.time() - t0 < grace_seconds:
        if not pid_alive(pid):
            remove_pid()
            remove_state()
            return True, "Stopped."
        time.sleep(0.2)

    try:
        os.kill(pid, signal.SIGKILL)
    except Exception as e:
        return False, f"Could not force stop (SIGKILL): {e}"

    time.sleep(0.2)
    if not pid_alive(pid):
        remove_pid()
        remove_state()
        return True, "Stopped (forced)."

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
    info = check_for_update()
    if not info["update_available"]:
        return True, f"Already up to date ({info['local']})."

    was_running = status()["running"]

    with tempfile.TemporaryDirectory(prefix="otp_update_") as temp_dir:
        zip_path = os.path.join(temp_dir, "update.zip")
        backup_root = os.path.join(temp_dir, "backup")

        download_file(REMOTE_ZIP_URL, zip_path, timeout=60)
        repo_root = extract_repo_root(zip_path, temp_dir)
        file_list = collect_update_files(repo_root)

        if not file_list:
            return False, "No update files found in downloaded archive."

        if was_running:
            ok, msg = stop_server()
            if not ok:
                return False, f"Update aborted. Could not stop server: {msg}"

        backed_up = []
        try:
            backed_up = backup_existing_files(file_list, backup_root)
            apply_update_files(file_list)
        except Exception as e:
            try:
                restore_backup(backup_root, backed_up)
            except:
                pass
            if was_running:
                start_server()
            return False, f"Update failed and rollback was attempted: {e}"

        new_local = read_local_version()
        if version_tuple(new_local) < version_tuple(info["remote"]):
            try:
                restore_backup(backup_root, backed_up)
            except:
                pass
            if was_running:
                start_server()
            return False, "Update aborted because local VERSION did not update correctly."

        restart_msg = ""
        if was_running:
            ok, msg = start_server()
            restart_msg = f" Server restart: {msg}"

        return True, f"Updated from {info['local']} to {info['remote']}.{restart_msg}"

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
    s = status()
    st = read_state()
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
                    else:
                        pass
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
    print(f"{bold('0)')} Exit")
    print("")
    return input(bold("Select: ")).strip()

def main():
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