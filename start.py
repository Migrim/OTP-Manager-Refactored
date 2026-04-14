import os
import sys
import time
import json
import signal
import shutil
import zipfile
import tempfile
import subprocess
import threading
from datetime import datetime
import re
import socket
import urllib.request
try:
    import termios
    import tty
except Exception:
    termios = None
    tty = None
try:
    import msvcrt
except Exception:
    msvcrt = None

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
BOOT_UPDATE_LOCK = threading.Lock()
BOOT_UPDATE_STATUS = {
    "state": "idle",
    "info": None,
    "error": None,
    "last_check_ts": 0.0
}
UPDATE_CHECK_INTERVAL = 300  # re-check every 5 minutes
SYSTEM_METRICS_LOCK = threading.Lock()
SYSTEM_METRICS_CACHE = {"ts": 0.0, "data": None}
CPU_SNAPSHOT = None

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
def color8(s, n): return c(s, f"38;5;{int(n)}")

def clamp(v, lo=0.0, hi=100.0):
    try:
        x = float(v)
    except:
        return lo
    return max(lo, min(hi, x))

def metric_color_code(pct):
    p = clamp(pct)
    if p < 55:
        return 77   
    if p < 75:
        return 149  
    if p < 88:
        return 214  
    return 196      

def progress_bar(pct, width=16):
    p = clamp(pct)
    filled = int(round((p / 100.0) * width))
    filled = max(0, min(width, filled))
    bar = ("█" * filled) + ("░" * (width - filled))
    if filled <= 0:
        return gray(bar)
    return color8(bar, metric_color_code(p))

def fmt_size_gib(num_bytes):
    try:
        return f"{(float(num_bytes) / (1024.0 ** 3)):.1f}G"
    except:
        return "n/a"

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
    if not valid_port(port):
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
        targets = ["127.0.0.1", "::1"]
    else:
        targets = [host]

    for target in targets:
        try:
            family = socket.AF_INET6 if ":" in target else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
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

    months = delta // (30 * 86400)
    delta %= 30 * 86400
    days = delta // 86400
    delta %= 86400
    hours = delta // 3600
    delta %= 3600
    minutes = delta // 60
    seconds = delta % 60

    parts = []
    if months > 0:
        parts.append(f"{months}mo")
    if days > 0 or months > 0:
        parts.append(f"{days}d")
    parts.append(f"{hours:02d}h")
    parts.append(f"{minutes:02d}m")
    parts.append(f"{seconds:02d}s")
    return " ".join(parts)

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
        if not os.path.exists(LOG_PATH):
            with open(LOG_PATH, "a", encoding="utf-8") as f:
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

    deadline = time.time() + 1.2
    while time.time() < deadline:
        rc = p.poll()
        if rc is not None:
            try:
                logf.close()
            except:
                pass
            tail = "\n".join(read_last_lines(LOG_PATH, n=12))
            msg = f"Process exited during startup (code {rc})."
            if tail:
                msg += f"\nLast log lines:\n{tail}"
            return False, msg
        time.sleep(0.1)

    try:
        logf.close()
    except:
        pass

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

def read_cpu_percent():
    global CPU_SNAPSHOT
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/stat", "r", encoding="utf-8") as f:
                line = f.readline().strip()
            parts = line.split()
            if len(parts) < 5 or parts[0] != "cpu":
                return None
            vals = [int(x) for x in parts[1:8]]
            idle = vals[3] + vals[4]
            total = sum(vals)
            prev = CPU_SNAPSHOT
            CPU_SNAPSHOT = (total, idle)
            if not prev:
                return None
            dt = total - prev[0]
            di = idle - prev[1]
            if dt <= 0:
                return None
            return clamp((1.0 - (di / float(dt))) * 100.0)
        except:
            return None
    try:
        load1 = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        return clamp((load1 / float(cores)) * 100.0)
    except:
        return None

def read_ram_percent_and_detail():
    if sys.platform.startswith("linux"):
        try:
            mem = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for ln in f:
                    if ":" not in ln:
                        continue
                    k, v = ln.split(":", 1)
                    mem[k.strip()] = int(v.strip().split()[0]) * 1024
            total = mem.get("MemTotal")
            avail = mem.get("MemAvailable")
            if total and avail is not None and total > 0:
                used = total - avail
                pct = clamp((used / float(total)) * 100.0)
                return pct, f"{fmt_size_gib(used)}/{fmt_size_gib(total)}"
        except:
            pass
    if sys.platform == "darwin":
        try:
            total = int(subprocess.check_output(
                ["sysctl", "-n", "hw.memsize"],
                text=True
            ).strip())
            vm = subprocess.check_output(["vm_stat"], text=True)
            m = re.search(r"page size of (\d+) bytes", vm)
            page_size = int(m.group(1)) if m else 4096
            pages = {}
            for ln in vm.splitlines():
                if ":" not in ln:
                    continue
                k, v = ln.split(":", 1)
                token = v.strip().split()[0].strip(".")
                try:
                    pages[k.strip()] = int(token)
                except:
                    continue
            avail_pages = (
                pages.get("Pages free", 0)
                + pages.get("Pages inactive", 0)
                + pages.get("Pages speculative", 0)
            )
            avail = avail_pages * page_size
            used = max(0, total - avail)
            if total > 0:
                pct = clamp((used / float(total)) * 100.0)
                return pct, f"{fmt_size_gib(used)}/{fmt_size_gib(total)}"
        except:
            pass
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        total_pages = os.sysconf("SC_PHYS_PAGES")
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        total = int(page) * int(total_pages)
        avail = int(page) * int(avail_pages)
        if total > 0:
            used = total - avail
            pct = clamp((used / float(total)) * 100.0)
            return pct, f"{fmt_size_gib(used)}/{fmt_size_gib(total)}"
    except:
        pass
    return None, None

def read_storage_percent_and_detail():
    try:
        du = shutil.disk_usage(BASE_DIR)
        used = du.total - du.free
        pct = clamp((used / float(du.total)) * 100.0) if du.total > 0 else None
        return pct, f"{fmt_size_gib(used)}/{fmt_size_gib(du.total)}"
    except:
        return None, None

def get_system_metrics():
    now = time.time()
    with SYSTEM_METRICS_LOCK:
        ts = SYSTEM_METRICS_CACHE.get("ts", 0.0)
        data = SYSTEM_METRICS_CACHE.get("data")
        if data and (now - ts) < 1.0:
            return data

    cpu_pct = read_cpu_percent()
    ram_pct, ram_detail = read_ram_percent_and_detail()
    disk_pct, disk_detail = read_storage_percent_and_detail()
    out = {
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pct,
        "ram_detail": ram_detail,
        "disk_pct": disk_pct,
        "disk_detail": disk_detail
    }
    with SYSTEM_METRICS_LOCK:
        SYSTEM_METRICS_CACHE["ts"] = now
        SYSTEM_METRICS_CACHE["data"] = out
    return out

def maybe_trigger_update_check():
    with BOOT_UPDATE_LOCK:
        if BOOT_UPDATE_STATUS.get("state") == "checking":
            return
        if time.time() - BOOT_UPDATE_STATUS.get("last_check_ts", 0.0) < UPDATE_CHECK_INTERVAL:
            return
        BOOT_UPDATE_STATUS["state"] = "checking"
        BOOT_UPDATE_STATUS["info"] = None
        BOOT_UPDATE_STATUS["error"] = None

    def worker():
        try:
            info = check_for_update()
            with BOOT_UPDATE_LOCK:
                BOOT_UPDATE_STATUS["state"] = "done"
                BOOT_UPDATE_STATUS["info"] = info
                BOOT_UPDATE_STATUS["error"] = None
                BOOT_UPDATE_STATUS["last_check_ts"] = time.time()
        except Exception as e:
            with BOOT_UPDATE_LOCK:
                BOOT_UPDATE_STATUS["state"] = "error"
                BOOT_UPDATE_STATUS["info"] = None
                BOOT_UPDATE_STATUS["error"] = str(e)
                BOOT_UPDATE_STATUS["last_check_ts"] = time.time()

    threading.Thread(target=worker, daemon=True).start()

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
░░░░░░░░      ░░░        ░░       ░░░░░░░░░        ░░░      ░░░░      ░░░  ░░░░░░░░░░░░░
▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒▒▒
▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓▓       ▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓
███████  ████  █████  █████  █████████████████  █████  ████  ██  ████  ██  █████████████
████████      ██████  █████  █████████████████  ██████      ████      ███        ███████
""".strip("\n")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
MIN_LINE_WIDTH = 92

def strip_ansi(s):
    return ANSI_RE.sub("", str(s or ""))

def visible_len(s):
    return len(strip_ansi(s))

def pad_visible(s, width):
    text = str(s or "")
    return text + (" " * max(0, width - visible_len(text)))

def center_visible(s, width):
    text = str(s or "")
    v = visible_len(text)
    if v >= width:
        return text
    left = (width - v) // 2
    right = width - v - left
    return (" " * left) + text + (" " * right)

def shorten_middle(text, max_len):
    s = str(text or "")
    if max_len <= 0:
        return ""
    if len(s) <= max_len:
        return s
    if max_len <= 3:
        return "." * max_len
    keep = max_len - 3
    left = keep // 2
    right = keep - left
    return s[:left] + "..." + s[-right:]

def get_terminal_size():
    try:
        ts = shutil.get_terminal_size((100, 30))
        return max(60, ts.columns), max(18, ts.lines)
    except:
        return 100, 30

def print_centered(line, total_width):
    left = max(0, (total_width - visible_len(line)) // 2)
    print((" " * left) + line)

def render_box(title, lines, hint=None):
    tw, th = get_terminal_size()
    body = list(lines or [])
    widths = [visible_len(x) for x in body]
    if title:
        widths.append(visible_len(title) + 4)
    if hint:
        widths.append(visible_len(hint))
    inner_w = min(max(widths + [54]), max(40, tw - 8))

    top = lavender("┌" + ("─" * (inner_w + 2)) + "┐")
    bottom = lavender("└" + ("─" * (inner_w + 2)) + "┘")
    boxed = [top]

    if title:
        title_text = f" {title} "
        t_line = f"│ {pad_visible(title_text, inner_w)} │"
        boxed.append(lavender(t_line))
        boxed.append(lavender("├" + ("─" * (inner_w + 2)) + "┤"))

    for line in body:
        boxed.append(lavender("│ ") + pad_visible(line, inner_w) + lavender(" │"))

    if hint:
        boxed.append(lavender("├" + ("─" * (inner_w + 2)) + "┤"))
        boxed.append(lavender("│ ") + pad_visible(dim(hint), inner_w) + lavender(" │"))

    boxed.append(bottom)

    clear()
    pad_top = max(0, (th - len(boxed)) // 2)
    for _ in range(pad_top):
        print("")
    for row in boxed:
        print_centered(row, tw)

def print_centered_box(lines, title=None, hint=None, width=None):
    tw, _ = get_terminal_size()
    body = list(lines or [])
    widths = [visible_len(x) for x in body]
    if title:
        widths.append(visible_len(title) + 4)
    if hint:
        widths.append(visible_len(hint))
    inner_w = width if width else min(max(widths + [52]), max(40, tw - 12))

    top = lavender("┌" + ("─" * (inner_w + 2)) + "┐")
    bottom = lavender("└" + ("─" * (inner_w + 2)) + "┘")
    print_centered(top, tw)
    if title:
        t_line = f"│ {pad_visible(f' {title} ', inner_w)} │"
        print_centered(lavender(t_line), tw)
        print_centered(lavender("├" + ("─" * (inner_w + 2)) + "┤"), tw)
    for line in body:
        row = lavender("│ ") + pad_visible(line, inner_w) + lavender(" │")
        print_centered(row, tw)
    if hint:
        print_centered(lavender("├" + ("─" * (inner_w + 2)) + "┤"), tw)
        if isinstance(hint, tuple):
            left_h, right_h = hint
            gap = max(1, inner_w - visible_len(left_h) - visible_len(right_h))
            hint_row = dim(left_h) + (" " * gap) + dim(right_h)
        else:
            hint_row = pad_visible(dim(hint), inner_w)
        row = lavender("│ ") + hint_row + lavender(" │")
        print_centered(row, tw)
    print_centered(bottom, tw)

def build_dashboard_lines():
    ensure_settings_file()
    s = status()
    st = read_state()
    cfg = read_settings()
    started_at = st.get("started_at") if s["running"] else None
    up = fmt_uptime(started_at)
    stat = green("RUNNING") if s["running"] else red("STOPPED")
    pid_txt = f"{s['pid']}" if s["running"] else "-"
    version_txt = read_local_version()

    lines = [
        f"{bold('Status')} : {stat}",
        f"{bold('PID')}    : {pid_txt}",
        f"{bold('Uptime')} : {up}",
        f"{bold('Version')}: {gray(version_txt)}",
        f"{bold('Port')}   : {gray(str(cfg['port']))}",
        f"{bold('Secret')} : {gray(mask_secret(cfg['secret_key']))}",
        f"{bold('Log')}    : {gray(LOG_PATH)}",
    ]
    urls = server_urls()
    if urls:
        lines.append("")
        lines.append(f"{bold('URL')}    : {gray('  '.join(urls))}")
    return lines

def get_db_status():
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("database", os.path.join(BASE_DIR, "database.py"))
        _db = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_db)
        missing = _db.get_missing_columns()
        if missing:
            return False, f"Schema outdated — missing: {', '.join(missing)}"
        return True, "Schema up to date"
    except Exception as e:
        return None, f"Check failed: {shorten_middle(str(e), 40)}"

def get_db_integrity():
    db_path = os.path.join(BASE_DIR, "instance", "otp.db")
    if not os.path.exists(db_path):
        return None, "Database file not found"
    try:
        import sqlite3 as _sql
        with _sql.connect(db_path, timeout=3) as con:
            con.execute("PRAGMA journal_mode=WAL")
            integrity = con.execute("PRAGMA integrity_check").fetchone()
            fk_issues = con.execute("PRAGMA foreign_key_check").fetchall()
        if integrity and integrity[0].lower() != "ok":
            return False, f"integrity_check: {integrity[0]}"
        if fk_issues:
            return False, f"{len(fk_issues)} foreign key violation(s)"
        return True, "Passed"
    except Exception as e:
        return None, f"Check failed: {shorten_middle(str(e), 40)}"

def draw_header():
    ensure_settings_file()
    s = status()
    st = read_state()
    cfg = read_settings()
    started_at = st.get("started_at") if s["running"] else None
    up = fmt_uptime(started_at)
    _, term_h = get_terminal_size()
    w = term_width()

    stat        = green("RUNNING") if s["running"] else red("STOPPED")
    pid_txt     = str(s["pid"]) if s["running"] else "-"
    version_txt = read_local_version()
    box_w       = 86

    sep = gray("─" * box_w)

    # ── update status ─────────────────────────────────────────────────
    with BOOT_UPDATE_LOCK:
        upd_state = BOOT_UPDATE_STATUS.get("state")
        upd_info  = BOOT_UPDATE_STATUS.get("info")
        upd_error = BOOT_UPDATE_STATUS.get("error")

    if upd_state == "checking":
        spin    = ["|", "/", "-", "\\"][int(time.time() * 6) % 4]
        upd_val = yellow(f"{spin} Checking...")
    elif upd_state == "done" and isinstance(upd_info, dict):
        if upd_info.get("update_available"):
            upd_val = yellow(f"● {upd_info.get('local')} → {upd_info.get('remote')}  (update available)")
        else:
            upd_val = green("✓") + f"  Up to date  {gray(upd_info.get('local', ''))}"
    elif upd_state == "error":
        upd_val = red("✗") + f"  {gray(shorten_middle(upd_error or 'Unknown error', 40))}"
    else:
        upd_val = gray("—")

    # ── db schema & integrity ─────────────────────────────────────────
    db_ok, db_msg = get_db_status()
    if db_ok is True:
        db_val = green("✓") + f"  {db_msg}"
    elif db_ok is False:
        db_val = red("✗") + f"  {db_msg}"
    else:
        db_val = yellow("?") + f"  {db_msg}"

    int_ok, int_msg = get_db_integrity()
    if int_ok is True:
        int_val = green("✓") + f"  {int_msg}"
    elif int_ok is False:
        int_val = red("✗") + f"  {int_msg}"
    else:
        int_val = yellow("?") + f"  {int_msg}"

    # ── system metrics ────────────────────────────────────────────────
    sysm        = get_system_metrics()
    cpu_pct     = sysm.get("cpu_pct")
    ram_pct     = sysm.get("ram_pct")
    ram_detail  = sysm.get("ram_detail")
    disk_pct    = sysm.get("disk_pct")
    disk_detail = sysm.get("disk_detail")

    def bar_line(label, pct, detail=None):
        name = f"{label:>4}"
        bar_w = 16
        if pct is None:
            empty = gray("░" * bar_w)
            return f"{bold(name)} : {empty}  n/a  {gray(detail) if detail else ''}".rstrip()
        p    = int(round(clamp(pct)))
        base = f"{bold(name)} : {progress_bar(p, width=bar_w)}  {p:>3d}%"
        if detail:
            base += f"  {gray(detail)}"
        return base

    urls    = server_urls()

    status_row = (
        f"{bold('Status')}: {stat}   "
        f"{bold('PID')}: {pid_txt}   "
        f"{bold('Uptime')}: {up}   "
        f"{bold('Version')}: {gray(version_txt)}"
    )

    info_lines = [
        center_visible(status_row, box_w),
        sep,
        f"{bold('Port')}    : {gray(str(cfg['port']))}",
        f"{bold('Secret')}  : {gray(mask_secret(cfg['secret_key']))}",
    ]
    if urls:
        info_lines.append(f"{bold('URL')}     : {gray('  '.join(urls))}")
    info_lines += [
        sep,
        bar_line("CPU",  cpu_pct),
        bar_line("RAM",  ram_pct,  ram_detail),
        bar_line("Disk", disk_pct, disk_detail),
        sep,
        f"{bold('DB')}        : {db_val}",
        f"{bold('Integrity')} : {int_val}",
        f"{bold('Update ')}   : {upd_val}",
    ]

    clear()
    ascii_h = len(ASCII_TITLE.splitlines())
    box_h   = len(info_lines) + 4
    total_h = ascii_h + 1 + box_h
    top_pad = max(0, (term_h - total_h) // 2)
    for _ in range(top_pad):
        print("")
    for row in ASCII_TITLE.splitlines():
        pad = max(0, (w - len(row)) // 2)
        print(" " * pad + lavender(row))
    print("")
    print_centered_box(
        info_lines,
        hint=("↵ Enter  Open menu", "X  Exit"),
        width=box_w
    )

def toast(msg, ok=True):
    tag = green("✓") if ok else red("✗")
    print("")
    print(f"{tag} {msg}")
    print(dim("Press any key to continue..."), end="", flush=True)
    wait_for_any_key()
    print("")

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

def read_menu_key():
    if os.name == "nt" and msvcrt:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            return "enter"
        if ch in ("\x00", "\xe0"):
            k = msvcrt.getwch()
            if k == "H":
                return "up"
            if k == "P":
                return "down"
            return None
        if ch == "\x1b":
            return "esc"
        return ch.lower()

    if termios and tty and sys.stdin.isatty():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            import select
            tty.setraw(fd)
            first = os.read(fd, 1)
            if not first:
                return None
            ch = first.decode("utf-8", errors="ignore")
            if ch in ("\r", "\n"):
                return "enter"
            if ch == "\x1b":
                seq = b""
                t_end = time.time() + 0.22
                while time.time() < t_end:
                    r, _, _ = select.select([fd], [], [], 0.03)
                    if not r:
                        continue
                    chunk = os.read(fd, 8)
                    if not chunk:
                        break
                    seq += chunk
                    if b"A" in seq or b"B" in seq:
                        break
                if seq.startswith(b"[") and len(seq) >= 2:
                    code = chr(seq[1])
                    if code == "A":
                        return "up"
                    if code == "B":
                        return "down"
                if seq.startswith(b"O") and len(seq) >= 2:
                    code = chr(seq[1])
                    if code == "A":
                        return "up"
                    if code == "B":
                        return "down"
                return "esc"
            return ch.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    txt = input().strip().lower()
    return txt[:1] if txt else "enter"

def wait_for_any_key():
    if os.name == "nt" and msvcrt:
        _ = msvcrt.getwch()
        return
    if termios and tty and sys.stdin.isatty():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            _ = os.read(fd, 1)
            return
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    input()

def read_line_allow_escape(prompt):
    print(prompt, end="", flush=True)

    if os.name == "nt" and msvcrt:
        buf = []
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                print("")
                return "".join(buf)
            if ch == "\x1b":
                print("")
                return None
            if ch in ("\b", "\x7f"):
                if buf:
                    buf.pop()
                    print("\b \b", end="", flush=True)
                continue
            if ch in ("\x00", "\xe0"):
                _ = msvcrt.getwch()
                continue
            if ch and ch.isprintable():
                buf.append(ch)
                print(ch, end="", flush=True)

    if termios and tty and sys.stdin.isatty():
        import select
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            buf = []
            while True:
                b = os.read(fd, 1)
                if not b:
                    print("")
                    return "".join(buf)
                if b in (b"\r", b"\n"):
                    print("")
                    return "".join(buf)
                if b in (b"\x7f", b"\x08"):
                    if buf:
                        buf.pop()
                        print("\b \b", end="", flush=True)
                    continue
                if b == b"\x1b":
                    r, _, _ = select.select([fd], [], [], 0.03)
                    if r:
                        _ = os.read(fd, 8)
                        continue
                    print("")
                    return None
                ch = b.decode("utf-8", errors="ignore")
                if ch and ch.isprintable():
                    buf.append(ch)
                    print(ch, end="", flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    try:
        value = input()
    except EOFError:
        return None
    if value.strip().lower() == "esc":
        return None
    return value

def print_urls_line():
    urls = server_urls()
    if not urls:
        return
    print(lavender(hr()))
    print(bold("URL") + "      : " + gray("  ".join(urls)))

def follow_log(path):
    ensure_log_file()
    mode = "tail"
    urls_text = "  ".join(server_urls())

    def show_tail():
        n = max(10, min(22, term_height() - 14))
        lines = read_last_lines(path, n)
        body = []
        if lines:
            body.extend(lines)
        else:
            body.append(dim("No terminal output yet."))
        if urls_text:
            body.append("")
            body.append(f"{bold('URL')} : {gray(urls_text)}")
        body.append("")
        body.append(dim("Q/B/Esc = back    F = follow live    R = refresh"))
        render_box("Terminal Output", body, "Use arrow-style menu keys here too.")

        key = read_menu_key()
        if key in ("q", "b", "esc"):
            return "q"
        if key == "f":
            return "f"
        return "r"

    def show_follow():
        while True:
            n = max(10, min(22, term_height() - 14))
            lines = read_last_lines(path, n)
            body = []
            if lines:
                body.extend(lines)
            else:
                body.append(dim("No terminal output yet."))
            if urls_text:
                body.append("")
                body.append(f"{bold('URL')} : {gray(urls_text)}")
            body.append("")
            body.append(dim("LIVE MODE: auto-refresh"))
            body.append(dim("Q/B/Esc = back    R = refresh now"))
            render_box("Live Terminal Output", body, "Updates automatically.")

            try:
                if os.name == "nt" and msvcrt:
                    t_end = time.time() + 0.18
                    while time.time() < t_end:
                        if msvcrt.kbhit():
                            key = read_menu_key()
                            if key in ("q", "b", "esc"):
                                return "q"
                            break
                        time.sleep(0.03)
                    continue

                key = None
                if sys.stdin in select_readable(0.18):
                    key = read_menu_key()
                if key in ("q", "b", "esc"):
                    return "q"
            except Exception as e:
                print(red(str(e)))
                print(dim("Press any key..."), end="", flush=True)
                wait_for_any_key()
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

def term_width():
    try:
        return max(MIN_LINE_WIDTH, shutil.get_terminal_size((80, 24)).columns)
    except:
        return MIN_LINE_WIDTH
    
def term_height():
    try:
        return max(12, shutil.get_terminal_size((80, 24)).lines)
    except:
        return 24
    
def hr(w=None):
    w = w or term_width()
    return "─" * w

def run_with_spinner(label, fn, *args, **kwargs):
    if not ANSI:
        print(dim(f"{label}..."))
        return fn(*args, **kwargs)

    done = threading.Event()
    result = {}
    error = {}
    frames = ["|", "/", "-", "\\"]

    def worker():
        try:
            result["value"] = fn(*args, **kwargs)
        except Exception as e:
            error["exc"] = e
        finally:
            done.set()

    def spin():
        i = 0
        while not done.wait(0.1):
            frame = frames[i % len(frames)]
            text = f"\r{cyan(frame)} {label}..."
            print(text, end="", flush=True)
            i += 1
        clear_line = "\r" + (" " * max(24, len(label) + 8)) + "\r"
        print(clear_line, end="", flush=True)

    t_work = threading.Thread(target=worker, daemon=True)
    t_spin = threading.Thread(target=spin, daemon=True)
    t_work.start()
    t_spin.start()
    t_work.join()
    t_spin.join()

    if "exc" in error:
        raise error["exc"]
    return result.get("value")

def _load_db_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "edit_database",
        os.path.join(BASE_DIR, "edit-database.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # inject color functions so output matches start.py's ANSI state
    mod.bold = bold
    mod.dim = dim
    mod.red = red
    mod.green = green
    mod.yellow = yellow
    mod.gray = gray
    return mod


def _db_select_backup(db):
    entries = db.get_backup_entries()
    if not entries:
        toast("No backup files found.", False)
        return None

    def fmt_size(b):
        return f"{b / 1024:.1f} KB" if b < 1024 * 1024 else f"{b / (1024 * 1024):.2f} MB"

    def fmt_age(mtime):
        delta = int(time.time() - mtime)
        if delta < 60:    return f"{delta}s ago"
        if delta < 3600:  return f"{delta // 60}m ago"
        if delta < 86400: return f"{delta // 3600}h ago"
        return f"{delta // 86400}d ago"

    selected = 0
    while True:
        lines = []
        for idx, (mtime, name, size, path) in enumerate(entries):
            marker = "▶" if idx == selected else " "
            age = fmt_age(mtime) if mtime else "?"
            label = f"{name}  {dim(fmt_size(size))}  {gray(age)}"
            line = f"{marker} {label}" if idx != selected else cyan(f"▶ {name}") + f"  {dim(fmt_size(size))}  {gray(age)}"
            lines.append(line)
        lines.append("")
        lines.append(dim("↑/↓ to select   Enter to confirm   Esc/B to cancel"))
        render_box("Select Backup to Restore", lines)

        key = read_menu_key()
        if key == "up":
            selected = (selected - 1) % len(entries)
        elif key == "down":
            selected = (selected + 1) % len(entries)
        elif key == "enter":
            _, name, size, path = entries[selected]
            server_running = status()["running"]
            conf_lines = [
                f"  {yellow('!')} This will overwrite the current live database.",
                "",
                f"  File : {bold(name)}",
                f"  Size : {gray(fmt_size(size))}",
                "",
            ]
            if server_running:
                conf_lines.append(f"  {yellow('!')} Server is running — it will be stopped and restarted.")
                conf_lines.append("")
            conf_lines.append(f"  {dim('A security backup of the current DB will be saved first.')}")
            conf_lines.append("")
            conf_lines.append(dim("Press Y to confirm, any other key to cancel."))
            render_box("Confirm Restore", conf_lines)
            k = read_menu_key()
            if k == "y":
                return path
        elif key in ("esc", "b", "q"):
            return None


def database_menu():
    try:
        db = _load_db_module()
    except Exception as e:
        toast(f"Could not load database module: {e}", False)
        return

    items = [
        {"key": "1", "choice": "1", "label": "Check integrity"},
        {"key": "2", "choice": "2", "label": "Repair database"},
        {"key": "3", "choice": "3", "label": "Upgrade schema"},
        {"key": "4", "choice": "4", "label": "Database statistics"},
        {"key": "5", "choice": "5", "label": "Vacuum database"},
        {"key": "6", "choice": "6", "label": "Reset all sessions"},
        {"key": "7", "choice": "7", "label": "Create backup"},
        {"key": "8", "choice": "8", "label": "List backups"},
        {"key": "9", "choice": "9", "label": "Load backup"},
        {"key": "B", "choice": "0", "label": "Back"},
    ]

    shortcuts = {it["key"].lower(): it["choice"] for it in items}
    shortcuts["q"] = "0"
    selected = 0

    while True:
        lines = []
        for idx, it in enumerate(items):
            marker = "▶" if idx == selected else " "
            label = f"{it['key']}  {it['label']}"
            line = f"{marker} {label}"
            if idx == selected:
                line = cyan(line)
            lines.append(line)
        lines.append("")
        lines.append(dim("Use ↑/↓ + Enter, or press 1-9/0 directly."))
        render_box("Database Tools", lines, "Esc also goes back.")

        key = read_menu_key()
        if key == "up":
            selected = (selected - 1) % len(items)
            continue
        if key == "down":
            selected = (selected + 1) % len(items)
            continue
        if key == "enter":
            choice = items[selected]["choice"]
        elif key == "esc":
            choice = "0"
        elif key in shortcuts:
            choice = shortcuts[key]
        else:
            continue

        if choice == "0":
            return

        # Option 9: interactive select → stop server → restore → restart server
        if choice == "9":
            restore_path = _db_select_backup(db)
            if restore_path is None:
                continue

            server_was_running = status()["running"]
            stop_msg = None
            if server_was_running:
                _, stop_msg = run_with_spinner("Stopping server", stop_server)

            import io
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                db.restore_backup_file(restore_path)
            except Exception as e:
                print(f"  {red('✗')} {e}")
            finally:
                sys.stdout = old_stdout

            start_msg = None
            if server_was_running:
                _, start_msg = run_with_spinner("Restarting server", start_server)

            out_lines = buf.getvalue().splitlines()
            while out_lines and not out_lines[0].strip():
                out_lines.pop(0)
            while out_lines and not out_lines[-1].strip():
                out_lines.pop()
            if server_was_running:
                out_lines.append("")
                if stop_msg:
                    out_lines.append(f"  {dim('Stop')}    : {gray(stop_msg)}")
                if start_msg:
                    out_lines.append(f"  {dim('Restart')} : {gray(start_msg)}")
            out_lines.append("")
            out_lines.append(dim("Press any key to continue..."))
            render_box("Restore Backup", out_lines)
            wait_for_any_key()
            continue

        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            if choice == "1":
                db.check_integrity()
            elif choice == "2":
                db.repair_database()
            elif choice == "3":
                db.upgrade_database()
            elif choice == "4":
                db.database_stats()
            elif choice == "5":
                db.vacuum_database()
            elif choice == "6":
                db.reset_sessions()
            elif choice == "7":
                db.create_backup()
                if db.check_schema_needs_update():
                    print("")
                    print(f"  {yellow('!')} Schema is outdated — run {bold('Upgrade Schema')} to update.")
            elif choice == "8":
                db.list_backups()
        except Exception as e:
            print(f"  {red('✗')} {e}")
        finally:
            sys.stdout = old_stdout

        out_lines = buf.getvalue().splitlines()
        while out_lines and not out_lines[0].strip():
            out_lines.pop(0)
        while out_lines and not out_lines[-1].strip():
            out_lines.pop()

        titles = {
            "1": "Integrity Check",
            "2": "Repair Database",
            "3": "Upgrade Schema",
            "4": "Database Statistics",
            "5": "Vacuum Database",
            "6": "Reset All Sessions",
            "7": "Create Backup",
            "8": "List Backups",
        }
        out_lines.append("")
        out_lines.append(dim("Press any key to continue..."))
        render_box(titles.get(choice, "Database Tools"), out_lines)
        wait_for_any_key()


def settings_menu():
    ensure_settings_file()

    items = [
        {"key": "1", "choice": "1", "label": "Set port"},
        {"key": "2", "choice": "2", "label": "Set secret"},
        {"key": "3", "choice": "3", "label": "Reset to defaults"},
        {"key": "B", "choice": "0", "label": "Back"},
    ]

    shortcuts = {it["key"]: it["choice"] for it in items}
    shortcuts["b"] = "0"
    shortcuts["q"] = "0"
    selected = 0

    while True:
        cfg = read_settings()
        lines = [
            f"{bold('Current Port')}   : {gray(str(cfg['port']))}",
            f"{bold('Current Secret')} : {gray(mask_secret(cfg['secret_key']))}",
            "",
        ]

        for idx, it in enumerate(items):
            marker = "▶" if idx == selected else " "
            label = f"{it['key']}  {it['label']}"
            line = f"{marker} {label}"
            if idx == selected:
                line = cyan(line)
            lines.append(line)

        lines.append("")
        lines.append(dim("Use ↑/↓ + Enter, or press 1/2/3/0 directly."))
        render_box("Settings", lines, "Esc also goes back.")

        key = read_menu_key()
        if key == "up":
            selected = (selected - 1) % len(items)
            continue
        if key == "down":
            selected = (selected + 1) % len(items)
            continue
        if key == "enter":
            choice = items[selected]["choice"]
        elif key == "esc":
            choice = "0"
        elif key in shortcuts:
            choice = shortcuts[key]
        else:
            continue

        if choice == "1":
            tw, _ = get_terminal_size()
            prompt = (" " * max(0, (tw - 24) // 2)) + "New port: "
            value = read_line_allow_escape(prompt)
            if value is None:
                toast("Port change cancelled.", False)
                continue
            value = value.strip()
            if value.lower() == "b":
                toast("Port change cancelled.", False)
                continue
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

def _read_dashboard_key(timeout):
    """Wait up to `timeout` seconds for a single keypress in raw mode. Returns key or None."""
    if os.name == "nt" and msvcrt:
        t_end = time.time() + timeout
        while time.time() < t_end:
            if msvcrt.kbhit():
                return read_menu_key()
            time.sleep(0.05)
        return None

    if termios and tty and sys.stdin.isatty():
        import select as _sel
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            r, _, _ = _sel.select([fd], [], [], timeout)
            if not r:
                return None
            first = os.read(fd, 1)
            if not first:
                return None
            ch = first.decode("utf-8", errors="ignore")
            if ch in ("\r", "\n"):
                return "enter"
            if ch == "\x1b":
                seq = b""
                t_end = time.time() + 0.08
                while time.time() < t_end:
                    r2, _, _ = _sel.select([fd], [], [], 0.03)
                    if not r2:
                        break
                    chunk = os.read(fd, 8)
                    if not chunk:
                        break
                    seq += chunk
                    if b"A" in seq or b"B" in seq:
                        break
                if seq.startswith(b"[") and len(seq) >= 2:
                    code = chr(seq[1])
                    if code == "A": return "up"
                    if code == "B": return "down"
                return "esc"
            return ch.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    r = select_readable(timeout)
    if r:
        return read_menu_key()
    return None


def _confirm_exit():
    conf_lines = [
        "",
        f"  {bold('Exit OTP Manager?')}",
        "",
        f"  {dim('The server will keep running in the background.')}",
        "",
        dim("Y  confirm     any other key  cancel"),
    ]
    render_box("Exit", conf_lines)
    k = read_menu_key()
    if k == "y":
        sys.exit(0)


def menu_action(choice):
    c0 = (choice or "").strip().lower()
    s = status()

    can_start = not s["running"]
    can_stop = s["running"]
    can_update = not s["running"]

    if c0 in ("s", "1"):
        if not can_start:
            toast("Server is already running.", False)
            return
        ok, msg = run_with_spinner("Starting server", start_server)
        toast(msg, ok)
        return

    if c0 in ("t", "2"):
        if not can_stop:
            toast("Server is already stopped.", False)
            return
        ok, msg = run_with_spinner("Stopping server", stop_server)
        toast(msg, ok)
        return

    if c0 in ("l", "3"):
        follow_log(LOG_PATH)
        return

    if c0 in ("c", "4"):
        try:
            info = check_for_update()
            if info["update_available"]:
                toast(f"Update available: {info['local']} -> {info['remote']}", True)
            else:
                toast(f"Already up to date: {info['local']}", True)
        except Exception as e:
            toast(f"Version check failed: {e}", False)
        return

    if c0 in ("u", "5"):
        if not can_update:
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

    if c0 in ("g", "6"):
        settings_menu()
        return

    if c0 in ("d", "7"):
        database_menu()
        return

    if c0 in ("b", "0", "q"):
        return "back"

    if c0 in ("x", "8"):
        _confirm_exit()
        return

    toast("Invalid selection.", False)

def show_menu_once():
    s = status()

    can_start = not s["running"]
    can_stop = s["running"]
    can_update = not s["running"]

    items = [
        {"key": "S", "num": "1", "choice": "s", "label": "Start server", "enabled": can_start, "note": "(already running)"},
        {"key": "T", "num": "2", "choice": "t", "label": "Stop server", "enabled": can_stop, "note": "(already stopped)"},
        {"key": "L", "num": "3", "choice": "l", "label": "Peek terminal output", "enabled": True, "note": ""},
        {"key": "C", "num": "4", "choice": "c", "label": "Check for updates", "enabled": True, "note": ""},
        {"key": "U", "num": "5", "choice": "u", "label": "Update from GitHub", "enabled": can_update, "note": "(stop server first)"},
        {"key": "G", "num": "6", "choice": "g", "label": "Settings", "enabled": True, "note": ""},
        {"key": "D", "num": "7", "choice": "d", "label": "Database tools", "enabled": True, "note": ""},
        {"key": "B", "num": "0", "choice": "b", "label": "Back to dashboard", "enabled": True, "note": ""},
        {"key": "X", "num": "8", "choice": "x", "label": "Exit OTP Manager", "enabled": True, "note": ""},
    ]

    shortcuts = {}
    for it in items:
        shortcuts[it["choice"]] = it["choice"]
        shortcuts[it["key"].lower()] = it["choice"]
        shortcuts[it["num"]] = it["choice"]
    shortcuts["q"] = "b"

    selected = 0

    while True:
        lines = []
        for idx, it in enumerate(items):
            marker = "▶" if idx == selected else " "
            base = f"{it['key']}  {it['label']}"
            if it["note"] and not it["enabled"]:
                base += f" {gray(it['note'])}"
            line = f"{marker} {base}"
            if idx == selected:
                line = cyan(line)
            if not it["enabled"]:
                line = dim(line)
            lines.append(line)
        lines.append("")
        lines.append(dim("Use ↑/↓ + Enter, or press shortcut keys directly."))
        lines.append(dim("Shortcuts: 1=S, 2=T, 3=L, 4=C, 5=U, 6=G, 7=D, 0=B, X=Exit"))

        render_box("Menu", lines, "Esc also goes back.")
        key = read_menu_key()

        if key == "up":
            selected = (selected - 1) % len(items)
            continue
        if key == "down":
            selected = (selected + 1) % len(items)
            continue
        if key == "enter":
            return items[selected]["choice"]
        if key == "esc":
            return "b"
        if key in shortcuts:
            return shortcuts[key]

def main():
    signal.signal(signal.SIGINT, lambda _sig, _frame: None)
    ensure_settings_file()
    while True:
        maybe_trigger_update_check()
        draw_header()
        wait_seconds = 5.0
        with BOOT_UPDATE_LOCK:
            if BOOT_UPDATE_STATUS.get("state") == "checking":
                wait_seconds = 0.12
        key = _read_dashboard_key(wait_seconds)
        if key in ("x", "esc"):
            _confirm_exit()
        elif key == "enter":
            while True:
                choice = show_menu_once()
                result = menu_action(choice)
                if result == "back":
                    break

if __name__ == "__main__":
    main()
