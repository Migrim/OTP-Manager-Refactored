import os
import sys
import time
import json
import signal
import subprocess
from datetime import datetime
import re
import socket

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PID_PATH = os.path.join(BASE_DIR, "otp-server.pid")
STATE_PATH = os.path.join(BASE_DIR, "otp-server.state.json")
LOG_PATH = os.path.join(BASE_DIR, "otp-server.output.log")
APP_PY_PATH = os.path.join(BASE_DIR, "app.py")

PYTHON = sys.executable or "python3"
APP_CMD = [PYTHON, os.path.join(BASE_DIR, "app.py")]

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

def draw_header():
    s = status()
    st = read_state()
    started_at = st.get("started_at") if s["running"] else None
    up = fmt_uptime(started_at)
    line = "─" * 64

    title = f"{bold('OTP-Tool Server Control')}"
    stat = green("RUNNING") if s["running"] else red("STOPPED")
    pid_txt = f"{s['pid']}" if s["running"] else "-"
    log_txt = LOG_PATH

    print(cyan(line))
    print(title)
    print(cyan(line))
    print(f"{bold('Status')}   : {stat}    {bold('PID')}: {pid_txt}    {bold('Uptime')}: {up}")
    print(f"{bold('Log')}      : {gray(log_txt)}")
    print(cyan(line))

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
    print(cyan("─" * 64))
    print(bold("URL") + "      : " + gray("  ".join(urls)))

def follow_log(path):
    ensure_log_file()
    mode = "tail"

    def show_tail():
        clear()
        print(bold("Peek terminal output"))
        print(dim("q = back, f = follow (live)"))
        print(cyan("─" * 64))
        for ln in read_last_lines(path, 60):
            print(ln)
        print_urls_line()
        return input(dim("Command: ")).strip().lower()

    def show_follow():
        clear()
        print(bold("Peek terminal output"))
        print(dim("Following... type q + Enter to stop"))
        print(cyan("─" * 64))
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