"""One-Auth account integration: device info, secure token storage, cached user, refresh.

This module is deliberately independent of the Flask app so it can be tested on its own.
The app calls configure() once at start-up with its license API key and version getter.

Security notes:
  * HTTPS only, certificates verified (urllib default context), 10s timeouts, no redirects
    followed (so the API key / bearer token can never be forwarded to another host).
  * account_token and the API key are never logged.
  * Everything that comes back from the server is treated as untrusted text.
"""
import base64
import binascii
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

log = logging.getLogger("otp_manager.one_auth")

DEFAULT_BASE_URL = "https://www.one-auth.net"
REQUEST_TIMEOUT = 10
KEYRING_SERVICE = "otp-manager-one-auth"
KEYRING_USER = "account_token"
USE_KEYRING = os.environ.get("OTP_DISABLE_KEYRING", "").strip() not in ("1", "true", "yes")

AVATAR_MAX = 600_000
AVATAR_PREFIXES = ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "data:image/gif;base64,")

# Result states returned by refresh()
OK = "ok"                          # license + user refreshed
SIGNED_OUT = "signed_out"          # invalid_token: token/cache cleared, user must sign in again
LICENSE_INVALID = "license_invalid"  # suspended / revoked / expired / no_license (reason in result)
RATE_LIMITED = "rate_limited"      # back off and retry later
UNAUTHORIZED = "unauthorized"      # wrong API key; keep everything as is
NO_ACCOUNT = "no_account"          # no stored token: nothing to refresh
NETWORK_ERROR = "network_error"    # unreachable / bad response: keep last known state

RETRY_AFTER_FAILURE = 15 * 60
REFRESH_INTERVAL = 60 * 60
JITTER_FRACTION = 0.15

_config = {"api_key": "", "version": lambda: "0.0.0"}
_lock = threading.Lock()


def configure(api_key, version_getter=None):
    _config["api_key"] = api_key or ""
    if version_getter:
        _config["version"] = version_getter


def base_url():
    url = (os.environ.get("OTP_ONE_AUTH_URL") or DEFAULT_BASE_URL).strip().rstrip("/")
    if not url.lower().startswith("https://"):
        raise ValueError("OTP_ONE_AUTH_URL must be an https:// URL")
    return url


def api_url(path):
    return base_url() + path


# --------------------------------------------------------------------------- device info

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_EXCLUDED_IF = re.compile(r"^(lo\d*|docker\d*|veth.*|br-.*|br\d+|virbr.*|tun\d*|tap\d*|wg\d*|wireguard.*|utun\d*|"
                          r"awdl\d*|llw\d*|bridge\d*|gif\d*|stf\d*|ap\d*|ipsec\d*|zt.*|tailscale.*|cni.*|flannel.*|cali.*|kube.*)$")


def _normalize_mac(value):
    if not value:
        return None
    mac = str(value).strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.match(mac):
        return None
    first = int(mac[:2], 16)
    if mac == "00:00:00:00:00:00" or first & 1:  # all-zero or multicast: never a real NIC address
        return None
    return mac


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return ""


def _default_route_interfaces():
    """Interfaces carrying a default route, best (lowest metric) first."""
    found = []
    try:  # Linux, no dependencies
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            rows = [line.split() for line in f.read().splitlines()[1:]]
        routes = [(int(r[6]), r[0]) for r in rows if len(r) >= 8 and r[1] == "00000000"]
        found = [name for _, name in sorted(routes)]
    except Exception:
        pass
    if not found:
        for line in _run(["ip", "route", "show", "default"]).splitlines():
            m = re.search(r"\bdev\s+(\S+)", line)
            if m:
                found.append(m.group(1))
    if not found and sys.platform == "darwin":
        m = re.search(r"interface:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        if m:
            found.append(m.group(1))
    return found


def _interface_table():
    """{name: (mac_or_None, is_up)} from psutil, falling back to /sys/class/net on Linux."""
    table = {}
    try:
        import psutil
        stats = psutil.net_if_stats()
        link_families = {getattr(psutil, "AF_LINK", None), getattr(socket, "AF_PACKET", None)} - {None}
        for name, addrs in psutil.net_if_addrs().items():
            mac = None
            for a in addrs:
                if a.family in link_families:
                    mac = _normalize_mac(a.address)
                    if mac:
                        break
            st = stats.get(name)
            table[name] = (mac, bool(st and st.isup))
        return table
    except Exception:
        pass
    base = "/sys/class/net"
    try:
        for name in os.listdir(base):
            try:
                with open(f"{base}/{name}/address", "r", encoding="utf-8") as f:
                    mac = _normalize_mac(f.read())
                with open(f"{base}/{name}/operstate", "r", encoding="utf-8") as f:
                    up = f.read().strip() in ("up", "unknown")
            except Exception:
                continue
            table[name] = (mac, up)
    except Exception:
        pass
    return table


def detect_mac():
    """MAC of the primary (default-route) interface that is up; None if no valid one is found.
    Deliberately does NOT use uuid.getnode(), which can return a random value."""
    table = _interface_table()

    def usable(name):
        entry = table.get(name)
        return bool(entry and entry[0] and entry[1] and not _EXCLUDED_IF.match(name.lower()))

    for name in _default_route_interfaces():
        if usable(name):
            return table[name][0]
    # No default route found (or it uses an excluded interface): first physical-looking up NIC.
    for name in sorted(table):
        if usable(name):
            return table[name][0]
    return None


def _os_name():
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
    except Exception:
        pass
    if sys.platform == "darwin":
        ver = platform.mac_ver()[0]
        return ("macOS " + ver).strip()
    return (platform.system() + " " + platform.release()).strip()


def get_device_info():
    """{hostname, mac?, os, app_version}. OTP_DEVICE_HOSTNAME / OTP_DEVICE_MAC override the
    detected values (useful in Docker/Kubernetes, where they would be the container's)."""
    hostname = (os.environ.get("OTP_DEVICE_HOSTNAME") or "").strip() or socket.gethostname()
    mac = _normalize_mac(os.environ.get("OTP_DEVICE_MAC")) if os.environ.get("OTP_DEVICE_MAC") else None
    if not mac:
        try:
            mac = detect_mac()
        except Exception as e:
            log.warning("MAC detection failed: %s", type(e).__name__)
            mac = None
    info = {"hostname": hostname[:255], "os": _os_name()[:120], "app_version": str(_config["version"]())[:40]}
    if mac:
        info["mac"] = mac
    return info


# --------------------------------------------------------------------------- storage

def state_dir():
    d = os.environ.get("OTP_ONE_AUTH_DIR") or os.path.join(os.path.expanduser("~"), ".config", "otp-manager")
    return d


def _token_file():
    return os.environ.get("OTP_ACCOUNT_TOKEN_FILE") or os.path.join(state_dir(), "account_token")


def _user_file():
    return os.path.join(state_dir(), "account_user.json")


def _write_private(path, data):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _keyring():
    if not USE_KEYRING:
        return None
    try:
        import keyring
        return keyring
    except Exception:
        return None


def store_token(token):
    token = (token or "").strip()
    if not token:
        return
    kr = _keyring()
    if kr:
        try:
            kr.set_password(KEYRING_SERVICE, KEYRING_USER, token)
            try:
                os.unlink(_token_file())  # drop any older plaintext copy
            except OSError:
                pass
            return
        except Exception as e:
            log.warning("keyring unavailable, using 0600 token file (%s)", type(e).__name__)
    _write_private(_token_file(), token)


def load_token():
    kr = _keyring()
    if kr:
        try:
            token = kr.get_password(KEYRING_SERVICE, KEYRING_USER)
            if token:
                return token
        except Exception:
            pass
    try:
        with open(_token_file(), "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def clear_token():
    kr = _keyring()
    if kr:
        try:
            kr.delete_password(KEYRING_SERVICE, KEYRING_USER)
        except Exception:
            pass
    try:
        os.unlink(_token_file())
    except OSError:
        pass


def _clean_avatar(value):
    avatar = str(value or "").strip()
    if not avatar.startswith(AVATAR_PREFIXES) or len(avatar) > AVATAR_MAX:
        return ""
    try:
        base64.b64decode(avatar.split(",", 1)[1], validate=True)
    except (binascii.Error, ValueError):
        return ""
    return avatar


def clean_user(raw, cached=None):
    """Sanitize an untrusted `user` object. If the avatar key is absent (unchanged avatar),
    the cached avatar and version are kept."""
    raw = raw if isinstance(raw, dict) else {}
    cached = cached if isinstance(cached, dict) else {}
    if "avatar" in raw:
        avatar = _clean_avatar(raw.get("avatar"))
        version = raw.get("avatar_version")
    else:
        avatar = cached.get("avatar", "")
        version = raw.get("avatar_version", cached.get("avatar_version"))
    try:
        version = int(version) if version is not None else None
    except (TypeError, ValueError):
        version = None
    return {
        "id": str(raw.get("id") if raw.get("id") is not None else cached.get("id", ""))[:64],
        "name": str(raw.get("full_name") or "").strip()[:80],
        "email": str(raw.get("email") or "").strip()[:254],
        "company": str(raw.get("company") or "").strip()[:60],
        "avatar": avatar,
        "avatar_version": version,
    }


def load_user():
    try:
        with open(_user_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_user(user):
    _write_private(_user_file(), json.dumps(user))


def clear_user():
    try:
        os.unlink(_user_file())
    except OSError:
        pass


def clear_account():
    clear_token()
    clear_user()


def has_account():
    return bool(load_token())


# --------------------------------------------------------------------------- HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def post_json(url, payload, bearer=None):
    """POST JSON. Returns (status, body_dict); status 0 on any network/transport failure."""
    if not url.lower().startswith("https://"):
        log.error("refusing non-HTTPS One-Auth URL")
        return 0, {}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "OTP-Tool/" + str(_config["version"]()),
        "X-License-Api-Key": _config["api_key"],
    }
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with _opener.open(req, timeout=REQUEST_TIMEOUT) as res:
            status, raw = res.status, res.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except Exception as e:
        log.warning("one-auth request failed: %s", type(e).__name__)
        return 0, {}
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        log.warning("one-auth returned a non-JSON response: status=%s", status)
        return status, {}
    return status, body if isinstance(body, dict) else {}


# --------------------------------------------------------------------------- sign-in / refresh

def on_sign_in(body):
    """Call after a successful sign-in response: stores the token and caches the user.
    Returns the cleaned user dict."""
    token = body.get("account_token")
    if isinstance(token, str) and token.strip():
        store_token(token)
    user = clean_user(body.get("user"), None)
    save_user(user)
    return user


def refresh():
    """POST /api/v1/account/me. Never raises. Returns {"state", "reason", "body", "user"}.

    On OK / LICENSE_INVALID the cached user is updated; on SIGNED_OUT token and cache are
    cleared. Network failures change nothing."""
    with _lock:
        token = load_token()
        if not token:
            return {"state": NO_ACCOUNT, "reason": None, "body": {}, "user": load_user()}
        cached = load_user()
        payload = {"device": get_device_info()}
        version = (cached or {}).get("avatar_version")
        if version is not None:
            payload["avatar_version"] = version
        try:
            status, body = post_json(api_url("/api/v1/account/me"), payload, bearer=token)
        except Exception as e:  # e.g. bad OTP_ONE_AUTH_URL
            log.warning("one-auth refresh failed: %s", type(e).__name__)
            return {"state": NETWORK_ERROR, "reason": "unreachable", "body": {}, "user": cached}

        reason = body.get("reason") or body.get("error")
        if not isinstance(reason, str):
            reason = None

        def result(state):
            return {"state": state, "reason": reason, "body": body, "user": load_user()}

        if status == 0 or (status >= 500) or (status != 200 and not body):
            return {"state": NETWORK_ERROR, "reason": "unreachable", "body": {}, "user": cached}
        if status == 429 or reason == "rate_limited":
            return result(RATE_LIMITED)
        if status == 401 and reason == "invalid_token":
            log.warning("one-auth: stored account token was rejected; signing out")
            clear_account()
            return {"state": SIGNED_OUT, "reason": "invalid_token", "body": body, "user": None}
        if status == 401:
            return result(UNAUTHORIZED)

        if status == 200 and body.get("valid") is not False:
            user = clean_user(body.get("user"), cached) if isinstance(body.get("user"), dict) else cached
            if user:
                save_user(user)
            return {"state": OK, "reason": None, "body": body, "user": user}

        if reason in ("suspended", "revoked", "expired", "no_license"):
            if isinstance(body.get("user"), dict):
                save_user(clean_user(body["user"], cached))
            return result(LICENSE_INVALID)
        return {"state": NETWORK_ERROR, "reason": reason or "unreachable", "body": {}, "user": cached}


def next_delay(state, retry_after=None):
    """Seconds until the next refresh, with jitter so installs don't all fire together."""
    import random
    if state in (NETWORK_ERROR, UNAUTHORIZED):
        base = RETRY_AFTER_FAILURE
    elif state == RATE_LIMITED:
        base = max(RETRY_AFTER_FAILURE, int(retry_after or 0))
    else:
        base = REFRESH_INTERVAL
    return base * (1 + random.uniform(-JITTER_FRACTION, JITTER_FRACTION))
