"""Encrypted database sync: pushes an AES-256-GCM encrypted copy of the
OTP database to a remote endpoint over a shared secret.

Every message (ping, pong, db push) is wrapped in the same envelope: a
random salt + PBKDF2 key derivation from the shared secret, a random
nonce, and an AES-256-GCM ciphertext (which is authenticated, so a wrong
secret or a tampered-with payload fails to decrypt rather than silently
returning garbage). Nothing is ever sent in plaintext, and the raw
secret itself never goes over the wire.

See SYNC_COUNTERPART.txt (repo root) for the receiver-side protocol that
the remote endpoint must implement.
"""
import base64
import json
import os
import secrets as pysecrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROTOCOL_VERSION = 1
KDF_ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
AAD_CONTEXT = b"otp-sync-v1"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(secret: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(secret.encode("utf-8"))


def encrypt_blob(secret: str, plaintext: bytes) -> dict:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(secret, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, AAD_CONTEXT)
    return {
        "v": PROTOCOL_VERSION,
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iter": KDF_ITERATIONS,
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ct": _b64e(ct),
    }


def decrypt_blob(secret: str, envelope: dict) -> bytes:
    try:
        salt = _b64d(envelope["salt"])
        nonce = _b64d(envelope["nonce"])
        ct = _b64d(envelope["ct"])
        iterations = int(envelope.get("iter", KDF_ITERATIONS))
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"Malformed envelope: {e}")
    key = derive_key(secret, salt, iterations)
    try:
        return AESGCM(key).decrypt(nonce, ct, AAD_CONTEXT)
    except InvalidTag:
        raise ValueError("Decryption failed — wrong secret or tampered data")


def generate_secret() -> str:
    return pysecrets.token_urlsafe(32)


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "OTP-Tool-Sync/1"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read().decode("utf-8"))


def test_connection(endpoint: str, secret: str, timeout: int = 10):
    """Sends an encrypted challenge to the endpoint and verifies the
    encrypted, echoed-back response — proving both sides hold the same
    secret and that the tunnel round-trips correctly.
    Returns (ok, message, latency_ms)."""
    endpoint = (endpoint or "").strip()
    secret = secret or ""
    if not endpoint or not secret:
        return False, "Endpoint and secret are required", None

    challenge = pysecrets.token_hex(16)
    envelope = encrypt_blob(secret, json.dumps({"challenge": challenge, "ts": time.time()}).encode("utf-8"))

    t0 = time.perf_counter()
    try:
        resp = _post_json(endpoint.rstrip("/") + "/otp-sync/ping", envelope, timeout)
    except urllib.error.HTTPError as e:
        return False, f"Endpoint responded with HTTP {e.code}", None
    except urllib.error.URLError as e:
        return False, f"Could not reach endpoint: {e.reason}", None
    except Exception as e:
        return False, f"Connection failed: {e}", None
    latency_ms = round((time.perf_counter() - t0) * 1000)

    try:
        pong = decrypt_blob(secret, resp)
        data = json.loads(pong.decode("utf-8"))
    except Exception:
        return False, "Endpoint responded but the reply could not be decrypted — secret mismatch?", None
    if data.get("challenge") != challenge:
        return False, "Endpoint responded with an unexpected challenge — possible tampering", None
    return True, "Connection verified — encrypted tunnel confirmed", latency_ms


def push_database(endpoint: str, secret: str, db_path: str, timeout: int = 60):
    """Encrypts the whole database file with the shared secret and POSTs
    it to the endpoint's receiver. Returns (ok, message)."""
    endpoint = (endpoint or "").strip()
    secret = secret or ""
    if not endpoint or not secret:
        return False, "Endpoint and secret are required"
    if not os.path.exists(db_path):
        return False, "No database file found to push"

    with open(db_path, "rb") as f:
        raw = f.read()

    payload = json.dumps({
        "filename": "otp.db",
        "size": len(raw),
        "pushed_at": datetime.now(timezone.utc).isoformat(),
        "db_b64": _b64e(raw),
    }).encode("utf-8")
    envelope = encrypt_blob(secret, payload)

    try:
        resp = _post_json(endpoint.rstrip("/") + "/otp-sync/receive", envelope, timeout)
    except urllib.error.HTTPError as e:
        return False, f"Endpoint responded with HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, f"Could not reach endpoint: {e.reason}"
    except Exception as e:
        return False, f"Push failed: {e}"

    if not resp.get("ok"):
        return False, str(resp.get("error") or "Endpoint rejected the push")
    return True, "Database pushed and encrypted successfully"
