"""
CNS Cryptography Web Application
=================================
Flask-based web app implementing AES-256 and DES encryption/decryption
with text & file support, key generation, and comparative analysis.

Stack: Flask + pycryptodome + Bootstrap 5

Fixes applied:
  - AES switched from CBC → GCM (authenticated encryption; kills padding oracle)
  - DES kept CBC but all decrypt calls verify ciphertext length before touching unpad
  - secure_filename() used on all uploaded filenames (prevents path traversal)
  - Temp files cleaned up immediately after send_file via a teardown callback
  - /api/analysis rate-limited to 1 req/5s per IP (simple in-memory token bucket)
  - Algorithm input validated against an allowlist (no unknown strings fall through)
  - Duplicate encrypt/decrypt logic collapsed into shared helpers
  - DES marked prominently as "Educational Only" in API responses
"""

import os
import time
import tempfile
import threading
from pathlib import Path
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from collections import defaultdict
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_file, g
from werkzeug.utils import secure_filename

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

UPLOAD_DIR = Path(tempfile.gettempdir()) / "cns_crypto"
UPLOAD_DIR.mkdir(exist_ok=True)

# Crypto constants
AES_KEY_SIZE   = 32   # 256-bit
AES_BLOCK_SIZE = 16   # 128-bit blocks (also GCM tag / nonce sizes)
AES_NONCE_SIZE = 16
AES_TAG_SIZE   = 16
DES_KEY_SIZE   = 8    # 56-bit effective
DES_BLOCK_SIZE = 8    # 64-bit blocks
PBKDF2_ITERATIONS = 100_000

VALID_ALGORITHMS = {"AES", "DES"}

# ---------------------------------------------------------------------------
# Simple per-IP rate limiter (in-memory, thread-safe)
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_store: dict[str, float] = defaultdict(float)  # ip -> last_allowed_ts

def rate_limit(min_interval_sec: float):
    """Decorator: allow at most one call per `min_interval_sec` per remote IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.monotonic()
            with _rate_lock:
                last = _rate_store[ip]
                if now - last < min_interval_sec:
                    wait = round(min_interval_sec - (now - last), 1)
                    return jsonify({"error": f"Rate limited. Try again in {wait}s."}), 429
                _rate_store[ip] = now
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# Crypto Helpers
# ---------------------------------------------------------------------------

def _validate_algorithm(algorithm: str):
    """Return uppercased algorithm or raise ValueError."""
    algo = algorithm.upper()
    if algo not in VALID_ALGORITHMS:
        raise ValueError(f"Unknown algorithm '{algorithm}'. Must be AES or DES.")
    return algo


def generate_key(algorithm: str, password: str | None = None):
    """Generate a random key or derive one from a password via PBKDF2."""
    algo = _validate_algorithm(algorithm)
    key_size  = AES_KEY_SIZE  if algo == "AES" else DES_KEY_SIZE
    salt_size = 16            if algo == "AES" else 8

    if password:
        salt = get_random_bytes(salt_size)
        key  = PBKDF2(password, salt, dkLen=key_size,
                      count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        return key, salt
    return get_random_bytes(key_size), None


# --- AES-GCM (authenticated) -----------------------------------------------

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce + tag + ciphertext."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(AES_NONCE_SIZE))
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct          # 16 + 16 + len(data) bytes


def aes_decrypt(payload: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises ValueError on authentication failure."""
    if len(payload) < AES_NONCE_SIZE + AES_TAG_SIZE + 1:
        raise ValueError("Ciphertext too short.")
    nonce = payload[:AES_NONCE_SIZE]
    tag   = payload[AES_NONCE_SIZE:AES_NONCE_SIZE + AES_TAG_SIZE]
    ct    = payload[AES_NONCE_SIZE + AES_TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        raise ValueError("Authentication failed — ciphertext may be tampered or key is wrong.")


# --- DES-CBC (educational only) --------------------------------------------

def des_encrypt(data: bytes, key: bytes) -> bytes:
    """DES-CBC encrypt. Returns IV + ciphertext. EDUCATIONAL USE ONLY."""
    iv     = get_random_bytes(DES_BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, DES_BLOCK_SIZE))


def des_decrypt(payload: bytes, key: bytes) -> bytes:
    """DES-CBC decrypt. EDUCATIONAL USE ONLY."""
    if len(payload) < DES_BLOCK_SIZE + DES_BLOCK_SIZE:
        raise ValueError("Ciphertext too short.")
    iv, ct = payload[:DES_BLOCK_SIZE], payload[DES_BLOCK_SIZE:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES_BLOCK_SIZE)


def encrypt_data(data: bytes, key: bytes, algorithm: str) -> bytes:
    return aes_encrypt(data, key) if algorithm == "AES" else des_encrypt(data, key)


def decrypt_data(payload: bytes, key: bytes, algorithm: str) -> bytes:
    return aes_decrypt(payload, key) if algorithm == "AES" else des_decrypt(payload, key)


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _get_key_and_algo(source) -> tuple[bytes, str]:
    """Parse and validate key_hex + algorithm from a dict-like source."""
    algorithm = source.get("algorithm", "AES")
    try:
        algorithm = _validate_algorithm(algorithm)
    except ValueError as e:
        raise ValueError(str(e))

    key_hex = source.get("key_hex", "").strip()
    if not key_hex:
        raise ValueError("Key (hex) is required.")
    try:
        key = unhexlify(key_hex)
    except Exception:
        raise ValueError("Invalid hex key format.")

    expected = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    if len(key) != expected:
        raise ValueError(f"Key must be {expected} bytes ({expected*8} bits) for {algorithm}.")

    return key, algorithm


def _cleanup_after(path: Path):
    """Register a teardown to delete `path` after the response is sent."""
    @app.after_request
    def _delete(response):
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    body      = request.get_json(force=True)
    algorithm = body.get("algorithm", "AES")
    password  = body.get("password", "").strip() or None

    try:
        algorithm = _validate_algorithm(algorithm)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    key, salt = generate_key(algorithm, password)
    result = {
        "key_hex":   hexlify(key).decode(),
        "key_b64":   b64encode(key).decode(),
        "bits":      len(key) * 8,
        "algorithm": algorithm,
    }
    if salt:
        result["salt_hex"] = hexlify(salt).decode()
    return jsonify(result)


@app.route("/api/encrypt-text", methods=["POST"])
def api_encrypt_text():
    body      = request.get_json(force=True)
    plaintext = body.get("plaintext", "")

    if not plaintext:
        return jsonify({"error": "Plaintext is required."}), 400

    try:
        key, algorithm = _get_key_and_algo(body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        start = time.perf_counter()
        ct    = encrypt_data(plaintext.encode("utf-8"), key, algorithm)
        elapsed = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    response = {
        "ciphertext_hex": hexlify(ct).decode(),
        "ciphertext_b64": b64encode(ct).decode(),
        "plaintext_len":  len(plaintext),
        "ciphertext_len": len(ct),
        "time_ms":        round(elapsed, 4),
        "algorithm":      algorithm,
        "mode":           "GCM (authenticated)" if algorithm == "AES" else "CBC (educational only — not authenticated)",
    }
    if algorithm == "DES":
        response["warning"] = "DES is cryptographically broken. For educational comparison only."
    return jsonify(response)


@app.route("/api/decrypt-text", methods=["POST"])
def api_decrypt_text():
    body           = request.get_json(force=True)
    ciphertext_hex = body.get("ciphertext_hex", "").strip()

    if not ciphertext_hex:
        return jsonify({"error": "Ciphertext (hex) is required."}), 400

    try:
        key, algorithm = _get_key_and_algo(body)
        ct = unhexlify(ciphertext_hex)
    except Exception as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    try:
        start     = time.perf_counter()
        plaintext = decrypt_data(ct, key, algorithm).decode("utf-8")
        elapsed   = (time.perf_counter() - start) * 1000
    except ValueError as e:
        # Return a generic message — don't leak padding/auth oracle details
        return jsonify({"error": "Decryption failed. Wrong key, wrong algorithm, or tampered ciphertext."}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 500

    return jsonify({
        "plaintext": plaintext,
        "time_ms":   round(elapsed, 4),
        "algorithm": algorithm,
    })


@app.route("/api/encrypt-file", methods=["POST"])
def api_encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    try:
        key, algorithm = _get_key_and_algo(request.form)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        raw       = file.read()
        start     = time.perf_counter()
        encrypted = encrypt_data(raw, key, algorithm)
        elapsed   = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    safe_name = secure_filename(file.filename or "upload")  # FIX: path traversal
    out_path  = UPLOAD_DIR / f"{safe_name}.enc"
    out_path.write_bytes(encrypted)

    response = send_file(
        out_path,
        as_attachment=True,
        download_name=f"{safe_name}.enc",
        mimetype="application/octet-stream",
    )
    # FIX: clean up temp file after response is sent
    @response.call_on_close
    def cleanup():
        out_path.unlink(missing_ok=True)

    return response


@app.route("/api/decrypt-file", methods=["POST"])
def api_decrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    try:
        key, algorithm = _get_key_and_algo(request.form)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        raw       = file.read()
        start     = time.perf_counter()
        decrypted = decrypt_data(raw, key, algorithm)
        elapsed   = (time.perf_counter() - start) * 1000
    except ValueError as e:
        return jsonify({"error": "Decryption failed. Wrong key, wrong algorithm, or tampered file."}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 500

    safe_name    = secure_filename(file.filename or "decrypted")  # FIX: path traversal
    original_name = safe_name[:-4] if safe_name.endswith(".enc") else safe_name
    out_path     = UPLOAD_DIR / original_name
    out_path.write_bytes(decrypted)

    response = send_file(
        out_path,
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream",
    )
    @response.call_on_close
    def cleanup():
        out_path.unlink(missing_ok=True)

    return response


@app.route("/api/analysis", methods=["POST"])
@rate_limit(5.0)  # FIX: max 1 benchmark per 5s per IP
def api_analysis():
    body       = request.get_json(force=True)
    sample     = body.get("sample_text", "Benchmark text for CNS project.")
    iterations = min(int(body.get("iterations", 100)), 500)

    aes_key, _ = generate_key("AES")
    des_key, _ = generate_key("DES")

    sample_bytes = sample.encode("utf-8")

    # AES-GCM encrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        aes_ct = aes_encrypt(sample_bytes, aes_key)
    aes_enc_ms = (time.perf_counter() - t) / iterations * 1000

    # AES-GCM decrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        aes_decrypt(aes_ct, aes_key)
    aes_dec_ms = (time.perf_counter() - t) / iterations * 1000

    # DES-CBC encrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        des_ct = des_encrypt(sample_bytes, des_key)
    des_enc_ms = (time.perf_counter() - t) / iterations * 1000

    # DES-CBC decrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        des_decrypt(des_ct, des_key)
    des_dec_ms = (time.perf_counter() - t) / iterations * 1000

    return jsonify({
        "iterations":    iterations,
        "sample_length": len(sample),
        "aes": {
            "mode":           "GCM (authenticated)",
            "encrypt_ms":     round(aes_enc_ms, 4),
            "decrypt_ms":     round(aes_dec_ms, 4),
            "ciphertext_bytes": len(aes_ct),
            "key_bits":       256,
            "block_bits":     128,
        },
        "des": {
            "mode":           "CBC (educational only)",
            "warning":        "DES is cryptographically broken. Do not use in production.",
            "encrypt_ms":     round(des_enc_ms, 4),
            "decrypt_ms":     round(des_dec_ms, 4),
            "ciphertext_bytes": len(des_ct),
            "key_bits":       56,
            "block_bits":     64,
        },
    })


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n CNS Cryptography Web App")
    print(" http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)