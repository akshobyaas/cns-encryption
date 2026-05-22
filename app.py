"""
CNS Cryptography Web Application
=================================
Flask-based web app implementing AES-256 and DES encryption/decryption
with text & file support, key generation, and comparative analysis.

Stack: Flask + pycryptodome + Bootstrap 5
"""

import os
import time
import tempfile
from pathlib import Path
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
)

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
AES_KEY_SIZE = 32       # 256-bit
AES_BLOCK_SIZE = 16     # 128-bit blocks
DES_KEY_SIZE = 8        # 56-bit effective
DES_BLOCK_SIZE = 8      # 64-bit blocks
PBKDF2_ITERATIONS = 100_000


# ---------------------------------------------------------------------------
# Crypto Helpers
# ---------------------------------------------------------------------------

def generate_key(algorithm: str, password: str | None = None):
    """Generate a random key or derive one from a password via PBKDF2."""
    key_size = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    salt_size = 16 if algorithm == "AES" else 8

    if password:
        salt = get_random_bytes(salt_size)
        key = PBKDF2(password, salt, dkLen=key_size,
                     count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        return key, salt
    else:
        return get_random_bytes(key_size), None


def encrypt_text(plaintext: str, key: bytes, algorithm: str) -> bytes:
    """Encrypt plaintext string. Returns IV + ciphertext."""
    data = plaintext.encode("utf-8")
    if algorithm == "AES":
        iv = get_random_bytes(AES_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    else:
        iv = get_random_bytes(DES_BLOCK_SIZE)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, DES_BLOCK_SIZE))
    return iv + ct


def decrypt_text(ciphertext: bytes, key: bytes, algorithm: str) -> str:
    """Decrypt ciphertext bytes. Returns plaintext string."""
    if algorithm == "AES":
        iv, ct = ciphertext[:AES_BLOCK_SIZE], ciphertext[AES_BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES_BLOCK_SIZE).decode("utf-8")
    else:
        iv, ct = ciphertext[:DES_BLOCK_SIZE], ciphertext[DES_BLOCK_SIZE:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), DES_BLOCK_SIZE).decode("utf-8")


def encrypt_file_data(data: bytes, key: bytes, algorithm: str) -> bytes:
    """Encrypt raw file bytes. Returns IV + ciphertext."""
    if algorithm == "AES":
        iv = get_random_bytes(AES_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    else:
        iv = get_random_bytes(DES_BLOCK_SIZE)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, DES_BLOCK_SIZE))
    return iv + ct


def decrypt_file_data(data: bytes, key: bytes, algorithm: str) -> bytes:
    """Decrypt raw file bytes (IV prepended). Returns original bytes."""
    if algorithm == "AES":
        iv, ct = data[:AES_BLOCK_SIZE], data[AES_BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES_BLOCK_SIZE)
    else:
        iv, ct = data[:DES_BLOCK_SIZE], data[DES_BLOCK_SIZE:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), DES_BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    """Generate a random key or derive from password."""
    body = request.get_json(force=True)
    algorithm = body.get("algorithm", "AES").upper()
    password = body.get("password", "").strip() or None

    key, salt = generate_key(algorithm, password)
    result = {
        "key_hex": hexlify(key).decode(),
        "key_b64": b64encode(key).decode(),
        "bits": len(key) * 8,
        "algorithm": algorithm,
    }
    if salt:
        result["salt_hex"] = hexlify(salt).decode()
    return jsonify(result)


@app.route("/api/encrypt-text", methods=["POST"])
def api_encrypt_text():
    """Encrypt plaintext with provided hex key."""
    body = request.get_json(force=True)
    plaintext = body.get("plaintext", "")
    key_hex = body.get("key_hex", "").strip()
    algorithm = body.get("algorithm", "AES").upper()

    if not plaintext:
        return jsonify({"error": "Plaintext is required."}), 400
    if not key_hex:
        return jsonify({"error": "Key (hex) is required."}), 400

    try:
        key = unhexlify(key_hex)
    except Exception:
        return jsonify({"error": "Invalid hex key format."}), 400

    expected = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    if len(key) != expected:
        return jsonify({"error": f"Key must be {expected} bytes ({expected*8} bits) for {algorithm}."}), 400

    try:
        start = time.perf_counter()
        ct = encrypt_text(plaintext, key, algorithm)
        elapsed = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    return jsonify({
        "ciphertext_hex": hexlify(ct).decode(),
        "ciphertext_b64": b64encode(ct).decode(),
        "plaintext_len": len(plaintext),
        "ciphertext_len": len(ct),
        "time_ms": round(elapsed, 4),
        "algorithm": algorithm,
    })


@app.route("/api/decrypt-text", methods=["POST"])
def api_decrypt_text():
    """Decrypt ciphertext with provided hex key."""
    body = request.get_json(force=True)
    ciphertext_hex = body.get("ciphertext_hex", "").strip()
    key_hex = body.get("key_hex", "").strip()
    algorithm = body.get("algorithm", "AES").upper()

    if not ciphertext_hex:
        return jsonify({"error": "Ciphertext (hex) is required."}), 400
    if not key_hex:
        return jsonify({"error": "Key (hex) is required."}), 400

    try:
        key = unhexlify(key_hex)
        ct = unhexlify(ciphertext_hex)
    except Exception:
        return jsonify({"error": "Invalid hex format."}), 400

    expected = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    if len(key) != expected:
        return jsonify({"error": f"Key must be {expected} bytes for {algorithm}."}), 400

    try:
        start = time.perf_counter()
        plaintext = decrypt_text(ct, key, algorithm)
        elapsed = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 500

    return jsonify({
        "plaintext": plaintext,
        "time_ms": round(elapsed, 4),
        "algorithm": algorithm,
    })


@app.route("/api/encrypt-file", methods=["POST"])
def api_encrypt_file():
    """Encrypt an uploaded file and return the encrypted file for download."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    key_hex = request.form.get("key_hex", "").strip()
    algorithm = request.form.get("algorithm", "AES").upper()

    if not key_hex:
        return jsonify({"error": "Key (hex) is required."}), 400

    try:
        key = unhexlify(key_hex)
    except Exception:
        return jsonify({"error": "Invalid hex key."}), 400

    expected = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    if len(key) != expected:
        return jsonify({"error": f"Key must be {expected} bytes for {algorithm}."}), 400

    try:
        raw = file.read()
        start = time.perf_counter()
        encrypted = encrypt_file_data(raw, key, algorithm)
        elapsed = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    out_path = UPLOAD_DIR / f"{file.filename}.enc"
    out_path.write_bytes(encrypted)

    return send_file(
        out_path,
        as_attachment=True,
        download_name=f"{file.filename}.enc",
        mimetype="application/octet-stream",
    )


@app.route("/api/decrypt-file", methods=["POST"])
def api_decrypt_file():
    """Decrypt an uploaded .enc file and return the original."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    key_hex = request.form.get("key_hex", "").strip()
    algorithm = request.form.get("algorithm", "AES").upper()

    if not key_hex:
        return jsonify({"error": "Key (hex) is required."}), 400

    try:
        key = unhexlify(key_hex)
    except Exception:
        return jsonify({"error": "Invalid hex key."}), 400

    expected = AES_KEY_SIZE if algorithm == "AES" else DES_KEY_SIZE
    if len(key) != expected:
        return jsonify({"error": f"Key must be {expected} bytes for {algorithm}."}), 400

    try:
        raw = file.read()
        start = time.perf_counter()
        decrypted = decrypt_file_data(raw, key, algorithm)
        elapsed = (time.perf_counter() - start) * 1000
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 500

    original_name = file.filename
    if original_name.endswith(".enc"):
        original_name = original_name[:-4]

    out_path = UPLOAD_DIR / original_name
    out_path.write_bytes(decrypted)

    return send_file(
        out_path,
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/analysis", methods=["POST"])
def api_analysis():
    """Run comparative benchmark: AES-256 vs DES."""
    body = request.get_json(force=True)
    sample = body.get("sample_text", "Benchmark text for CNS project.")
    iterations = min(int(body.get("iterations", 100)), 500)

    aes_key, _ = generate_key("AES")
    des_key, _ = generate_key("DES")

    # AES encrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        aes_ct = encrypt_text(sample, aes_key, "AES")
    aes_enc_ms = (time.perf_counter() - t) / iterations * 1000

    # AES decrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        decrypt_text(aes_ct, aes_key, "AES")
    aes_dec_ms = (time.perf_counter() - t) / iterations * 1000

    # DES encrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        des_ct = encrypt_text(sample, des_key, "DES")
    des_enc_ms = (time.perf_counter() - t) / iterations * 1000

    # DES decrypt benchmark
    t = time.perf_counter()
    for _ in range(iterations):
        decrypt_text(des_ct, des_key, "DES")
    des_dec_ms = (time.perf_counter() - t) / iterations * 1000

    return jsonify({
        "iterations": iterations,
        "sample_length": len(sample),
        "aes": {
            "encrypt_ms": round(aes_enc_ms, 4),
            "decrypt_ms": round(aes_dec_ms, 4),
            "ciphertext_bytes": len(aes_ct),
            "key_bits": 256,
            "block_bits": 128,
        },
        "des": {
            "encrypt_ms": round(des_enc_ms, 4),
            "decrypt_ms": round(des_dec_ms, 4),
            "ciphertext_bytes": len(des_ct),
            "key_bits": 56,
            "block_bits": 64,
        },
    })


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n  CNS Cryptography Web App")
    print("  http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
