# CNS Cryptography Web Application

## Symmetric-Key Encryption: AES-256 & DES

**Course:** Cryptography and Network Security (6th Semester)  
**Type:** Peer-Supported Independent Study (PSIS)  
**Stack:** Python Flask + pycryptodome + Bootstrap 5

---

## Overview

A fully functional web application that implements and compares **AES-256** and **DES** symmetric-key encryption algorithms. Features include text encryption/decryption, file encryption/decryption, secure key generation, and a live comparative performance analysis dashboard.

### Features

| Feature | Description |
|---------|-------------|
| **Text Encrypt/Decrypt** | AES-256 or DES with hex key input, real-time timing |
| **File Encrypt/Decrypt** | Upload any file, download encrypted/decrypted result |
| **Key Generation** | Random or password-derived (PBKDF2-SHA256, 100K iterations) |
| **Comparative Analysis** | Live benchmark: AES vs DES speed, size, security metrics |
| **Modern UI** | Dark-themed Bootstrap 5 responsive interface |

---

## Project Structure

```
CNS/
├── app.py                  # Flask backend (REST API + crypto logic)
├── templates/
│   └── index.html          # Single-page frontend (Bootstrap 5 + vanilla JS)
├── static/                 # (empty, assets served via CDN)
├── README.md               # This file
├── SETUP.md                # Step-by-step running instructions
└── requirements.txt        # Python dependencies
```

---

## Quick Start

```bash
pip install flask pycryptodome
python app.py
# Open http://localhost:5000
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.8+, Flask |
| Cryptography | pycryptodome (AES, DES, PBKDF2) |
| Frontend | HTML5, Bootstrap 5.3, Bootstrap Icons |
| API | RESTful JSON endpoints |
| Deployment | Single-file Flask server |

---

## Cryptographic Details

### AES-256 Configuration
- **Key Size:** 256 bits (32 bytes)
- **Block Size:** 128 bits (16 bytes)
- **Mode:** CBC (Cipher Block Chaining)
- **Padding:** PKCS7
- **IV:** 16 bytes, cryptographically random, prepended to ciphertext

### DES Configuration (Educational)
- **Key Size:** 56 bits effective (8 bytes)
- **Block Size:** 64 bits (8 bytes)
- **Mode:** CBC
- **Padding:** PKCS7
- **IV:** 8 bytes, random, prepended to ciphertext

### Key Derivation (PBKDF2)
- **Hash:** SHA-256
- **Iterations:** 100,000
- **Salt:** Random (16 bytes AES / 8 bytes DES)

---

## API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Serve web UI |
| `/api/generate-key` | POST | Generate random or password-derived key |
| `/api/encrypt-text` | POST | Encrypt plaintext string |
| `/api/decrypt-text` | POST | Decrypt ciphertext hex string |
| `/api/encrypt-file` | POST | Encrypt uploaded file (returns .enc download) |
| `/api/decrypt-file` | POST | Decrypt uploaded .enc file |
| `/api/analysis` | POST | Run AES vs DES benchmark |

---

## License

Educational project for CNS 6th-semester curriculum.  
Uses pycryptodome (BSD license) and Flask (BSD license).
