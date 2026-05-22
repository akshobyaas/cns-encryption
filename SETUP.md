# Setup & Running Instructions

## Prerequisites

- **Python:** 3.8 or higher
- **pip:** Package installer for Python
- **Network:** Internet access (for Bootstrap CDN on first load)

---

## Step 1: Install Dependencies

```bash
cd encryption-toolkit
pip install flask pycryptodome
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

---

## Step 2: Run the Server

```bash
python app.py
```

You will see:

```
  CNS Cryptography Web App
  http://localhost:5000
```

---

## Step 3: Open in Browser

Navigate to:

```
http://localhost:5000
```

If running on a remote server, use the server's IP:

```
http://<server-ip>:5000
```

---

## Step 4: Using the Application

### Text Encryption
1. Go to the **Text** tab
2. Select algorithm (AES-256 or DES)
3. Click **Gen Key** to generate a key (or paste your own hex key)
4. Type your plaintext in the input box
5. Click **Encrypt** → ciphertext appears in output
6. To decrypt: paste ciphertext hex in input, same key, click **Decrypt**

### File Encryption
1. Go to the **File** tab
2. Select algorithm and generate/paste a key
3. Click **Choose File** and select any file
4. Click **Encrypt File** → encrypted `.enc` file downloads
5. To decrypt: upload the `.enc` file with same key, click **Decrypt File**

### Key Generation
1. Go to the **Keys** tab
2. Select algorithm
3. Optionally enter a password (for PBKDF2 derivation)
4. Click **Generate** → key displayed in hex and base64

### Comparative Analysis
1. Go to the **Analysis** tab
2. Enter sample text and iteration count
3. Click **Run** → live benchmark results with metrics table

---

## Stopping the Server

Press `Ctrl+C` in the terminal where the server is running.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: flask` | Run `pip install flask` |
| `ModuleNotFoundError: Crypto` | Run `pip install pycryptodome` |
| Port 5000 in use | Change port in `app.py` last line or use `python app.py` with env var |
| Cannot access from another machine | Ensure firewall allows port 5000 |

---

## Google Colab Usage

```python
# Cell 1: Install
!pip install flask pycryptodome pyngrok

# Cell 2: Run with ngrok tunnel
from pyngrok import ngrok
import threading
# paste app.py content here or upload it
# then:
public_url = ngrok.connect(5000)
print(f"Public URL: {public_url}")
threading.Thread(target=lambda: app.run(port=5000)).start()
```
