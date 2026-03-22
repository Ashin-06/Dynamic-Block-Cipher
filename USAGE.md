# Working & Usage Guide

This document provides a guide on how to integrate, deploy, run, and test the Dynamic Block Cipher (Secure GFN v2) in various environments.

---

## 1. Installation

The library is written in pure Python 3 and has **zero third-party dependencies**. It only requires Python 3.8 or higher.

### Step 1: Clone the repository
```bash
git clone https://github.com/Ashin-06/Dynamic-Block-Cipher.git
cd Dynamic-Block-Cipher
```

### Step 2: Verify environment
Make sure python is on your path:
```bash
python --version
```

---

## 2. Desktop GUI

The library includes a professional, dark-themed Tkinter GUI. Since Tkinter is bundled with standard Python distributions, no extra packages need to be installed.

Run the GUI using:
```bash
python gui.py
```

### Interface Features:
1. **Text Cipher Tab:** Encrypt or decrypt plain text messages directly in the UI. Displays key derivation latency, ciphertext sizes, and output formatting.
2. **File Cipher Tab:** Securely encrypt or decrypt local files of any size (documents, archives, media). Includes real-time progress logging and file save pickers.
3. **Avalanche Effect Tab:** Click the test run button to run a simulated single-bit mutation test and render an interactive canvas showing bit propagation across all 32 rounds.

---

## 3. Command Line Interface (CLI)

The core script `cipher.py` doubles as a command-line interface.

### 3.1 Encrypting / Decrypting a Text String
To encrypt a string, pass the `encrypt-str` action, followed by your message and a password (minimum 8 characters):
```bash
python cipher.py encrypt-str "This is my secret message" "MyStrongPassword123"
```
*Outputs a hexadecimal representation of the encrypted payload.*

To decrypt, copy the hexadecimal string and run:
```bash
python cipher.py decrypt-str "<hex_ciphertext>" "MyStrongPassword123"
```
*Outputs the original decrypted text message.*

### 3.2 Encrypting / Decrypting a File
To encrypt any local file (e.g., `document.pdf`):
```bash
python cipher.py encrypt document.pdf "MyStrongPassword123"
```
*Creates an encrypted file named `document.pdf.enc`.*

To decrypt the file back:
```bash
python cipher.py decrypt document.pdf.enc "MyStrongPassword123"
```
*Restores the file as `document.pdf` (or `document.pdf.dec` if the original file still exists in the directory to prevent overwriting).*

---

## 4. Python API Usage

To integrate the cipher directly into your Python application, import the `FeistelCipher` class from `cipher.py`.

```python
from cipher import FeistelCipher

# 1. Initialize the cipher with a password (must be at least 8 characters)
password = "MySuperSecretPassword99"
cipher = FeistelCipher(password)

# 2. Encrypt bytes payload
plaintext = b"Confidential data payload..."
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted payload: {ciphertext.hex()[:64]}...")

# 3. Decrypt bytes payload (integrity is verified via HMAC tag)
try:
    decrypted = cipher.decrypt(ciphertext)
    assert decrypted == plaintext
    print("Decryption successful, integrity verified!")
except ValueError as e:
    print(f"Decryption or integrity verification failed: {e}")
```

---

## 5. Verification Demos

Two demo files are provided to show the cipher in action and log internal states:

### 5.1 Comprehensive Verification Demo
Run `demo.py` to trace correct GFN round calculations, verify the Encrypt-then-MAC integrity protections, test password rejection logic, and see a full summary of active cipher features:
```bash
python demo.py
```

### 5.2 ASCII Avalanche Effect Demo
Run `avalanche_demo.py` to see a detailed ASCII chart showing bit-flipping percentages round-by-round (visualizing the Strict Avalanche Criterion):
```bash
python avalanche_demo.py
```

### 5.3 Hybrid Post-Quantum Key Agreement Demo
Run `pq_key_exchange.py` to demonstrate establishing a shared symmetric key using a hybrid combination of ML-KEM-768 (Kyber768, FIPS 203) and standard classical ECDH (secp256r1):
```bash
python pq_key_exchange.py
```

---

## 6. Automated Unit Tests

The codebase comes with a complete test suite verifying 13 distinct correctness, security, padding, and avalanche assertions:
```bash
python -m unittest test_cipher.py -v
```
*Outputs confirmation of all passing test cases.*
