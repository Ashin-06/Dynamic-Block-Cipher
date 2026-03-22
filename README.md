# Dynamic Block Cipher — Secure GFN v2

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Verified-brightgreen)](#features)
[![Tests](https://img.shields.io/badge/Tests-13%20Passing-brightgreen)](#testing)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None%20(stdlib%20only)-lightgrey)](#installation)
[![PQ Security](https://img.shields.io/badge/Post--Quantum-128--bit%20(NIST%20Cat.1)-blueviolet)](SECURITY.md)

A professional-grade custom symmetric block cipher built on a **4-branch Type-II Generalized Feistel Network (GFN)**. It implements state-of-the-art cryptographic design patterns to ensure confidentiality, integrity, and performance.

---

## Documentation Index

For detailed descriptions of the cipher design, internals, and operations, refer to the following documents:
* 📘 **[Architecture Specification](ARCHITECTURE.md)** — Detailed block cipher architecture, confusion/diffusion layers, and key derivation.
* 📊 **[Flow Diagrams](FLOWS.md)** — Interactive Mermaid diagrams showing data flows, subkey counter loops, and GFN branch transformations.
* ⚡ **[Performance & Security Benchmarks](BENCHMARKS.md)** — Empirical block throughput, password cracking cost estimations, and avalanche statistics.
* 💻 **[Working & Usage Guide](USAGE.md)** — Comprehensive installation and usage manuals for GUI, CLI, and Python API.
* 🛡️ **[Security Analysis](SECURITY.md)** — Core pre-quantum and post-quantum threat analysis.

---

## Architecture

```
Password  ──►  PBKDF2-HMAC-SHA256 (600 000 iters, random 16-byte salt)
                        │
                   Master Key (256-bit)
                   ┌────┴────┐
               k_enc        k_mac
                 │              │
          HMAC-SHA256        HMAC-SHA256
          key schedule       (auth tag)
          (64 subkeys,
           1024-bit each)
                 │
   ┌─────────────▼─────────────────────────────────┐
   │  4-Branch Type-II GFN  ×  32 rounds           │
   │  Block size: 4096-bit (512 bytes)              │
   │  Round function F(X, K):                       │
   │    1. XOR sub-block with round subkey          │
   │    2. AES S-Box substitution  (confusion)      │
   │    3. 1024-bit permutation    (diffusion)      │
   │  Mode: CBC with random 512-byte IV             │
   └─────────────────────────────────────────────────┘
                 │
         Ciphertext payload
                 │
   Encrypt-then-MAC  (HMAC-SHA256, constant-time verify)
```

---

## Key Features

* **High-Security Key Derivation:** Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST standard compliant) and a cryptographically secure random 16-byte salt to derive keys from passwords.
* **Hardened 4-Branch GFN:** A 32-round Generalized Feistel Network incorporating the standard Rijndael (AES) S-Box for non-linearity (confusion) and a deterministic 1024-bit permutation table.
* **Advanced Linear Diffusion:** Incorporates `MixBytes` (column-wise MixColumns over GF(2⁸) with branch number 5) and 1024-bit circular bit-rotations to satisfy the Strict Avalanche Criterion (SAC) in a single round.
* **Authenticated Chaining Mode:** Operates in CBC (Cipher Chaining) mode with a cryptographically secure 512-byte random IV. Protected by an **Encrypt-then-MAC** authentication wrapper using HMAC-SHA256 with constant-time comparison to prevent timing and padding oracle attacks.
* **Zero Dependencies:** Written entirely in pure Python using only standard library modules.

---

## File Layout

```
├── cipher.py          # Core cipher library + CLI
├── gui.py             # Desktop GUI (tkinter — no install needed)
├── demo.py            # Interactive feature demonstration (CLI)
├── avalanche_demo.py  # Round-by-round bit diffusion chart (CLI)
├── pq_key_exchange.py # Hybrid Post-Quantum Key Agreement (KEM)
├── test_cipher.py     # 13 automated unit tests
├── ARCHITECTURE.md    # Detailed block cipher architecture & designs
├── FLOWS.md           # Visual execution flows (Mermaid diagrams)
├── BENCHMARKS.md      # Performance & post-quantum security metrics
├── USAGE.md           # Working guide and usage manual
├── SECURITY.md        # Pre-quantum & post-quantum analysis
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/Ashin-06/Dynamic-Block-Cipher.git
cd Dynamic-Block-Cipher
```

---

## Usage

### Desktop GUI
```bash
python gui.py
```
Provides three interactive tabs: **Text Cipher**, **File Cipher**, and **Avalanche Effect**.

### CLI — encrypt / decrypt a string
```bash
python cipher.py encrypt-str "Your secret message" "YourPassword123"
# Copy the hex output, then:
python cipher.py decrypt-str "<hex>" "YourPassword123"
```

### CLI — encrypt / decrypt a file
```bash
python cipher.py encrypt  report.pdf    "YourPassword123"
python cipher.py decrypt  report.pdf.enc "YourPassword123"
```

### Library usage
```python
from cipher import FeistelCipher

c = FeistelCipher("YourPassword123")          # min 8 chars
ciphertext = c.encrypt(b"Hello, World!")
plaintext  = c.decrypt(ciphertext)
assert plaintext == b"Hello, World!"
```

---

## Testing

Run the automated test suite to verify implementation correctness:
```bash
python -m unittest test_cipher.py -v
```

```
test_avalanche_key              ... ok
test_avalanche_plaintext        ... ok
test_ciphertext_tampering       ... ok
test_exact_block_boundary       ... ok
test_non_deterministic_encryption ... ok
test_padding_validation         ... ok
test_roundtrip_binary_data      ... ok
test_roundtrip_empty_input      ... ok
test_roundtrip_long_string      ... ok
test_roundtrip_short_string     ... ok
test_sac_round_function         ... ok
test_weak_password_rejected     ... ok
test_wrong_password             ... ok

Ran 13 tests in 5.4s  OK
```

### Demos
```bash
python demo.py            # Comprehensive verification of all cryptographic primitives
python avalanche_demo.py  # Run and plot bit-propagation metrics over 32 rounds
```

---

## License

MIT © Ashin-06
