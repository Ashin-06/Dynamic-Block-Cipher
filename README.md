# Dynamic Block Cipher

An educational Python implementation of a 32-round, four-branch Generalized Feistel Network, with a desktop interface, file and text commands, and diffusion experiments.

[![Tests](https://github.com/Ashin-06/Dynamic-Block-Cipher/actions/workflows/tests.yml/badge.svg)](https://github.com/Ashin-06/Dynamic-Block-Cipher/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Experimental cryptography: do not use this custom cipher to protect sensitive data.** The audit identified a structural diffusion weakness. Passing round-trip and avalanche tests does not establish security. See [SECURITY.md](SECURITY.md) and [AUDIT.md](AUDIT.md).

## Quick start

Use Python 3.10 or newer. The core library and CLI have no third-party dependencies.

```sh
git clone https://github.com/Ashin-06/Dynamic-Block-Cipher.git
cd Dynamic-Block-Cipher
python gui.py
```

The GUI uses Tkinter (included in many Python distributions; Linux may require your distribution's Tk package). It has text, file, and avalanche tabs, background operations, password visibility controls, and copy output. Text whitespace is preserved; Clear also clears the text password. Only one operation runs at a time.

## Command line

Omit the password to use a hidden prompt. Encryption prompts twice to catch typing errors.

```sh
python cipher.py encrypt report.pdf
python cipher.py decrypt report.pdf.enc -o recovered.pdf
python cipher.py encrypt-str "Hello, world!"
python cipher.py decrypt-str "<hex ciphertext>"
```

Encryption defaults to `input.enc`; decryption defaults to `input.enc.dec`. Existing files are never overwritten. Use `-o` / `--output` to choose a new destination. Completed output is published atomically using a hard link on a compatible local filesystem; unsupported filesystems report an error without falling back to an unsafe write. Files are processed in memory, so this is intended for small educational samples.

String encryption prints only hex for easier scripting. A positional password remains accepted for compatibility, but may appear in shell history or process listings. Errors go to stderr with a nonzero exit code.

## Python API

```python
from cipher import FeistelCipher

with FeistelCipher("ExamplePassword123") as cipher:
    encrypted = cipher.encrypt(b"Hello, world!")
    assert cipher.decrypt(encrypted) == b"Hello, world!"
```

The context manager clears the mutable password buffer. Derived mutable key buffers are cleared on both success and failure. Python does not guarantee complete erasure of secret copies in memory.

## Tests and demonstrations

```sh
python -m unittest discover -v
python demo.py
python avalanche_demo.py --trials 20
python avalanche_demo.py --trials 20 --plot  # optional matplotlib window
```

Tests include legacy ciphertext compatibility, padding boundaries, authentication before decryption, malformed inputs, output collision protection, cleanup on exceptions, CLI prompts, and actual Tk GUI jobs. GUI tests skip if no display is available. The real hybrid exchange test skips when optional native dependencies are missing. CI covers Python 3.10–3.13 on Linux and Windows, including GUI tests with a virtual display on Linux.

## Optional hybrid key exchange

`pq_key_exchange.py` demonstrates ECDH plus ML-KEM-768. It requires `cryptography`, `liboqs-python`, and a compatible native liboqs installation with ML-KEM-768 enabled. Follow the [official liboqs Python installation guide](https://github.com/open-quantum-safe/liboqs-python#installation). This module fails closed when dependencies are missing; it has no simulated fallback. Public keys must be authenticated separately. It is not a complete secure messaging protocol.

## Documentation

- [Usage](USAGE.md): CLI and API behavior
- [Audit](AUDIT.md): findings, fixes, and remaining limitations
- [Security](SECURITY.md): threat model and known design weakness
- [Architecture](ARCHITECTURE.md): educational cipher internals
- [Flow diagrams](FLOWS.md): implementation flow
- [Benchmarks](BENCHMARKS.md): reproducible measurements and interpretation

MIT license. Copyright Ashin-06.
