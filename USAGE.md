# Usage guide

See [README.md](README.md) for setup and [SECURITY.md](SECURITY.md) before using the experimental cipher.

## Files

```sh
python cipher.py encrypt sample.bin
python cipher.py decrypt sample.bin.enc -o recovered.bin
```

Passwords are entered at hidden prompts; encryption asks for confirmation. Output paths must be new. Without `--output`, encryption appends `.enc` and decryption appends `.dec` to the entire input name. No source file is removed or replaced. A failed authentication creates no decrypted output. Hard-link support on the destination filesystem is required for atomic publication.

## Text

```sh
python cipher.py encrypt-str "  whitespace is preserved  "
python cipher.py decrypt-str "<hex output>"
```

Encryption writes a single hex string to stdout. Decryption prints UTF-8 text. Malformed hex, invalid UTF-8, short passwords, and authentication failures produce a nonzero exit code and an error on stderr. Positional passwords remain supported, but hidden prompts avoid putting passwords into command history.

## Desktop

```sh
python gui.py
```

Text Cipher accepts plaintext or hex ciphertext. Copy preserves leading/trailing whitespace. Clear resets text, output, and password. File Cipher accepts a file path and writes a new `.enc` or `.dec` sibling. Existing output is refused; choose another source location or use the CLI's custom output option. Avalanche Effect plots sample bit differences. One background job runs at a time and all widget updates are dispatched on the main UI thread.

## API

```python
from cipher import FeistelCipher

with FeistelCipher("ExamplePassword123") as cipher:
    ciphertext = cipher.encrypt(b"sample")
    plaintext = cipher.decrypt(ciphertext)
```

Operations after `clear()` or context exit raise `ValueError`. Empty byte strings and arbitrary binary payloads are supported by the library. Complete inputs and outputs are kept in memory.

## Checks

```sh
python -m unittest discover -v
python demo.py
python avalanche_demo.py --trials 5
python pq_key_exchange.py
```

The hybrid demo exits with an explanatory error unless the optional cryptography and native liboqs dependencies are installed. Test skips are reported explicitly; they are not successful integration results.
