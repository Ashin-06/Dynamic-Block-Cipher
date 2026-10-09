# Cipher architecture

This document describes the implemented legacy format. It is an educational design with a known structural weakness; see [SECURITY.md](SECURITY.md). It is not a security specification for production use.

## Key derivation

PBKDF2-HMAC-SHA256 derives a 32-byte master value from the UTF-8 password, a random 16-byte salt, and 600,000 iterations. Two separate HMAC-SHA256 calls derive 32-byte keys using the exact labels `encryption_key` and `authentication_key`. The master value is not split into two 16-byte halves.

The encryption key generates 64 round subkeys. Each 128-byte subkey concatenates four HMAC-SHA256 outputs with UTF-8 labels `subkey_{i}_part_{part}` for parts 0–3. A key-seeded `random.Random` shuffle produces the session permutation. This is a deterministic educational construction, not a cryptographic PRNG claim.

## Block transform

Each 512-byte block is divided into four 128-byte branches. For each of 32 rounds:

1. Apply the round function to branches 1 and 3 with the two round subkeys.
2. XOR the results into branches 0 and 2.
3. Rotate the branches one place left.

Decryption reverses these operations. The round function XORs its input with the subkey, substitutes bytes through the AES S-box, permutes 1024 bits, and applies `mix_bytes`.

`FastPermuter` maps an input bit at position `perm_table[i]` to output position `i`. The default helper uses the fixed seed-1337 table; high-level encryption builds a session table from the derived encryption key.

`mix_bytes` first applies AES-style MixColumns to consecutive groups of four bytes. It then sequentially XORs the entire 1024-bit value with right rotations of 512, 256, 128, 64, 17, and 251 bits. This sequence collapses the result to a repeated 64-bit pattern. It does not establish the Strict Avalanche Criterion. Existing ciphertext compatibility requires retaining this legacy transform.

## Padding and authenticated envelope

Padding appends zero bytes followed by a two-byte big-endian total padding length. The length is 2–513 bytes for 512-byte blocks. A 511-byte message needs 513 padding bytes. This is custom padding, not PKCS#7.

The envelope is:

```
salt (16 bytes) | IV (512 bytes) | CBC ciphertext (N * 512 bytes) | tag (32 bytes)
```

At least one ciphertext block is required; minimum size is 1072 bytes. HMAC-SHA256 covers salt, IV, and ciphertext. Decryption checks length/alignment, derives keys, verifies the tag with `compare_digest`, then decrypts and validates padding. There is no format version or stored KDF iteration count.

## Application behavior

The context manager clears its mutable password copy at exit. Derived mutable buffers are cleared in `finally` blocks. Python does not guarantee secure erasure of every secret copy.

CLI and GUI output is written to a temporary file in the destination directory, flushed, then published with a no-replace hard link. Existing destinations are never overwritten. This requires filesystem hard-link support and processes whole inputs in memory.

GUI workers publish callback requests to a queue. A recurring main-thread callback updates Tk widgets. A busy guard serializes operations and the polling timer is cancelled when the window is destroyed.

The optional ECDH/ML-KEM-768 example requires real native backends. It is an unauthenticated demonstration, not a complete secure channel.
