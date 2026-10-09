# Security status

This repository is an educational custom cipher, not a reviewed or standardized encryption system. No classical or post-quantum security level is established. Previous claims of production readiness, NIST security-category compliance, GPU cracking costs, and guaranteed SAC were unsupported and have been withdrawn.

## Known structural weakness: repeated round-function output

`mix_bytes` applies sequential operations of the form `v ^= rotate(v, n)`. The first rotation is 512 bits on a 1024-bit value. This makes the two 512-bit halves identical. Subsequent rotations of 256, 128, and 64 bits reduce the period to 64 bits. The remaining rotations preserve that period. Consequently the 128-byte result consists of the same 8-byte value repeated 16 times; its image has dimension at most 64 bits.

This also imposes a block-cipher invariant: each Feistel XOR adds the same 8-byte mask to every 8-byte segment of a branch. Pairwise XOR differences between those segments survive the addition. After 32 branch rotations, each branch returns to its original position. Good average Hamming distance can coexist with this strong structure.

The regression suite records this limitation explicitly. The round transform remains unchanged so existing encrypted samples remain readable. Repair requires a separately versioned format and design review; silently changing the transform would make existing ciphertext unreadable. Do not interpret compatibility retention as acceptance of this design for sensitive use.

## Implemented defenses and their limits

- Encrypt-then-MAC authenticates salt, IV, and ciphertext before block decryption. Invalid ciphertext lengths are rejected before password derivation.
- PBKDF2-HMAC-SHA256 uses 600,000 iterations and a random 16-byte salt. A 256-bit derived output does not give a human password 256 bits of entropy. Guessing costs depend on attacker hardware and implementation.
- The wrapper uses a random 512-byte IV and HMAC-SHA256. This does not repair weaknesses in the underlying custom block cipher.
- Tag comparison uses `hmac.compare_digest`. The Python implementation as a whole is not constant-time; S-box/permutation lookups and other operations may leak information.
- Mutable passwords and derived keys are cleared on normal and exceptional paths. Immutable objects, runtime copies, swap, dumps, and key-dependent permutation tables are not reliably erased.
- File output never replaces an existing destination, and a complete temporary file is published atomically. Filesystem hard-link support is required. Data and encrypted output are held in memory; arbitrarily large or hostile inputs can exhaust resources.
- The legacy ciphertext has no magic header, version, or encoded KDF parameters. Its format and default KDF parameters must remain stable for compatibility.

## Hybrid exchange

The optional example uses ECDH over secp256r1 plus ML-KEM-768 and HKDF-style extraction/expansion. Both real backends are required. Historical Kyber and standardized ML-KEM names are not interchangeable protocol identifiers.

The example has no peer identity authentication, transcript binding, replay protection, or session protocol. It does not prevent an active attacker replacing public keys. Using a hybrid shared secret with this custom cipher does not repair the cipher's structural weakness. Native backend availability and behavior must be tested in the deployment environment.

## Reporting

Provide a minimal reproducer and affected revision when reporting a defect. Never include real passwords, private keys, or sensitive ciphertext in a public issue. Review [AUDIT.md](AUDIT.md) for the scope and limits of the current implementation audit.
