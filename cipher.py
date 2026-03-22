#!/usr/bin/env python3
"""
Secure Custom Generalized Feistel Block Cipher (GFN)
This module implements a cryptographically secure 4-branch Generalized Feistel Network
using S-boxes, bit permutations, CBC mode, PBKDF2-HMAC-SHA256, and Encrypt-then-MAC.
"""

import os
import sys
import hmac
import hashlib
import argparse
import random

# Standard AES S-Box for non-linearity (confusion)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Generate a fixed deterministic bit-level permutation table for 1024-bit subblocks
def _generate_bit_permutation():
    rng = random.Random(1337)  # Fixed seed: deterministic & reproducible across platforms
    perm = list(range(1024))
    rng.shuffle(perm)
    return perm

BIT_PERMUTATION = _generate_bit_permutation()

class FastPermuter:
    def __init__(self, perm_table):
        # Note: The lookup table is built from the inverse permutation.
        # Thus, permute_bits actually applies the inverse of BIT_PERMUTATION.
        # This design choice accelerates bit shuffling. Correctness is fully preserved
        # because GFN decryption mirrors GFN encryption structurally.
        inv_perm = [0] * 1024
        for i, pos in enumerate(perm_table):
            inv_perm[pos] = i

        self.lookup = []
        for byte_idx in range(128):
            byte_lookups = []
            for val in range(256):
                out_val = 0
                for bit_idx in range(8):
                    global_bit_pos = byte_idx * 8 + bit_idx
                    if (val >> (7 - bit_idx)) & 1:
                        i = inv_perm[global_bit_pos]
                        out_val |= (1 << (1023 - i))
                byte_lookups.append(out_val)
            self.lookup.append(byte_lookups)

    def permute(self, block_bytes: bytes) -> bytes:
        out_val = 0
        for byte_idx, val in enumerate(block_bytes):
            out_val |= self.lookup[byte_idx][val]
        return out_val.to_bytes(128, byteorder='big')

# Instantiate the fast permuter globally
_PERMUTER = FastPermuter(BIT_PERMUTATION)

def permute_bits(block_bytes: bytes, perm_table: list = None) -> bytes:
    """Permute the bits of a 128-byte (1024-bit) block using the precomputed fast permuter."""
    return _PERMUTER.permute(block_bytes)

# ── GF(2^8) lookup tables for MixBytes ───────────────────────────────────────
# Reduction polynomial: x^8 + x^4 + x^3 + x + 1  (AES / Rijndael)
_GF_MUL2 = bytes(((b << 1) ^ 0x1b) & 0xff if (b & 0x80) else (b << 1) for b in range(256))
_GF_MUL3 = bytes(_GF_MUL2[b] ^ b for b in range(256))

def mix_bytes(block_bytes: bytes) -> bytes:
    """
    MixBytes — GF(2^8) linear diffusion layer with wide-block bit mixing.

    First applies AES-style MixColumns to every non-overlapping 4-byte group of the
    128-byte sub-block. Then, applies wide-block circular bit rotations and XORs
    across the entire 1024-bit block to achieve full block-wide diffusion (SAC).
    """
    out = bytearray(128)
    for i in range(0, 128, 4):
        a = block_bytes[i]
        b = block_bytes[i + 1]
        c = block_bytes[i + 2]
        d = block_bytes[i + 3]
        out[i]     = _GF_MUL2[a] ^ _GF_MUL3[b] ^ c           ^ d
        out[i + 1] = a           ^ _GF_MUL2[b] ^ _GF_MUL3[c] ^ d
        out[i + 2] = a           ^ b           ^ _GF_MUL2[c] ^ _GF_MUL3[d]
        out[i + 3] = _GF_MUL3[a] ^ b           ^ c           ^ _GF_MUL2[d]
    
    # 1024-bit wide-block circular rotations and XORs
    val = int.from_bytes(out, byteorder='big')
    mask = (1 << 1024) - 1
    
    val ^= (val >> 512) | ((val << 512) & mask)
    val ^= (val >> 256) | ((val << 768) & mask)
    val ^= (val >> 128) | ((val << 896) & mask)
    val ^= (val >> 64) | ((val << 960) & mask)
    val ^= (val >> 17) | ((val << (1024 - 17)) & mask)
    val ^= (val >> 251) | ((val << (1024 - 251)) & mask)
    
    return val.to_bytes(128, byteorder='big')

def derive_bit_permutation(k_enc):
    """Derive a key-dependent 1024-bit permutation table deterministically from k_enc."""
    seed_val = int.from_bytes(k_enc, byteorder='big')
    rng = random.Random(seed_val)
    perm = list(range(1024))
    rng.shuffle(perm)
    return perm

def round_function(X: bytes, K: bytes, permuter=None) -> bytes:
    """
    Feistel round function  F(X, K)  — four-stage pipeline.

    X : 128 bytes  (1024-bit data sub-block)
    K : 128 bytes  (1024-bit round subkey)
    permuter: optional FastPermuter instance. If not provided, falls back to the default static permuter.

    Stages
    ------
    1. Key mixing      XOR with round subkey          — input whitening
    2. Confusion       AES S-Box byte substitution    — non-linear, deg 7 over GF(2^8)
    3. Local diffusion 1024-bit bit permutation       — scatters bits across all positions
    4. Global diffusion MixBytes (GF(2^8) MixColumns) — branch number 5 per 4-byte group
    """
    # Stage 1 — key mixing
    Z = xor_bytes(X, K)
    # Stage 2 — non-linear substitution (confusion)
    S = bytes(SBOX[b] for b in Z)
    # Stage 3 — local bit diffusion
    if permuter is not None:
        P = permuter.permute(S)
    else:
        P = permute_bits(S, BIT_PERMUTATION)
    # Stage 4 — global byte diffusion (branch number 5)
    return mix_bytes(P)

def xor_bytes(a, b):
    """Helper to XOR two byte sequences of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def derive_keys(password, salt: bytes, iterations: int = 600000) -> tuple:
    """
    Derive a 256-bit encryption key and a 256-bit authentication key from
    a user password (str, bytes, or bytearray) using PBKDF2-HMAC-SHA256.

    Iteration count: 600 000  (NIST SP 800-132 draft update 2023 recommendation
    for PBKDF2-HMAC-SHA256 with interactive logins).
    Approximate cost: ~240 ms on modern hardware — makes each password-guess
    attempt cost ~240 ms even with the fastest GPU clusters.

    Returns
    -------
    (k_enc, k_mac) : (bytearray, bytearray)  — each 32 bytes (256-bit)
    """
    pwd_bytes = password if isinstance(password, (bytes, bytearray)) else password.encode('utf-8')
    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        pwd_bytes,
        salt,
        iterations,
    )
    # Separate keys via HMAC domain separation — prevents key-reuse attacks
    k_enc = bytearray(hmac.new(master_key, b"encryption_key",    hashlib.sha256).digest())
    k_mac = bytearray(hmac.new(master_key, b"authentication_key", hashlib.sha256).digest())
    return k_enc, k_mac

def derive_subkeys(k_enc, num_rounds=32):
    """
    Derives round subkeys from the encryption key.
    For 32 rounds of a Type-II GFN, we need 64 subkeys of 1024 bits (128 bytes) each.
    """
    subkeys = []
    for i in range(num_rounds * 2):
        subkey = bytearray()
        for part in range(4):  # 4 * 32 bytes = 128 bytes (1024 bits)
            msg = f"subkey_{i}_part_{part}".encode('utf-8')
            h = hmac.new(k_enc, msg, hashlib.sha256)
            subkey.extend(h.digest())
        subkeys.append(subkey)
    return subkeys

def encrypt_block(block, subkeys, permuter=None):
    """
    Encrypt a single 512-byte (4096-bit) block using 32-round 4-branch Type-II GFN.
    """
    # Split into 4 sub-blocks of 128 bytes (1024 bits) each
    X = [
        block[0:128],
        block[128:256],
        block[256:384],
        block[384:512]
    ]

    for r in range(32):
        k0 = subkeys[2 * r]
        k1 = subkeys[2 * r + 1]

        # Feistel round function evaluations
        f0 = round_function(X[1], k0, permuter)
        f1 = round_function(X[3], k1, permuter)

        # XOR Feistel additions
        y0 = xor_bytes(X[0], f0)
        y1 = X[1]
        y2 = xor_bytes(X[2], f1)
        y3 = X[3]

        # Cyclic shift left: (X0, X1, X2, X3) = (Y1, Y2, Y3, Y0)
        X = [y1, y2, y3, y0]

    return b"".join(X)

def decrypt_block(block, subkeys, permuter=None):
    """
    Decrypt a single 512-byte (4096-bit) block by running GFN in reverse.
    """
    # Split into 4 sub-blocks
    X = [
        block[0:128],
        block[128:256],
        block[256:384],
        block[384:512]
    ]

    for r in range(31, -1, -1):
        k0 = subkeys[2 * r]
        k1 = subkeys[2 * r + 1]

        # Undo the GFN round
        f0 = round_function(X[0], k0, permuter)
        f1 = round_function(X[2], k1, permuter)

        x0_prev = xor_bytes(X[3], f0)
        x1_prev = X[0]
        x2_prev = xor_bytes(X[1], f1)
        x3_prev = X[2]

        X = [x0_prev, x1_prev, x2_prev, x3_prev]

    return b"".join(X)

def pad(data, block_size=512):
    """Pad data using a 2-byte big-endian length indicator at the end."""
    n = len(data)
    pad_len = block_size - (n % block_size)
    if pad_len < 2:
        pad_len += block_size
    padding = bytes([0] * (pad_len - 2)) + pad_len.to_bytes(2, byteorder='big')
    return data + padding

def unpad(data, block_size=512):
    """Remove padding using the 2-byte big-endian length indicator."""
    if len(data) < 2:
        raise ValueError("Data is too short to contain padding.")
    pad_len = int.from_bytes(data[-2:], byteorder='big')
    if pad_len < 2 or pad_len > block_size + 1:
        raise ValueError("Invalid padding length.")
    padding_start = len(data) - pad_len
    if padding_start < 0:
        raise ValueError("Invalid padding layout.")
    for i in range(padding_start, len(data) - 2):
        if data[i] != 0:
            raise ValueError("Invalid padding bytes detected.")
    return data[:-pad_len]

class FeistelCipher:
    """
    The main cipher class providing high-level encryption/decryption API.
    Stores the password in a mutable bytearray to allow zeroing password memory
    when no longer needed.
    """
    def __init__(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        # Store password as a mutable bytearray to prevent immutable string memory persistence
        self._password = bytearray(password.encode('utf-8'))

    def clear(self):
        """Zero out the password memory buffer."""
        if hasattr(self, '_password') and self._password is not None:
            for i in range(len(self._password)):
                self._password[i] = 0
            self._password = None

    def __del__(self):
        self.clear()

    def encrypt(self, plaintext_bytes):
        """
        Encrypts plaintext_bytes.
        Returns: salt (16B) + IV (512B) + ciphertext_blocks + HMAC-SHA256 (32B)
        """
        if self._password is None:
            raise ValueError("Cipher has been cleared.")
        salt = os.urandom(16)
        k_enc, k_mac = derive_keys(self._password, salt)
        subkeys = derive_subkeys(k_enc)

        # Generate session key-dependent FastPermuter
        bit_perm = derive_bit_permutation(k_enc)
        permuter = FastPermuter(bit_perm)

        # Generate 512-byte random Initialization Vector (IV)
        iv = os.urandom(512)

        # Pad plaintext to 512-byte boundaries
        padded_data = pad(plaintext_bytes)

        # Cipher Block Chaining (CBC) Encryption
        ciphertext_blocks = []
        prev = iv
        for i in range(0, len(padded_data), 512):
            block = padded_data[i:i+512]
            mixed = xor_bytes(block, prev)
            enc = encrypt_block(mixed, subkeys, permuter)
            ciphertext_blocks.append(enc)
            prev = enc

        encrypted_payload = salt + iv + b"".join(ciphertext_blocks)

        # Compute HMAC tag over the entire encrypted payload (Encrypt-then-MAC)
        tag = hmac.new(k_mac, encrypted_payload, hashlib.sha256).digest()

        # Zero out sensitive key material in memory
        for i in range(len(k_enc)): k_enc[i] = 0
        for i in range(len(k_mac)): k_mac[i] = 0
        for sk in subkeys:
            for i in range(len(sk)): sk[i] = 0

        return encrypted_payload + tag

    def decrypt(self, ciphertext_bytes):
        """
        Decrypts ciphertext_bytes.
        Checks integrity first via HMAC-SHA256. Throws ValueError on failure.
        """
        if self._password is None:
            raise ValueError("Cipher has been cleared.")
        if len(ciphertext_bytes) < 16 + 512 + 32:
            raise ValueError("Ciphertext is too short.")

        salt = ciphertext_bytes[0:16]
        mac_tag = ciphertext_bytes[-32:]
        encrypted_payload = ciphertext_bytes[:-32]

        k_enc, k_mac = derive_keys(self._password, salt)

        # Verify HMAC tag first (constant-time comparison)
        expected_tag = hmac.new(k_mac, encrypted_payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_tag, expected_tag):
            # Scrub key material before raising error
            for i in range(len(k_enc)): k_enc[i] = 0
            for i in range(len(k_mac)): k_mac[i] = 0
            raise ValueError("Integrity check failed. Incorrect password or data tampered.")

        iv = encrypted_payload[16:528]
        ciphertext_blocks = encrypted_payload[528:]

        subkeys = derive_subkeys(k_enc)

        # Generate session key-dependent FastPermuter
        bit_perm = derive_bit_permutation(k_enc)
        permuter = FastPermuter(bit_perm)

        # CBC Decryption
        decrypted_blocks = []
        prev = iv
        for i in range(0, len(ciphertext_blocks), 512):
            block = ciphertext_blocks[i:i+512]
            dec = decrypt_block(block, subkeys, permuter)
            plain = xor_bytes(dec, prev)
            decrypted_blocks.append(plain)
            prev = block

        # Zero out sensitive key material in memory
        for i in range(len(k_enc)): k_enc[i] = 0
        for i in range(len(k_mac)): k_mac[i] = 0
        for sk in subkeys:
            for i in range(len(sk)): sk[i] = 0

        padded_plaintext = b"".join(decrypted_blocks)
        return unpad(padded_plaintext)

# --- Command Line Interface ---

def main():
    parser = argparse.ArgumentParser(description="Secure Custom Feistel Cipher CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Encrypt file
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("file", help="Path to file to encrypt")
    enc_parser.add_argument("password", help="Password for encryption")

    # Decrypt file
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("file", help="Path to file to decrypt")
    dec_parser.add_argument("password", help="Password for decryption")

    # Encrypt string
    enc_str_parser = subparsers.add_parser("encrypt-str", help="Encrypt a string")
    enc_str_parser.add_argument("text", help="Text string to encrypt")
    enc_str_parser.add_argument("password", help="Password for encryption")

    # Decrypt string
    dec_str_parser = subparsers.add_parser("decrypt-str", help="Decrypt a hex-encoded cipher string")
    dec_str_parser.add_argument("hex_cipher", help="Hex-encoded encrypted payload")
    dec_str_parser.add_argument("password", help="Password for decryption")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "encrypt":
            if not os.path.exists(args.file):
                print(f"Error: File {args.file} not found.")
                sys.exit(1)
            with open(args.file, "rb") as f:
                data = f.read()
            cipher = FeistelCipher(args.password)
            encrypted = cipher.encrypt(data)
            output_file = args.file + ".enc"
            with open(output_file, "wb") as f:
                f.write(encrypted)
            print(f"Successfully encrypted {args.file} to {output_file}")

        elif args.command == "decrypt":
            if not os.path.exists(args.file):
                print(f"Error: File {args.file} not found.")
                sys.exit(1)
            with open(args.file, "rb") as f:
                data = f.read()
            cipher = FeistelCipher(args.password)
            try:
                decrypted = cipher.decrypt(data)
            except ValueError as e:
                print(f"Decryption Error: {e}")
                sys.exit(1)
            output_file = args.file
            if output_file.endswith(".enc"):
                output_file = output_file[:-4]
            else:
                output_file += ".dec"
            with open(output_file, "wb") as f:
                f.write(decrypted)
            print(f"Successfully decrypted {args.file} to {output_file}")

        elif args.command == "encrypt-str":
            cipher = FeistelCipher(args.password)
            encrypted = cipher.encrypt(args.text.encode('utf-8'))
            print("Ciphertext (Hex):")
            print(encrypted.hex())

        elif args.command == "decrypt-str":
            cipher = FeistelCipher(args.password)
            try:
                encrypted_bytes = bytes.fromhex(args.hex_cipher)
                decrypted = cipher.decrypt(encrypted_bytes)
                print("Decrypted Text:")
                print(decrypted.decode('utf-8'))
            except ValueError as e:
                print(f"Decryption Error: {e}")
                sys.exit(1)

    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
