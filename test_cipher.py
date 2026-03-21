import unittest
import os
import random
from cipher import FeistelCipher, pad, unpad, derive_keys, derive_subkeys, \
                   round_function, xor_bytes

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers shared across tests
# ─────────────────────────────────────────────────────────────────────────────
def _hamming(b1: bytes, b2: bytes) -> int:
    """Count differing bits between two equal-length byte sequences."""
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def _get_round_states(block: bytes, subkeys: list) -> list:
    """Run the GFN forward and capture the full 512-byte state after every round."""
    X = [block[i * 128:(i + 1) * 128] for i in range(4)]
    states = [b"".join(X)]
    for r in range(32):
        k0, k1 = subkeys[2 * r], subkeys[2 * r + 1]
        f0 = round_function(X[1], k0)
        f1 = round_function(X[3], k1)
        y0 = xor_bytes(X[0], f0)
        y2 = xor_bytes(X[2], f1)
        X = [X[1], y2, X[3], y0]
        states.append(b"".join(X))
    return states


# ─────────────────────────────────────────────────────────────────────────────
#  Test cases
# ─────────────────────────────────────────────────────────────────────────────
class TestFeistelCipher(unittest.TestCase):

    def setUp(self):
        self.password = "MySecurePassword123"  # must be ≥ 8 chars
        self.cipher   = FeistelCipher(self.password)

    # ── Correctness ───────────────────────────────────────────────────────────

    def test_roundtrip_short_string(self):
        plaintext = b"Hello, World! This is a secure 4-branch Feistel Network."
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(plaintext)), plaintext)

    def test_roundtrip_empty_input(self):
        plaintext = b""
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(plaintext)), plaintext)

    def test_roundtrip_long_string(self):
        plaintext = b"A" * 2000 + b"B" * 50 + b"C" * 200
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(plaintext)), plaintext)

    def test_roundtrip_binary_data(self):
        plaintext = os.urandom(1024)
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(plaintext)), plaintext)

    def test_exact_block_boundary(self):
        # 512 bytes = one full block — padding must produce a second block
        plaintext = b"Z" * 512
        self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(plaintext)), plaintext)

    # ── Password enforcement ───────────────────────────────────────────────────

    def test_weak_password_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            FeistelCipher("short")
        self.assertIn("8 characters", str(ctx.exception))

    # ── Authentication ─────────────────────────────────────────────────────────

    def test_wrong_password(self):
        ciphertext = self.cipher.encrypt(b"Sensitive information!")
        wrong = FeistelCipher("WrongPassword!")
        with self.assertRaises(ValueError) as ctx:
            wrong.decrypt(ciphertext)
        self.assertIn("Integrity check failed", str(ctx.exception))

    def test_ciphertext_tampering(self):
        ciphertext = bytearray(self.cipher.encrypt(b"Super secret data."))
        ciphertext[600] ^= 0x01
        with self.assertRaises(ValueError) as ctx:
            self.cipher.decrypt(bytes(ciphertext))
        self.assertIn("Integrity check failed", str(ctx.exception))

    # ── Non-determinism ────────────────────────────────────────────────────────

    def test_non_deterministic_encryption(self):
        plaintext = b"Same plaintext encrypted twice."
        c1 = self.cipher.encrypt(plaintext)
        c2 = self.cipher.encrypt(plaintext)
        self.assertNotEqual(c1, c2)
        self.assertEqual(self.cipher.decrypt(c1), plaintext)
        self.assertEqual(self.cipher.decrypt(c2), plaintext)

    # ── Padding ────────────────────────────────────────────────────────────────

    def test_padding_validation(self):
        data   = b"Hello"
        padded = pad(data, 512)
        self.assertEqual(len(padded), 512)
        self.assertEqual(unpad(padded), data)
        with self.assertRaises(ValueError):
            unpad(b"\x01")
        with self.assertRaises(ValueError):
            unpad(data + b"\x00\x00")
        bad = data + b"\x01" + b"\x00" * 7 + b"\x00\x0a"
        with self.assertRaises(ValueError):
            unpad(bad)

    # ── Avalanche: 1-bit plaintext flip ───────────────────────────────────────

    def test_avalanche_plaintext(self):
        """
        Flip a single bit in the plaintext; after 32 GFN rounds the average Hamming
        distance between the two outputs over multiple trials must be close to the
        ideal 50 % (within 47 % - 53 %).
        """
        salt    = os.urandom(16)
        k_enc, _ = derive_keys(self.password, salt)
        subkeys  = derive_subkeys(k_enc)

        TRIALS    = 15
        ratios = []

        for _ in range(TRIALS):
            blk    = os.urandom(512)
            mut    = bytes([blk[0] ^ 0x01]) + blk[1:]
            hd     = _hamming(_get_round_states(blk, subkeys)[-1],
                               _get_round_states(mut, subkeys)[-1])
            ratios.append(hd / 4096)

        avg_ratio = sum(ratios) / TRIALS
        self.assertGreaterEqual(avg_ratio, 0.47, f"Average plaintext avalanche too low: {avg_ratio:.3f}")
        self.assertLessEqual(avg_ratio, 0.53, f"Average plaintext avalanche too high: {avg_ratio:.3f}")

    # ── Avalanche: 1-bit key flip ─────────────────────────────────────────────

    def test_avalanche_key(self):
        """
        Flip a single bit in the derived encryption key; after 32 GFN rounds the average
        Hamming distance over multiple trials must be close to the ideal 50 %
        (within 47 % - 53 %).
        """
        salt     = os.urandom(16)
        k_enc, _ = derive_keys(self.password, salt)
        subkeys  = derive_subkeys(k_enc)
        k_mut    = bytes([k_enc[0] ^ 0x01]) + k_enc[1:]
        sk_mut   = derive_subkeys(k_mut)

        TRIALS    = 15
        ratios = []

        for _ in range(TRIALS):
            blk   = os.urandom(512)
            hd    = _hamming(_get_round_states(blk, subkeys)[-1],
                              _get_round_states(blk, sk_mut)[-1])
            ratios.append(hd / 4096)

        avg_ratio = sum(ratios) / TRIALS
        self.assertGreaterEqual(avg_ratio, 0.47, f"Average key avalanche too low: {avg_ratio:.3f}")
        self.assertLessEqual(avg_ratio, 0.53, f"Average key avalanche too high: {avg_ratio:.3f}")

    # ── SAC: Strict Avalanche Criterion on round_function ────────────────────

    def test_sac_round_function(self):
        """
        Strict Avalanche Criterion (SAC) — Feistel round function F(X, K).

        For each of SAMPLES random 128-byte inputs, we flip BIT_FLIPS
        independent single-bit positions and measure how many output bits
        change.  A cipher satisfying SAC produces ≈ 50 % output bit flips.

        Methodology: Webster & Tavares (1985) / NIST FIPS 140-3 annex.
        Threshold: ≥ 40 % average output bit-flip probability (conservative).
        """
        salt     = os.urandom(16)
        k_enc, _ = derive_keys(self.password, salt)
        subkeys  = derive_subkeys(k_enc)
        K        = subkeys[0]

        SAMPLES    = 64
        BIT_FLIPS  = 32
        THRESHOLD  = 0.40

        rng        = random.Random(42)
        total_hd   = 0
        total_runs = 0

        for _ in range(SAMPLES):
            X      = os.urandom(128)
            f_orig = round_function(X, K)
            for _ in range(BIT_FLIPS):
                bit_pos  = rng.randint(0, 1023)
                byte_idx = bit_pos // 8
                bit_mask = 1 << (7 - (bit_pos % 8))
                X_mut    = bytearray(X)
                X_mut[byte_idx] ^= bit_mask
                total_hd   += _hamming(f_orig, round_function(bytes(X_mut), K))
                total_runs += 1

        avg = total_hd / (total_runs * 1024)
        self.assertGreaterEqual(
            avg, THRESHOLD,
            f"SAC failed: avg output bit-flip {avg:.4f} < {THRESHOLD}"
        )


if __name__ == "__main__":
    unittest.main()
