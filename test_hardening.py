"""Regression coverage for audit fixes and legacy-format compatibility."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import cipher
import pq_key_exchange as pq


class HardeningTests(unittest.TestCase):
    def test_legacy_ciphertext(self):
        with cipher.FeistelCipher("Compatibility123") as c:
            self.assertEqual(c.decrypt(bytes.fromhex(LEGACY)), b"legacy compatibility\x00\xff")

    def test_padding_boundaries(self):
        for size in (0, 1, 510, 511, 512, 513, 1023, 1024):
            data = os.urandom(size)
            self.assertEqual(cipher.unpad(cipher.pad(data)), data)

    def test_invalid_block_sizes(self):
        for size in (0, 1, -1, 65535):
            with self.assertRaises(ValueError):
                cipher.pad(b"", size)

    def test_unaligned_padding(self):
        with self.assertRaises(ValueError):
            cipher.unpad(b"\x00\x02")

    def test_xor_rejects_truncation(self):
        with self.assertRaises(ValueError):
            cipher.xor_bytes(b"abc", b"a")

    def test_block_validation(self):
        keys = cipher.derive_subkeys(b"k" * 32)
        for operation in (cipher.encrypt_block, cipher.decrypt_block):
            with self.assertRaises(ValueError):
                operation(b"a" * 511, keys)
            with self.assertRaises(ValueError):
                operation(b"a" * 512, keys[:-1])

    def test_custom_permutation_is_respected(self):
        data = bytes(range(128))
        self.assertEqual(cipher.permute_bits(data, list(range(1024))), data)
        with self.assertRaises(ValueError):
            cipher.FastPermuter([0] * 1024)

    def test_context_clears_on_exception(self):
        c = cipher.FeistelCipher("Password123")
        with self.assertRaises(RuntimeError):
            with c:
                raise RuntimeError("injected")
        with self.assertRaises(ValueError):
            c.encrypt(b"data")

    def test_malformed_rejected_before_kdf(self):
        with cipher.FeistelCipher("Password123") as c, patch.object(cipher, "derive_keys") as kdf:
            for length in (0, 560, 561, 1071, 1073, 1583):
                with self.assertRaises(ValueError):
                    c.decrypt(b"a" * length)
            kdf.assert_not_called()

    def test_keys_cleared_on_failure(self):
        keys = (bytearray(b"e" * 32), bytearray(b"m" * 32))
        with cipher.FeistelCipher("Password123") as c, patch.object(cipher, "derive_keys", return_value=keys), patch.object(cipher, "derive_subkeys", side_effect=RuntimeError("injected")):
            with self.assertRaises(RuntimeError):
                c.encrypt(b"abc")
        self.assertEqual(keys, (bytearray(32), bytearray(32)))

    def test_authentication_precedes_decryption(self):
        with cipher.FeistelCipher("Password123") as c:
            encrypted = bytearray(c.encrypt(b"abc"))
            with patch.object(cipher, "decrypt_block") as decrypt:
                for offset in (0, 16, 528, len(encrypted)-1):
                    changed = encrypted.copy()
                    changed[offset] ^= 1
                    with self.assertRaises(ValueError):
                        c.decrypt(bytes(changed))
                decrypt.assert_not_called()

    def test_known_diffusion_limitation(self):
        # Compatibility sentinel, NOT a security success criterion.
        result = cipher.mix_bytes(bytes(range(128)))
        self.assertEqual(result, result[:8] * 16)

    def test_atomic_output_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output"
            cipher.write_output(path, b"first")
            with self.assertRaises(FileExistsError):
                cipher.write_output(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_failed_publication_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cipher.os, "link", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                cipher.write_output(Path(directory) / "output", b"data")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_files_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            source = Path(directory) / "plain"
            source.write_bytes(b" \x00hello\xff\n")
            self.assertEqual(cipher.main(["encrypt", str(source), "Password123"]), 0)
            self.assertEqual(cipher.main(["decrypt", str(source)+".enc", "Password123"]), 0)
            self.assertEqual(Path(str(source)+".enc.dec").read_bytes(), source.read_bytes())
            self.assertEqual(cipher.main(["encrypt", str(source), "Password123"]), 1)
            self.assertEqual(cipher.main(["encrypt", str(source), "Password123", "-o", str(source)]), 1)

    def test_cli_prompt_and_machine_readable_hex(self):
        output = io.StringIO()
        with patch.object(cipher.getpass, "getpass", side_effect=["Password123", "Password123"]), contextlib.redirect_stdout(output):
            self.assertEqual(cipher.main(["encrypt-str", "  hello\n"]), 0)
        with cipher.FeistelCipher("Password123") as c:
            self.assertEqual(c.decrypt(bytes.fromhex(output.getvalue())), b"  hello\n")

    def test_cli_confirmation_mismatch(self):
        with patch.object(cipher.getpass, "getpass", side_effect=["Password123", "different"]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cipher.main(["encrypt-str", "hello"]), 1)

    def test_pq_missing_dependencies_fail_closed(self):
        for classical, quantum in ((False, False), (True, False), (False, True)):
            with patch.object(pq, "HAS_CRYPTOGRAPHY", classical), patch.object(pq, "HAS_OQS", quantum):
                with self.assertRaises(RuntimeError):
                    pq.HybridKeyExchange()

    @unittest.skipUnless(pq.HAS_CRYPTOGRAPHY and pq.HAS_OQS, "Optional native PQ dependencies unavailable")
    def test_real_hybrid_exchange(self):
        exchange = pq.HybridKeyExchange()
        private, public = exchange.generate_keypair()
        message, expected = exchange.encapsulate(public)
        self.assertEqual(exchange.decapsulate(private, message), expected)


LEGACY = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeffe36e9ca06ea4a659e86e83a871bcec5bf3729fa81d32962a9713e3d915c59e22af2bdbe12dfda61aa723d3e925f5ae12bf3bcbf13dedb60ab733c3f935e5be02cf4bbb814d9dc67ac743b3894595ce72df5bab915d8dd66ad753a3995585de62ef6b9ba16dbde65ae76393a965b5ee52ff7b8bb17dadf64af77383b975a5fe421a47cb9b87c7e98c124fc3938fcfe1840a57db8b97d7f99c025fd3839fdff1943a67ebbba7e7c9ac326fe3b3afefc1a42a77fbabb7f7d9bc227ff3a3bfffd1b45a078bdbc787a9cc520f83d3cf8fa1c44a179bcbd797b9dc421f93c3df9fb1d47a27abfbe7a789ec722fa3f3efaf81e46a37bbebf7b799fc623fb3e3ffbf91f4ef83700e33f37acbe78b78063bfb72c3ff93601e23e36adbf79b68162beb62d3cfa3502e13d35aebc7ab58261bdb52e3dfb3403e03c34afbd7bb48360bcb42f3afc3304e73b33a8ba7cb38467bbb3283bfd3205e63a32a9bb7db28566bab22938fe3106e53931aab87eb18665b9b12a39ff3007e43830abb97fb08764b8b02b38b7f774bfe64bd0b83777f43f66cb5039b6f675bee74ad1b93676f53e67ca513ab5f576bde449d2ba3575f63d64c9523bb4f477bce548d3bb3474f73c65c8533cb3f370bbe24fd4bc3373f03b62cf543db2f271bae34ed5bd3272f13a63ce553eb1f172b9e04dd6be3171f23960cd563fb0f073b8e14cd7bf3070f33861cc4993b2fe6737bde40fb9012020199221c95ae0fcbd6ace76bf7be54e4717c072f8b"
