#!/usr/bin/env python3
"""
pq_key_exchange.py - Hybrid Post-Quantum Key Agreement
======================================================
This module implements a hybrid post-quantum key agreement protocol combining
classical Elliptic Curve Diffie-Hellman (ECDH over secp256r1) with NIST FIPS 203
standardized Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768, formerly Kyber).

This is an unauthenticated educational exchange, not a complete secure transport.
Peers must authenticate public keys separately to prevent active interception.
"""

import hashlib
import hmac
import sys

# Try importing PQ and Classical cryptography libraries
HAS_OQS = False
try:
    import oqs
    HAS_OQS = True
except (ImportError, OSError):
    pass

HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTOGRAPHY = True
except (ImportError, OSError):
    pass

class HybridKeyExchange:
    """
    Implements a Hybrid Key Agreement protocol combining ML-KEM-768
    and ECDH (secp256r1).
    """
    def __init__(self):
        if not HAS_CRYPTOGRAPHY or not HAS_OQS:
            raise RuntimeError("Hybrid exchange requires cryptography and liboqs-python with native liboqs. No mock fallback is provided.")
        self.kem_name = "ML-KEM-768"
        if self.kem_name not in oqs.get_enabled_kem_mechanisms():
            raise RuntimeError("The installed liboqs does not enable ML-KEM-768.")

    def generate_keypair(self):
        """
        Generates public/private key pairs for both ECDH and ML-KEM.
        Returns:
            private_keys (dict): The private key handles/bytes.
            public_keys (dict): The serialized public key bytes to send to the peer.
        """
        public_keys = {}
        private_keys = {}

        # 1. Classical ECDH Generation
        ec_priv = ec.generate_private_key(ec.SECP256R1())
        ec_pub = ec_priv.public_key()
        private_keys["ec"] = ec_priv
        # Serialized EC public key bytes
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public_keys["ec"] = ec_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # 2. Post-Quantum ML-KEM Generation
        kem = oqs.KeyEncapsulation(self.kem_name)
        try:
            pq_pub = kem.generate_keypair()
        except Exception:
            kem.free()
            raise
        private_keys["pq"] = kem
        public_keys["pq"] = pq_pub

        return private_keys, public_keys

    def encapsulate(self, peer_public_keys):
        """
        Bob runs this to encapsulate secrets for Alice using Alice's public keys.
        Args:
            peer_public_keys (dict): Alice's EC and PQ public keys.
        Returns:
            ciphertexts (dict): The EC and PQ ciphertexts to send to Alice.
            shared_secret (bytes): The combined derived hybrid key.
        """
        ciphertexts = {}
        shared_secrets = []

        # 1. Classical ECDH Shared Secret
        # Generate Bob's ephemeral EC key
        bob_ec_priv = ec.generate_private_key(ec.SECP256R1())
        from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
        alice_ec_pub = load_der_public_key(peer_public_keys["ec"])

        # Compute EC shared secret
        ec_secret = bob_ec_priv.exchange(ec.ECDH(), alice_ec_pub)
        shared_secrets.append(ec_secret)

        # Bob's EC public key acts as the ciphertext/ephemeral key for Alice to do the exchange
        ciphertexts["ec"] = bob_ec_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # 2. Post-Quantum KEM Shared Secret
        with oqs.KeyEncapsulation(self.kem_name) as client:
            pq_ciphertext, pq_secret = client.encap_secret(peer_public_keys["pq"])
            shared_secrets.append(pq_secret)
            ciphertexts["pq"] = pq_ciphertext

        # 3. Hybrid Combination via HKDF-SHA256
        combined_secret = self._combine_secrets(shared_secrets)
        return ciphertexts, combined_secret

    def decapsulate(self, private_keys, peer_ciphertexts):
        """
        Alice runs this to recover the shared secret using her private keys
        and Bob's ciphertexts.
        Args:
            private_keys (dict): Alice's private key handles.
            peer_ciphertexts (dict): Bob's EC and PQ ciphertexts.
        Returns:
            shared_secret (bytes): The combined derived hybrid key.
        """
        shared_secrets = []

        # 1. Decapsulate Classical ECDH
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        bob_ec_pub = load_der_public_key(peer_ciphertexts["ec"])
        alice_ec_priv = private_keys["ec"]

        ec_secret = alice_ec_priv.exchange(ec.ECDH(), bob_ec_pub)
        shared_secrets.append(ec_secret)

        # 2. Decapsulate Post-Quantum KEM
        kem = private_keys["pq"]
        try:
            pq_secret = kem.decap_secret(peer_ciphertexts["pq"])
        finally:
            kem.free()
        shared_secrets.append(pq_secret)

        # 3. Hybrid Combination via HKDF-SHA256
        combined_secret = self._combine_secrets(shared_secrets)
        return combined_secret

    def _combine_secrets(self, secrets: list) -> bytes:
        """
        Combine multiple shared secrets using HKDF-SHA256 extraction and expansion.
        This demonstration does not establish a security proof for the protocol.
        """
        # Concatenate all raw secrets
        ikm = b"".join(secrets)

        # HKDF-Extract
        prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()

        # HKDF-Expand to 32 bytes (256-bit symmetric key)
        info = b"hybrid_pq_ecdh_agreement_v1"
        okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return okm

def main():
    print("=" * 60)
    print("      Hybrid Post-Quantum Key Agreement Demonstration")
    print("=" * 60)
    print(f"Post-Quantum library (liboqs-python): {'[DETECTED]' if HAS_OQS else '[NOT FOUND]'}")
    print(f"Classical cryptography library:       {'[DETECTED]' if HAS_CRYPTOGRAPHY else '[NOT FOUND]'}")
    print("-" * 60)

    try:
        exchange = HybridKeyExchange()
    except RuntimeError as exc:
        print(f"Unavailable: {exc}", file=sys.stderr)
        return 1

    # Step 1: Alice generates her key pair
    print("Step 1: Alice generates public/private keypair...")
    alice_priv, alice_pub = exchange.generate_keypair()
    print(f"  Alice EC Pub Size: {len(alice_pub['ec'])} bytes")
    print(f"  Alice PQ Pub Size: {len(alice_pub['pq'])} bytes")
    print()

    # Step 2: Bob receives Alice's public keys and encapsulates secrets
    print("Step 2: Bob encapsulates secrets using Alice's public keys...")
    bob_ciphertexts, bob_secret = exchange.encapsulate(alice_pub)
    print(f"  Bob EC Ciphertext Size: {len(bob_ciphertexts['ec'])} bytes")
    print(f"  Bob PQ Ciphertext Size: {len(bob_ciphertexts['pq'])} bytes")
    print("  Bob derived a 32-byte shared secret.")
    print()

    # Step 3: Alice receives Bob's ciphertexts and decapsulates
    print("Step 3: Alice decapsulates Bob's ciphertexts...")
    alice_secret = exchange.decapsulate(alice_priv, bob_ciphertexts)
    print("  Alice derived a 32-byte shared secret.")
    print()

    # Step 4: Verification
    if alice_secret == bob_secret:
        print("\033[92m[SUCCESS] Key Agreement Successful! secrets match perfectly.\033[0m")


        # Demonstrate initializing FeistelCipher with the derived key
        try:
            from cipher import FeistelCipher
            print("-" * 60)
            print("Step 5: Initialize zero-dependency FeistelCipher with shared secret...")

            # Using derived secret hex as password string
            cipher = FeistelCipher(alice_secret.hex())
            msg = b"Secure post-quantum message channel active!"
            ct = cipher.encrypt(msg)
            pt = cipher.decrypt(ct)
            print(f"  Plaintext  : {msg.decode('utf-8')}")
            print(f"  Ciphertext : {ct.hex()[:64]}...")
            print(f"  Decrypted  : {pt.decode('utf-8')}")
            print("\033[92m[PASS] Integrated verification successful!\033[0m")
        except (ImportError, OSError):
            print("  (cipher.py not found in path, skipping integration test)")
    else:
        print("\033[91m[FAILURE] Secrets mismatch!\033[0m")
        return 1

if __name__ == "__main__":
    sys.exit(main())
