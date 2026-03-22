#!/usr/bin/env python3
"""
pq_key_exchange.py - Hybrid Post-Quantum Key Agreement
======================================================
This module implements a hybrid post-quantum key agreement protocol combining
classical Elliptic Curve Diffie-Hellman (ECDH over secp256r1) with NIST FIPS 203
standardized Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768, formerly Kyber).

It demonstrates how two parties (Alice and Bob) can securely establish a shared
symmetric secret key over an insecure network, retaining classical security even
if the PQ algorithm is compromised, and PQ security even if classical ECDH is broken.
"""

import hashlib
import hmac
import os
import sys

# Try importing PQ and Classical cryptography libraries
HAS_OQS = False
try:
    import oqs
    HAS_OQS = True
except ImportError:
    pass

HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

class HybridKeyExchange:
    """
    Implements a Hybrid Key Agreement protocol combining ML-KEM-768 (Kyber768)
    and ECDH (secp256r1).
    """
    def __init__(self):
        self.kem_name = "Kyber768"  # ML-KEM-768 equivalent in liboqs
        
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
        if HAS_CRYPTOGRAPHY:
            ec_priv = ec.generate_private_key(ec.SECP256R1())
            ec_pub = ec_priv.public_key()
            private_keys["ec"] = ec_priv
            # Serialized EC public key bytes
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            public_keys["ec"] = ec_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        else:
            # Mock classical EC for demonstration if cryptography is missing
            private_keys["ec"] = os.urandom(32)
            public_keys["ec"] = os.urandom(65) # Mock public key bytes

        # 2. Post-Quantum ML-KEM Generation
        if HAS_OQS:
            kem = oqs.KeyEncapsulation(self.kem_name)
            pq_pub = kem.generate_keypair()
            private_keys["pq"] = kem
            public_keys["pq"] = pq_pub
        else:
            # Mock PQ for demonstration if liboqs is missing
            private_keys["pq"] = os.urandom(32)
            public_keys["pq"] = os.urandom(1184) # Kyber768 public key size

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
        if HAS_CRYPTOGRAPHY:
            # Generate Bob's ephemeral EC key
            bob_ec_priv = ec.generate_private_key(ec.SECP256R1())
            from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
            alice_ec_pub = load_der_public_key(peer_public_keys["ec"])
            
            # Compute EC shared secret
            ec_secret = bob_ec_priv.exchange(ec.ECDH(), alice_ec_pub)
            shared_secrets.append(ec_secret)
            
            # Bob's EC public key acts as the ciphertext/ephemeral key for Alice to do the exchange
            ciphertexts["ec"] = bob_ec_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        else:
            # Mock classical EC secret
            shared_secrets.append(os.urandom(32))
            ciphertexts["ec"] = os.urandom(65)

        # 2. Post-Quantum KEM Shared Secret
        if HAS_OQS:
            with oqs.KeyEncapsulation(self.kem_name) as client:
                pq_ciphertext, pq_secret = client.encap_secret(peer_public_keys["pq"])
                shared_secrets.append(pq_secret)
                ciphertexts["pq"] = pq_ciphertext
        else:
            # Mock PQ KEM secret: derive deterministically from peer public key for demo matching
            pq_secret = hashlib.sha256(peer_public_keys["pq"] + b"mock_kem_salt").digest()
            shared_secrets.append(pq_secret)
            ciphertexts["pq"] = peer_public_keys["pq"]

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
        if HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            bob_ec_pub = load_der_public_key(peer_ciphertexts["ec"])
            alice_ec_priv = private_keys["ec"]
            
            ec_secret = alice_ec_priv.exchange(ec.ECDH(), bob_ec_pub)
            shared_secrets.append(ec_secret)
        else:
            # Mock classical EC secret
            shared_secrets.append(b"mock_ec_shared_secret_value")

        # 2. Decapsulate Post-Quantum KEM
        if HAS_OQS:
            kem = private_keys["pq"]
            pq_secret = kem.decap_secret(peer_ciphertexts["pq"])
            # Clean up the C resources allocated by liboqs
            kem.free()
            shared_secrets.append(pq_secret)
        else:
            # Mock PQ KEM secret: matches Bob's deterministic derivation from public key
            pq_secret = hashlib.sha256(peer_ciphertexts["pq"] + b"mock_kem_salt").digest()
            shared_secrets.append(pq_secret)

        # 3. Hybrid Combination via HKDF-SHA256
        combined_secret = self._combine_secrets(shared_secrets)
        return combined_secret

    def _combine_secrets(self, secrets: list) -> bytes:
        """
        Combine multiple shared secrets using HKDF-SHA256 extraction and expansion.
        Guarantees that the resulting key is secure as long as AT LEAST ONE of the
        constituent secrets is secure.
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
    
    if not HAS_OQS or not HAS_CRYPTOGRAPHY:
        print("[WARNING] Missing libraries. Running protocol with Mock simulation.")
        print("To install dependencies on Windows, run:")
        print("  pip install liboqs-python cryptography")
        print("-" * 60)

    # Initialize protocol
    exchange = HybridKeyExchange()

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
    print(f"  Bob's Derived Secret:   {bob_secret.hex()[:32]}...")
    print()

    # Step 3: Alice receives Bob's ciphertexts and decapsulates
    print("Step 3: Alice decapsulates Bob's ciphertexts...")
    alice_secret = exchange.decapsulate(alice_priv, bob_ciphertexts)
    print(f"  Alice's Derived Secret: {alice_secret.hex()[:32]}...")
    print()

    # Step 4: Verification
    if alice_secret == bob_secret:
        print("\033[92m[SUCCESS] Key Agreement Successful! secrets match perfectly.\033[0m")
        print(f"  Established Shared Secret (256-bit): {alice_secret.hex()}")
        
        # Demonstrate initializing FeistelCipher with the derived key
        try:
            from cipher import FeistelCipher
            print("-" * 60)
            print("Step 5: Initialize zero-dependency FeistelCipher with shared secret...")
            
            # Using derived secret hex as password string
            cipher = FeistelCipher(alice_secret.hex()[:16])
            msg = b"Secure post-quantum message channel active!"
            ct = cipher.encrypt(msg)
            pt = cipher.decrypt(ct)
            print(f"  Plaintext  : {msg.decode('utf-8')}")
            print(f"  Ciphertext : {ct.hex()[:64]}...")
            print(f"  Decrypted  : {pt.decode('utf-8')}")
            print("\033[92m[PASS] Integrated verification successful!\033[0m")
        except ImportError:
            print("  (cipher.py not found in path, skipping integration test)")
    else:
        print("\033[91m[FAILURE] Secrets mismatch!\033[0m")

if __name__ == "__main__":
    main()
