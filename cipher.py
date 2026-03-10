import hashlib, hmac
def derive_keys(password, salt):
    return b"key_enc", b"key_mac"
def derive_subkeys(k_enc):
    return [b"subkey" * 16 for _ in range(64)]
