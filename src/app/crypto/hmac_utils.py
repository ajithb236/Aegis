# src/app/crypto/hmac_utils.py
from cryptography.hazmat.primitives import hmac, hashes

def generate_hmac(key: bytes, message: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

def verify_hmac(key: bytes, message: bytes, hmac_val: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(hmac_val)
        return True
    except Exception:
        return False
