# src/app/crypto/hmac_utils.py
from cryptography.hazmat.primitives import hmac, hashes
import binascii
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

def compute_hmac(message: str, key: bytes) -> str:
    """
    Compute an HMAC beacon (returns hex string instead of bytes).
    Compatible with demo_data.py and alert submissions.
    """
    raw = generate_hmac(key, message.encode())
    return binascii.hexlify(raw).decode()

