from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def encrypt_aes_gcm(plaintext: bytes, key: bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_aes_gcm(ciphertext_b64: str, key: bytes):
    raw = base64.b64decode(ciphertext_b64)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

