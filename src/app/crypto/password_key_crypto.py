# src/app/crypto/password_key_crypto.py
"""
Password-based key encryption for server-side storage.
Server NEVER calls decrypt - intentionally omitted for security.
"""
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_private_key(private_key_pem: bytes, password: str) -> dict:
    """
    Encrypt private key with password-derived AES key.
    Returns dict with encrypted data, salt, and nonce for client decryption.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
    
    return {
        "encrypted_key": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }

# NO DECRYPT FUNCTION - Server cannot decrypt by design
