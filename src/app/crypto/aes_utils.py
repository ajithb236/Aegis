# src/app/crypto/aes_utils.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_aes_gcm(plaintext: bytes):
    key = get_random_bytes(32)  # 256-bit key
    iv = get_random_bytes(12)   # 96-bit nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, key, iv, tag

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
