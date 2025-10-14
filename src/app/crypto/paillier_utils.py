# src/app/crypto/paillier_utils.py
from phe import paillier

# ================= Key Generation =================
def generate_paillier_keypair():
    public_key, private_key = paillier.generate_paillier_keypair()
    return public_key, private_key

# ================= Encryption / Decryption =================
def encrypt_paillier(pub_key, value: int):
    cipher = pub_key.encrypt(value)
    return cipher

def decrypt_paillier(priv_key, cipher):
    return priv_key.decrypt(cipher)

# ================= Homomorphic Operations =================
def add_paillier(cipher1, cipher2):
    return cipher1 + cipher2

def avg_paillier(ciphertexts):
    if len(ciphertexts) == 0:
        return 0
    total = sum(ciphertexts[1:], start=ciphertexts[0])
    avg = total / len(ciphertexts)
    return avg
