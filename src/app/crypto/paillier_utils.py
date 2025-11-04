# src/app/crypto/paillier_utils.py
import pickle
import json
from phe import paillier

# ================= Key Generation =================
def generate_paillier_keypair():
    public_key, private_key = paillier.generate_paillier_keypair()

    return public_key, private_key

# ================= Encryption / Decryption =================
def encrypt_paillier(pub_key, value: int):
    """
    Encrypt an integer using the given Paillier public key.
    Returns a serialized bytes object for database storage.
    """
    cipher = pub_key.encrypt(value)
    return pickle.dumps(cipher)  # store as bytes


def decrypt_paillier(priv_key, cipher_bytes):
    """
    Decrypts a serialized ciphertext using the private key.
    """
    cipher = pickle.loads(cipher_bytes)
    return priv_key.decrypt(cipher)


def serialize_to_json(cipher_bytes):
    """
    Convert a pickled Paillier ciphertext to JSON-serializable format.
    Returns a dict with ciphertext, exponent, and public_key_n.
    """
    cipher = pickle.loads(cipher_bytes)
    return {
        "ciphertext": str(cipher.ciphertext()),
        "exponent": cipher.exponent,
        "public_key_n": str(cipher.public_key.n)
    }


def reconstruct_from_json(json_data: dict):
    """
    Reconstruct a Paillier ciphertext from JSON components.
    Expected JSON format:
    {
        "ciphertext": "123456789...",
        "exponent": -3,
        "public_key_n": "987654321..."
    }
    Returns pickled bytes for use with other functions.
    """
    from phe.paillier import PaillierPublicKey, EncryptedNumber
    
    # Reconstruct the public key
    n = int(json_data["public_key_n"])
    public_key = PaillierPublicKey(n)
    
    # Reconstruct the encrypted number
    ciphertext = int(json_data["ciphertext"])
    exponent = json_data["exponent"]
    encrypted_number = EncryptedNumber(public_key, ciphertext, exponent)
    
    return pickle.dumps(encrypted_number)


# ================= Homomorphic Operations =================
def add_paillier(cipher1_bytes, cipher2_bytes):
    """
    Add two Paillier ciphertexts (serialized bytes).
    Returns a serialized bytes result.
    """
    cipher1 = pickle.loads(cipher1_bytes)
    cipher2 = pickle.loads(cipher2_bytes)
    result = cipher1 + cipher2
    return pickle.dumps(result)


def avg_paillier(ciphertexts_bytes):
    """
    Compute average of serialized Paillier ciphertexts.
    Returns a serialized ciphertext representing the average.
    """
    if not ciphertexts_bytes:
        return 0

    # Deserialize all ciphertexts
    ciphertexts = [pickle.loads(c) for c in ciphertexts_bytes]

    # Homomorphic addition
    total = sum(ciphertexts[1:], start=ciphertexts[0])

    # Divide by count (supported by phe)
    avg = total / len(ciphertexts)

    return pickle.dumps(avg)
