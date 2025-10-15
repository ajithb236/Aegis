# src/app/crypto/paillier_key_manager.py
"""
Global Paillier Key Manager
Manages a single shared Paillier keypair for homomorphic aggregation.
All organizations use the same public key to encrypt risk scores,
enabling homomorphic addition and averaging.
"""
import pickle
from pathlib import Path
from phe import paillier
from typing import Tuple, Optional

# Global key storage
_PAILLIER_PUBLIC_KEY = None
_PAILLIER_PRIVATE_KEY = None

# Key storage paths
KEYS_DIR = Path(__file__).resolve().parents[3] / "keys"
PUBLIC_KEY_PATH = KEYS_DIR / "paillier_public.key"
PRIVATE_KEY_PATH = KEYS_DIR / "paillier_private.key"


def generate_and_save_paillier_keys(key_size: int = 2048) -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    """
    Generate a new Paillier keypair and save to disk.
    """
    global _PAILLIER_PUBLIC_KEY, _PAILLIER_PRIVATE_KEY
    
    print("Generating new Paillier keypair (this may take a moment)...")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_size)
    
    # Create keys directory if it doesn't exist
    KEYS_DIR.mkdir(exist_ok=True)
    
    # Save keys to disk
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        pickle.dump(public_key, f)
    
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        pickle.dump(private_key, f)
    
    print(f"Paillier keys saved to {KEYS_DIR}")
    
    # Cache in memory
    _PAILLIER_PUBLIC_KEY = public_key
    _PAILLIER_PRIVATE_KEY = private_key
    
    return public_key, private_key


def load_paillier_keys() -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    """
    Load Paillier keys from disk. Generate new keys if they don't exist.
    """
    global _PAILLIER_PUBLIC_KEY, _PAILLIER_PRIVATE_KEY
    
    # Return cached keys if available
    if _PAILLIER_PUBLIC_KEY is not None and _PAILLIER_PRIVATE_KEY is not None:
        return _PAILLIER_PUBLIC_KEY, _PAILLIER_PRIVATE_KEY
    
    # Try to load from disk
    if PUBLIC_KEY_PATH.exists() and PRIVATE_KEY_PATH.exists():
        try:
            with open(PUBLIC_KEY_PATH, 'rb') as f:
                _PAILLIER_PUBLIC_KEY = pickle.load(f)
            
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                _PAILLIER_PRIVATE_KEY = pickle.load(f)
            
            print(f"Loaded Paillier keys from {KEYS_DIR}")
            return _PAILLIER_PUBLIC_KEY, _PAILLIER_PRIVATE_KEY
        except Exception as e:
            print(f"Failed to load Paillier keys: {e}")
            print("Generating new keys...")
    
    # Generate new keys if loading failed or keys don't exist
    return generate_and_save_paillier_keys()


def get_public_key() -> paillier.PaillierPublicKey:
    """
    Get the shared Paillier public key.
    All organizations use this key to encrypt risk scores.
    """
    public_key, _ = load_paillier_keys()
    return public_key


def get_private_key() -> paillier.PaillierPrivateKey:
    """
    Get the Paillier private key for decryption.
    Only authorized parties should have access to this.
    """
    _, private_key = load_paillier_keys()
    return private_key


def get_public_key_json() -> dict:
    """
    Get the public key in JSON-serializable format for API transmission.
    """
    public_key = get_public_key()
    return {
        "n": str(public_key.n),
        "g": str(public_key.g),
        "max_int": str(public_key.max_int)
    }


def encrypt_with_shared_key(value: int) -> bytes:
    """
    Encrypt a value using the shared Paillier public key.
    Returns pickled bytes for storage.
    """
    public_key = get_public_key()
    encrypted = public_key.encrypt(value)
    return pickle.dumps(encrypted)


def decrypt_with_shared_key(cipher_bytes: bytes) -> int:
    """
    Decrypt a ciphertext using the shared Paillier private key.
    """
    private_key = get_private_key()
    encrypted = pickle.loads(cipher_bytes)
    return private_key.decrypt(encrypted)


# Initialize keys on module import
try:
    load_paillier_keys()
except Exception as e:
    print(f"Warning: Failed to initialize Paillier keys: {e}")
