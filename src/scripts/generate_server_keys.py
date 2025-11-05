"""
Generate RSA keypair for server signing of analytics responses.
Run this once to create server keys.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def generate_server_keys():
    """Generate RSA keypair for server signing"""
    print("Generating server RSA keypair...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize private key (no password for server key)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Ensure keys directory exists
    keys_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    
    # Write keys to files
    private_path = os.path.join(keys_dir, 'server_private.pem')
    public_path = os.path.join(keys_dir, 'server_public.pem')
    
    with open(private_path, 'wb') as f:
        f.write(private_pem)
    print(f"✓ Private key saved to: {private_path}")
    
    with open(public_path, 'wb') as f:
        f.write(public_pem)
    print(f"✓ Public key saved to: {public_path}")
    
    print("\nServer keys generated successfully!")

if __name__ == "__main__":
    generate_server_keys()
