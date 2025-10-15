#!/usr/bin/env python3
"""
Initialize Paillier Keys for Aegis
Generates a shared Paillier keypair for homomorphic encryption.
All organizations use the same public key to enable aggregation.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.crypto.paillier_key_manager import generate_and_save_paillier_keys, KEYS_DIR


def main():
    print("=" * 60)
    print("Aegis Paillier Key Initialization")
    print("=" * 60)
    print()
    print("This will generate a shared Paillier keypair for homomorphic")
    print("encryption. All organizations will use the same public key")
    print("to encrypt risk scores, enabling privacy-preserving aggregation.")
    print()
    
    # Check if keys already exist
    public_key_path = KEYS_DIR / "paillier_public.key"
    private_key_path = KEYS_DIR / "paillier_private.key"
    
    if public_key_path.exists() and private_key_path.exists():
        print("⚠️  Warning: Paillier keys already exist!")
        print(f"   Public key:  {public_key_path}")
        print(f"   Private key: {private_key_path}")
        print()
        response = input("Overwrite existing keys? (yes/no): ").strip().lower()
        if response != 'yes':
            print("Aborted. Existing keys preserved.")
            return
        print()
    
    # Generate keys
    print("Generating Paillier keypair (2048-bit)...")
    print("This may take 10-30 seconds...")
    print()
    
    try:
        public_key, private_key = generate_and_save_paillier_keys(key_size=2048)
        
        print()
        print("✅ Paillier keys generated successfully!")
        print()
        print(f"📁 Keys saved to: {KEYS_DIR}")
        print(f"   Public key:  {public_key_path.name}")
        print(f"   Private key: {private_key_path.name}")
        print()
        print("📊 Key Properties:")
        print(f"   Modulus (n): {len(str(public_key.n))} digits")
        print(f"   Generator (g): {public_key.g}")
        print()
        print("🔒 Security Notes:")
        print("   - The public key is shared with all organizations")
        print("   - The private key must be kept secure (only for authorized decryption)")
        print("   - All risk scores must be encrypted with this public key")
        print("   - Homomorphic operations only work on ciphertexts from the same key")
        print()
        print("✓ Setup complete! The backend API is ready to serve the public key.")
        
    except Exception as e:
        print()
        print(f"❌ Error generating keys: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
