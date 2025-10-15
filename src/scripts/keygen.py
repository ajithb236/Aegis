# src/app/scripts/keygen.py
import sys
from pathlib import Path

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
from app.crypto import rsa_utils, paillier_utils
from app.db.init_db import get_db_connection

ORG_ID = "org1"
ORG_NAME = "Demo Org"

async def main():
    conn = await get_db_connection()

    # 1. Insert org
    await conn.execute(
        "INSERT INTO organizations (org_id, org_name) VALUES ($1, $2) ON CONFLICT (org_id) DO NOTHING",
        ORG_ID, ORG_NAME
    )

    # 2. Generate RSA keys for signing
    priv_key, pub_key = rsa_utils.generate_rsa_keypair()
    pub_pem = rsa_utils.serialize_public_key(pub_key)
    priv_pem = rsa_utils.serialize_private_key(priv_key)

    await conn.execute(
        """
        INSERT INTO rsa_keys (org_id, public_key, key_type)
        VALUES ((SELECT id FROM organizations WHERE org_id=$1), $2, 'signing')
        ON CONFLICT DO NOTHING
        """,
        ORG_ID, pub_pem.decode()
    )

    # Save private key to file
    import os
    keys_dir = Path(__file__).resolve().parents[2] / "keys"
    keys_dir.mkdir(exist_ok=True)
    priv_key_path = keys_dir / f"{ORG_ID}_private.pem"
    pub_key_path = keys_dir / f"{ORG_ID}_public.pem"
    
    with open(priv_key_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_key_path, "wb") as f:
        f.write(pub_pem)
    
    print(f"RSA keys saved to {keys_dir}")
    print(f"  Private key: {priv_key_path}")
    print(f"  Public key: {pub_key_path}")

    # 3. Generate Paillier keypair (optional, store locally)
    pub_p, priv_p = paillier_utils.generate_paillier_keypair()
    print("[Paillier Public Key]", pub_p)
    print("[Paillier Private Key]", priv_p)

    await conn.close()
    print("Demo organization and keys inserted successfully!")

if __name__ == "__main__":
    asyncio.run(main())
