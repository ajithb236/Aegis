# src/app/scripts/demo_data.py
import sys
from pathlib import Path

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

import base64
import json
import asyncio
import uuid
from app.crypto import aes_utils, rsa_utils, hmac_utils, paillier_utils
from app.db.init_db import get_db_connection

ORG_ID = "org1"

async def main():
    conn = await get_db_connection()

    # Fetch org public key for verification
    row = await conn.fetchrow(
        "SELECT public_key FROM rsa_keys WHERE org_id=(SELECT id FROM organizations WHERE org_id=$1) AND is_active=TRUE",
        ORG_ID
    )
    pub_key = rsa_utils.deserialize_public_key(row["public_key"].encode())

    # 1. Prepare dummy payload
    payload = {"type": "malware", "risk": 7, "description": "Test alert"}
    payload_bytes = json.dumps(payload).encode()

    # 2. AES encrypt payload
    key, ciphertext, nonce, tag = aes_utils.encrypt_aes_gcm(payload_bytes)
    wrapped_key = key  # for demo, can wrap with RSA later

    # 3. HMAC beacon
    hmac_beacon = hmac_utils.compute_hmac("malware", key=b"beaconsecret")

    # 4. Paillier encryption
    paillier_cipher = paillier_utils.encrypt_paillier(7)

    # 5. RSA sign
    signature = rsa_utils.sign_payload(pub_key, ciphertext)  # for demo, using pub_key; replace with private key

    alert = {
        "encrypted_payload": base64.b64encode(ciphertext).decode(),
        "wrapped_aes_key": base64.b64encode(wrapped_key).decode(),
        "signature": base64.b64encode(signature).decode(),
        "hmac_beacon": hmac_beacon.hex(),
        "paillier_ciphertext": base64.b64encode(paillier_cipher).decode()
    }

    print(json.dumps(alert, indent=4))
    await conn.close()

if __name__ == "__main__":
    asyncio.run(main())
