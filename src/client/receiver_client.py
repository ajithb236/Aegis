# src/app/client/receiver_client.py
import asyncio
import base64
from app.crypto import aes_utils, rsa_utils, paillier_utils

# For demo only, simulate fetching from DB
def decrypt_alert(alert, priv_key):
    encrypted_payload = base64.b64decode(alert["encrypted_payload"])
    wrapped_key = base64.b64decode(alert["wrapped_aes_key"])
    signature = base64.b64decode(alert["signature"])
    
    # Verify signature
    pub_key = rsa_utils.deserialize_public_key(alert["pub_key"].encode())
    if not rsa_utils.verify_signature(pub_key, encrypted_payload, signature):
        print("Invalid signature!")
        return

    # AES decrypt
    plaintext = aes_utils.decrypt_aes_gcm(encrypted_payload, wrapped_key)
    print("Decrypted alert:", plaintext)

if __name__ == "__main__":
    # Load alert JSON from sample_client.py
    alert = json.load(open("alert.json"))
    decrypt_alert(alert, None)  # pass private key if available
