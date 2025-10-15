from fastapi import APIRouter, HTTPException, Depends
from app.db.init_db import get_db_connection
from app.api.v1.auth import verify_token
from app.crypto import rsa_utils, hmac_utils, paillier_utils, aes_utils
import uuid
import base64
import json
# from app.utils.logger import get_logger

router = APIRouter()
# logger = get_logger()


@router.get("/")
async def get_alerts():
    return {"status": "ok", "data": []}


@router.post("/submit")
async def submit_alert(alert: dict, org_id: str = Depends(verify_token)):
    required_fields = ["encrypted_payload", "wrapped_aes_key", "signature", "hmac_beacon"]
    for field in required_fields:
        if field not in alert:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")

    alert_id = str(uuid.uuid4())

    # ================= VERIFY SIGNATURE ===================
    try:
        conn = await get_db_connection()
        row = await conn.fetchrow(
            """
            SELECT public_key FROM rsa_keys 
            WHERE org_id=(SELECT id FROM organizations WHERE org_id=$1) 
              AND is_active=TRUE
            """,
            org_id
        )
        if not row:
            raise HTTPException(status_code=403, detail="Public key not found for org")
        
        pub_pem = row["public_key"].encode()
        public_key = rsa_utils.deserialize_public_key(pub_pem)

        signature = base64.b64decode(alert["signature"])
        encrypted_payload_bytes = base64.b64decode(alert["encrypted_payload"])

        if not rsa_utils.verify_signature(public_key, encrypted_payload_bytes, signature):
            raise HTTPException(status_code=403, detail="Signature verification failed")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signature verification failed: {e}")

    # ================= VALIDATE AND STORE PAILLIER CIPHERTEXT ===================
    try:
        from app.crypto.paillier_key_manager import get_public_key
        
        paillier_data = None
        if alert.get("paillier_ciphertext"):
            paillier_json_str = alert["paillier_ciphertext"]
            paillier_json = json.loads(paillier_json_str)
            
            # Verify the ciphertext is encrypted with the shared public key
            shared_public_key = get_public_key()
            if str(shared_public_key.n) != str(paillier_json["public_key_n"]):
                raise HTTPException(
                    status_code=400,
                    detail="Paillier ciphertext must be encrypted with the shared public key"
                )
            
            paillier_data = paillier_json_str
        
        await conn.execute(
            """
            INSERT INTO alerts (
                alert_id, submitter_org_id, encrypted_payload,
                wrapped_aes_key, signature, hmac_beacon, paillier_ciphertext
            ) VALUES ($1, (SELECT id FROM organizations WHERE org_id=$2),
                      $3, $4, $5, $6, $7)
            """,
            alert_id,
            org_id,
            encrypted_payload_bytes,
            base64.b64decode(alert["wrapped_aes_key"]),
            signature,
            alert["hmac_beacon"],
            paillier_data.encode('utf-8') if paillier_data else None
        )
        return {"status": "success", "alert_id": alert_id}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        await conn.close()

@router.get("/search")
async def search_alerts(hmac_beacon: str, org_id: str = Depends(verify_token)):
    """
    Search alerts by HMAC beacon (equality-based)
    """
    try:
        conn = await get_db_connection()
        rows = await conn.fetch(
            """
            SELECT alert_id, submitter_org_id, created_at
            FROM alerts
            WHERE hmac_beacon = $1
            """,
            hmac_beacon
        )
        return {
            "alerts": [
                {"alert_id": r["alert_id"], "submitter_org_id": r["submitter_org_id"], "created_at": r["created_at"]}
                for r in rows
            ]
        }
    except Exception as e:
        # logger.error(f"DB Error while searching alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        await conn.close()


@router.get("/aggregate")
async def aggregate_risk(org_id: str = Depends(verify_token)):
    """
    Aggregate Paillier-encrypted risk scores using homomorphic encryption.
    All ciphertexts must be encrypted with the same shared public key.
    """
    try:
        from app.crypto.paillier_key_manager import get_public_key, get_private_key
        
        conn = await get_db_connection()
        rows = await conn.fetch("SELECT paillier_ciphertext FROM alerts WHERE paillier_ciphertext IS NOT NULL")
        await conn.close()

        if not rows:
            return {
                "count": 0,
                "total_encrypted": None,
                "average_encrypted": None,
                "total_decrypted": 0,
                "average_decrypted": 0.0,
                "message": "No alerts with risk scores found"
            }

        # Get the shared public and private keys
        public_key = get_public_key()
        private_key = get_private_key()
        
        ciphertexts = []
        for row in rows:
            data = row["paillier_ciphertext"]
            
            # Convert memoryview to bytes
            if isinstance(data, memoryview):
                data = bytes(data)
            
            # Decode bytes to string if needed
            if isinstance(data, bytes):
                try:
                    data = data.decode('utf-8')
                except UnicodeDecodeError:
                    # It's binary pickle data, use as-is
                    ciphertexts.append(data)
                    continue
            
            # Parse JSON and reconstruct Paillier ciphertext
            if isinstance(data, str):
                try:
                    json_data = json.loads(data)
                    # Verify it's encrypted with the shared key
                    if str(public_key.n) != str(json_data["public_key_n"]):
                        continue  # Skip ciphertexts encrypted with different keys
                    
                    # Reconstruct the EncryptedNumber from JSON components
                    cipher_bytes = paillier_utils.reconstruct_from_json(json_data)
                    ciphertexts.append(cipher_bytes)
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON in paillier_ciphertext: {e}")
                    continue

        if not ciphertexts:
            return {
                "count": 0,
                "total_encrypted": None,
                "average_encrypted": None,
                "total_decrypted": 0,
                "average_decrypted": 0.0,
                "message": "No valid Paillier ciphertexts found"
            }

        # Perform homomorphic addition
        total = ciphertexts[0]
        for c in ciphertexts[1:]:
            total = paillier_utils.add_paillier(total, c)

        # Compute homomorphic average
        average = paillier_utils.avg_paillier(ciphertexts)

        # Convert to JSON-serializable format (still encrypted)
        total_json = paillier_utils.serialize_to_json(total)
        average_json = paillier_utils.serialize_to_json(average)
        
        # Decrypt for demonstration purposes
        total_decrypted = paillier_utils.decrypt_paillier(private_key, total)
        average_decrypted = paillier_utils.decrypt_paillier(private_key, average)

        return {
            "count": len(ciphertexts),
            "total_encrypted": total_json,
            "average_encrypted": average_json,
            "total_decrypted": total_decrypted,
            "average_decrypted": float(average_decrypted),
            "message": f"Successfully aggregated {len(ciphertexts)} encrypted risk scores"
        }

    except Exception as e:
        import traceback
        print(f"Error during Paillier aggregation: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Aggregation error: {e}")
