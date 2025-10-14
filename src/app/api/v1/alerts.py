from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from app.db.init_db import get_db_connection
from app.api.v1.auth import verify_token
#from app.utils.logger import get_logger
from app.crypto import rsa_utils, hmac_utils, paillier_utils, aes_utils
import uuid
import psycopg2
import base64
import json

router = APIRouter()
#logger = get_logger()


@router.get("/")
async def get_alerts():
    return {"status": "ok", "data": []}

# ================= ALERT SUBMISSION ===================
@router.post("/submit")
def submit_alert(alert: dict, org_id: str = Depends(verify_token)):
    """
    Accepts an encrypted alert from a client.
    Expected fields:
        - encrypted_payload (base64)
        - wrapped_aes_key (base64)
        - signature (base64)
        - hmac_beacon (hex string)
        - paillier_ciphertext (optional, base64)
    """
    required_fields = ["encrypted_payload", "wrapped_aes_key", "signature", "hmac_beacon"]
    for field in required_fields:
        if field not in alert:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")

    alert_id = str(uuid.uuid4())

    # ================= VERIFY SIGNATURE ===================
    try:
        # For demo: assume org public key fetched from DB
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT public_key FROM rsa_keys WHERE org_id=(SELECT id FROM organizations WHERE org_id=%s) AND is_active=TRUE", (org_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Public key not found for org")
        pub_pem = row[0].encode()
        public_key = rsa_utils.deserialize_public_key(pub_pem)

        signature = base64.b64decode(alert["signature"])
        encrypted_payload_bytes = base64.b64decode(alert["encrypted_payload"])

        if not rsa_utils.verify_signature(public_key, encrypted_payload_bytes, signature):
            raise HTTPException(status_code=400, detail="Signature verification failed")
    except Exception as e:
        #logger.error(f"Signature verification error: {e}")
        raise HTTPException(status_code=500, detail="Signature verification failed")
    finally:
        cur.close()
        conn.close()

    # ================= STORE ALERT IN DB ===================
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO alerts (
                alert_id, submitter_org_id, encrypted_payload,
                wrapped_aes_key, signature, hmac_beacon, paillier_ciphertext
            ) VALUES (%s, (SELECT id FROM organizations WHERE org_id=%s),
                      %s, %s, %s, %s, %s)
            """,
            (
                alert_id,
                org_id,
                encrypted_payload_bytes,
                base64.b64decode(alert["wrapped_aes_key"]),
                signature,
                alert["hmac_beacon"],
                base64.b64decode(alert["paillier_ciphertext"]) if alert.get("paillier_ciphertext") else None
            )
        )
        conn.commit()
        logger.info(f"Alert {alert_id} submitted by org {org_id}")
        return {"status": "success", "alert_id": alert_id}
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"DB Error while submitting alert: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cur.close()
        conn.close()


# ================= ALERT SEARCH ===================
@router.get("/search")
def search_alerts(hmac_beacon: str, org_id: str = Depends(verify_token)):
    """
    Search alerts by HMAC beacon (equality-based)
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT alert_id, submitter_org_id, created_at
            FROM alerts
            WHERE hmac_beacon = %s
            """,
            (hmac_beacon,)
        )
        results = cur.fetchall()
        return {"alerts": [{"alert_id": r[0], "submitter_org_id": r[1], "created_at": r[2]} for r in results]}
    except psycopg2.Error as e:
        logger.error(f"DB Error while searching alerts: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cur.close()
        conn.close()


# ================= AGGREGATE RISK SCORE ===================

@router.get("/aggregate")
async def aggregate_risk(org_id: str = Depends(verify_token)):
    """
    Aggregate Paillier-encrypted risk scores asynchronously
    """
    try:
        conn = await get_db_connection()
        rows = await conn.fetch(
            "SELECT paillier_ciphertext FROM alerts WHERE paillier_ciphertext IS NOT NULL"
        )
        await conn.close()

        ciphertexts = []
        for row in rows:
            data = row["paillier_ciphertext"]
            if isinstance(data, memoryview):
                data = bytes(data)
            ciphertexts.append(paillier_utils.paillier_ciphertext_from_bytes(data))

        if not ciphertexts:
            return {"total": 0, "average": 0}

        total = ciphertexts[0]
        for c in ciphertexts[1:]:
            total = paillier_utils.add_paillier(total, c)

        average = paillier_utils.avg_paillier(ciphertexts)

        return {"total": str(total), "average": str(average)}

    except Exception as e:
        logger.error(f"Error during Paillier aggregation: {e}")
        raise HTTPException(status_code=500, detail=f"Aggregation error: {str(e)}")
