from fastapi import APIRouter, HTTPException, Depends
from app.db.init_db import get_db_connection
from app.api.v1.auth import get_current_user 
from app.models.alert_model import (
    AlertSubmission, 
    AlertResponse, 
    AlertSearchResponse,
    AlertSearchResult,
    AggregateResponse,
    DecryptAlertResponse,
    AnalyticsSummaryResponse,
    DailyCount,
    RiskTrend
)
from app.crypto import rsa_utils, hmac_utils, paillier_utils, aes_utils
from pydantic import BaseModel
from typing import List
import uuid
import base64
import json

router = APIRouter()

class ShareAlertRequest(BaseModel):
    shares: dict  # {recipient_org_id: wrapped_aes_key_base64}


@router.get("/", tags=["Alerts"])
async def get_alerts():
    return {"status": "ok", "message": "Alerts API is running"}


@router.post("/submit", response_model=AlertResponse, tags=["Alerts"])
async def submit_alert(alert: AlertSubmission, current_user: dict = Depends(get_current_user)):  
    org_id = current_user["sub"]
    alert_id = str(uuid.uuid4())

    # Verify signature
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

        signature = base64.b64decode(alert.signature)
        encrypted_payload_bytes = base64.b64decode(alert.encrypted_payload)

        if not rsa_utils.verify_signature(public_key, encrypted_payload_bytes, signature):
            raise HTTPException(status_code=403, detail="Signature verification failed")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signature verification failed: {e}")

  
    try:
        from app.crypto.paillier_key_manager import get_public_key
        
        paillier_data = None
        if alert.paillier_ciphertext:
            paillier_json_str = alert.paillier_ciphertext
            paillier_json = json.loads(paillier_json_str)
            
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
                wrapped_aes_key, signature, hmac_beacon, paillier_ciphertext,
                alert_type, severity
            ) VALUES ($1, (SELECT id FROM organizations WHERE org_id=$2),
                      $3, $4, $5, $6, $7, $8, $9)
            """,
            alert_id,
            org_id,
            encrypted_payload_bytes,
            base64.b64decode(alert.wrapped_aes_key),
            signature,
            alert.hmac_beacon,
            paillier_data.encode('utf-8') if paillier_data else None,
            alert.alert_type,
            alert.severity
        )
        
        return AlertResponse(
            alert_id=alert_id,
            message=f"Alert submitted successfully by {org_id}"
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        await conn.close()


@router.get("/search", response_model=AlertSearchResponse, tags=["Alerts"])
async def search_alerts(hmac_beacon: str, current_user: dict = Depends(get_current_user)): 
    """Search alerts by HMAC beacon."""
    org_id = current_user["sub"]
    
    try:
        conn = await get_db_connection()
        rows = await conn.fetch(
            """
            SELECT alert_id, submitter_org_id, created_at
            FROM alerts
            WHERE hmac_beacon = $1
            ORDER BY created_at DESC
            """,
            hmac_beacon
        )
        
        alerts = [
            AlertSearchResult(
                alert_id=r["alert_id"],
                submitter_org_id=r["submitter_org_id"],
                created_at=r["created_at"]
            )
            for r in rows
        ]
        
        return AlertSearchResponse(
            count=len(alerts),
            alerts=alerts,
            search_beacon=hmac_beacon
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")
    finally:
        await conn.close()


@router.get("/aggregate", response_model=AggregateResponse, tags=["Alerts"])
async def aggregate_risk(current_user: dict = Depends(get_current_user)): 
    """Aggregate Paillier-encrypted risk scores."""
    org_id = current_user["sub"]
    
    try:
        from app.crypto.paillier_key_manager import get_public_key, get_private_key
        
        conn = await get_db_connection()
        rows = await conn.fetch("SELECT paillier_ciphertext FROM alerts WHERE paillier_ciphertext IS NOT NULL")
        await conn.close()

        if not rows:
            return AggregateResponse(
                count=0,
                total_encrypted=None,
                average_encrypted=None,
                total_decrypted=0.0,
                average_decrypted=0.0,
                message="No alerts with risk scores found"
            )

        # Get the shared public and private keys
        public_key = get_public_key()
        private_key = get_private_key()
        
        ciphertexts = []
        for row in rows:
            data = row["paillier_ciphertext"]
            
            if isinstance(data, memoryview):
                data = bytes(data)
            
            if isinstance(data, bytes):
                try:
                    data = data.decode('utf-8')
                except UnicodeDecodeError:
                    ciphertexts.append(data)
                    continue
            
            if isinstance(data, str):
                try:
                    json_data = json.loads(data)
                    if str(public_key.n) != str(json_data["public_key_n"]):
                        continue
                    
                    cipher_bytes = paillier_utils.reconstruct_from_json(json_data)
                    ciphertexts.append(cipher_bytes)
                except json.JSONDecodeError:
                    continue

        if not ciphertexts:
            return AggregateResponse(
                count=0,
                total_encrypted=None,
                average_encrypted=None,
                total_decrypted=0.0,
                average_decrypted=0.0,
                message="No valid Paillier ciphertexts found"
            )

        total = ciphertexts[0]
        for c in ciphertexts[1:]:
            total = paillier_utils.add_paillier(total, c)

        average = paillier_utils.avg_paillier(ciphertexts)
        total_json = paillier_utils.serialize_to_json(total)
        average_json = paillier_utils.serialize_to_json(average)
        
        total_decrypted = paillier_utils.decrypt_paillier(private_key, total)
        average_decrypted = paillier_utils.decrypt_paillier(private_key, average)

        return AggregateResponse(
            count=len(ciphertexts),
            total_encrypted=total_json,
            average_encrypted=average_json,
            total_decrypted=float(total_decrypted),
            average_decrypted=float(average_decrypted),
            message=f"Successfully aggregated {len(ciphertexts)} encrypted risk scores"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Aggregation failed: {str(e)}")


@router.get("/{alert_id}/decrypt", response_model=DecryptAlertResponse, tags=["Alerts"])
async def decrypt_my_alert(alert_id: str, current_user: dict = Depends(get_current_user)):
    """Get your own alert for client-side decryption. Only your submitted alerts."""
    org_id = current_user["sub"]
    
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow(
            """
            SELECT a.alert_id, a.encrypted_payload, a.wrapped_aes_key
            FROM alerts a
            JOIN organizations o ON a.submitter_org_id = o.id
            WHERE a.alert_id = $1 AND o.org_id = $2
            """,
            alert_id,
            org_id
        )
        
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found or not yours")
        
        return DecryptAlertResponse(
            alert_id=row["alert_id"],
            encrypted_payload=base64.b64encode(row["encrypted_payload"]).decode(),
            wrapped_aes_key=base64.b64encode(row["wrapped_aes_key"]).decode()
        )
    finally:
        await conn.close()


@router.get("/analytics/summary", response_model=AnalyticsSummaryResponse, tags=["Alerts"])
async def get_analytics_summary(days: int = 7, current_user: dict = Depends(get_current_user)):
    from datetime import datetime, timedelta
    from app.crypto.paillier_key_manager import get_private_key, get_public_key
    
    conn = await get_db_connection()
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        total_count = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= $1",
            start_date
        )
        
        type_distribution = await conn.fetch(
            """
            SELECT COALESCE(alert_type, 'unknown') as type, COUNT(*) as count
            FROM alerts WHERE created_at >= $1
            GROUP BY alert_type
            """,
            start_date
        )
        
        daily_counts = await conn.fetch(
            """
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM alerts WHERE created_at >= $1
            GROUP BY DATE(created_at) ORDER BY date
            """,
            start_date
        )
        
        risk_stats = await conn.fetch(
            """
            SELECT DATE(created_at) as date, paillier_ciphertext
            FROM alerts
            WHERE created_at >= $1 AND paillier_ciphertext IS NOT NULL
            ORDER BY date
            """,
            start_date
        )
        
        participating_orgs = await conn.fetchval(
            "SELECT COUNT(DISTINCT submitter_org_id) FROM alerts WHERE created_at >= $1",
            start_date
        )
        
        type_counts = {row["type"]: row["count"] for row in type_distribution}
        daily_data = [DailyCount(date=row["date"].isoformat(), count=row["count"]) for row in daily_counts]
        
        private_key = get_private_key()
        shared_public_key = get_public_key()
        daily_risk = {}
        
        for row in risk_stats:
            date_str = row["date"].isoformat()
            if date_str not in daily_risk:
                daily_risk[date_str] = []
            
            try:
                cipher_data = row["paillier_ciphertext"]
                if isinstance(cipher_data, memoryview):
                    cipher_data = bytes(cipher_data)
                if isinstance(cipher_data, bytes):
                    cipher_data = cipher_data.decode('utf-8')
                
                if isinstance(cipher_data, str):
                    json_data = json.loads(cipher_data)
                    if str(shared_public_key.n) == str(json_data.get("public_key_n")):
                        cipher_bytes = paillier_utils.reconstruct_from_json(json_data)
                        risk_value = paillier_utils.decrypt_paillier(private_key, cipher_bytes)
                        daily_risk[date_str].append(float(risk_value))
            except Exception:
                continue
        
        risk_trends = [
            RiskTrend(
                date=date,
                average_risk=round(sum(scores) / len(scores), 2) if scores else 0.0,
                alert_count=len(scores)
            )
            for date, scores in sorted(daily_risk.items())
        ]
        
        response = AnalyticsSummaryResponse(
            period_days=days,
            total_alerts=total_count,
            alerts_by_type=type_counts,
            daily_counts=daily_data,
            risk_trends=risk_trends,
            participating_orgs=participating_orgs,
            signature="",
            signature_algorithm="RSA-PSS-SHA256"
        )
        
        response_dict = response.dict()
        data_to_sign = {k: v for k, v in response_dict.items() if k not in ['signature', 'signature_algorithm']}
        #js does this differently,using this to ensure that it happens in the same way client side
        def normalize_floats(obj):
            if isinstance(obj, float):
                rounded = round(obj, 2)
                if rounded == int(rounded):
                    return int(rounded)
                return rounded
            elif isinstance(obj, dict):
                return {k: normalize_floats(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [normalize_floats(item) for item in obj]
            return obj
        
        data_to_sign = normalize_floats(data_to_sign)
        
        import os
        server_key_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'keys', 'server_private.pem')
        with open(server_key_path, 'rb') as f:
            server_private_key = rsa_utils.deserialize_private_key(f.read())
        
        data_str = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
        signature = rsa_utils.sign_data(server_private_key, data_str.encode())
        response.signature = base64.b64encode(signature).decode()
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analytics failed: {str(e)}")
    finally:
        await conn.close()


@router.post("/{alert_id}/share", tags=["Alerts - Sharing"])
async def share_alert(
    alert_id: str,
    share_request: ShareAlertRequest,
    current_user: dict = Depends(get_current_user)
):
    org_id = current_user["sub"]
    conn = await get_db_connection()
    
    try:
        alert = await conn.fetchrow(
            """
            SELECT a.alert_id, a.wrapped_aes_key, o.id as submitter_id
            FROM alerts a
            JOIN organizations o ON a.submitter_org_id = o.id
            WHERE a.alert_id = $1 AND o.org_id = $2
            """,
            alert_id, org_id
        )
        
        if not alert:
            raise HTTPException(404, "Alert not found or not owned by you")
        
        # Get recipient org IDs from shares dict
        recipient_org_ids = list(share_request.shares.keys())
        
        # Verify all recipients exist
        recipients = await conn.fetch(
            "SELECT id, org_id FROM organizations WHERE org_id = ANY($1)",
            recipient_org_ids
        )
        
        if len(recipients) != len(recipient_org_ids):
            raise HTTPException(400, "One or more recipients not found")
        
        # Store pre-wrapped keys (already encrypted by frontend)
        shares_created = []
        shares_restored = []
        
        for recipient in recipients:
            wrapped_key_base64 = share_request.shares[recipient["org_id"]]
            wrapped_key_bytes = base64.b64decode(wrapped_key_base64)
            
            # Check if share exists (including revoked ones)
            existing = await conn.fetchrow(
                """
                SELECT revoked FROM alert_shares
                WHERE alert_id = $1 AND shared_with_org_id = $2
                """,
                alert_id, recipient["id"]
            )
            
            if existing:
                if existing["revoked"]:
                    # Un-revoke and update the wrapped key
                    await conn.execute(
                        """
                        UPDATE alert_shares
                        SET revoked = FALSE, revoked_at = NULL, 
                            wrapped_key_for_recipient = $3, shared_at = NOW()
                        WHERE alert_id = $1 AND shared_with_org_id = $2
                        """,
                        alert_id, recipient["id"], wrapped_key_bytes
                    )
                    shares_restored.append(recipient["org_id"])
                else:
                    # Already shared and active, update wrapped key
                    await conn.execute(
                        """
                        UPDATE alert_shares
                        SET wrapped_key_for_recipient = $3
                        WHERE alert_id = $1 AND shared_with_org_id = $2
                        """,
                        alert_id, recipient["id"], wrapped_key_bytes
                    )
                    shares_created.append(recipient["org_id"])
            else:
                # New share
                await conn.execute(
                    """
                    INSERT INTO alert_shares (
                        alert_id, shared_by_org_id, shared_with_org_id, wrapped_key_for_recipient
                    ) VALUES ($1, $2, $3, $4)
                    """,
                    alert_id, alert["submitter_id"], recipient["id"], wrapped_key_bytes
                )
                shares_created.append(recipient["org_id"])
        
        await conn.execute(
            "UPDATE alerts SET visibility = 'shared' WHERE alert_id = $1",
            alert_id
        )
        
        result = {"status": "success", "shared_with": shares_created}
        if shares_restored:
            result["restored"] = shares_restored
        
        return result
        
    finally:
        await conn.close()


@router.get("/shared-with-me", tags=["Alerts - Sharing"])
async def get_shared_alerts(current_user: dict = Depends(get_current_user)):
    org_id = current_user["sub"]
    conn = await get_db_connection()
    
    try:
        rows = await conn.fetch(
            """
            SELECT 
                a.alert_id, a.created_at, a.alert_type, a.severity,
                s.shared_at, o.org_id as shared_by, o.org_name
            FROM alert_shares s
            JOIN alerts a ON s.alert_id = a.alert_id
            JOIN organizations o ON s.shared_by_org_id = o.id
            WHERE s.shared_with_org_id = (SELECT id FROM organizations WHERE org_id = $1)
              AND s.revoked = FALSE
            ORDER BY s.shared_at DESC
            """,
            org_id
        )
        
        alerts = [
            {
                "alert_id": r["alert_id"],
                "alert_type": r["alert_type"],
                "severity": r["severity"],
                "shared_by": r["shared_by"],
                "shared_by_name": r["org_name"],
                "shared_at": r["shared_at"].isoformat(),
                "created_at": r["created_at"].isoformat()
            }
            for r in rows
        ]
        
        return {"count": len(alerts), "alerts": alerts}
        
    finally:
        await conn.close()


@router.get("/{alert_id}/shares", tags=["Alerts - Sharing"])
async def get_alert_shares(alert_id: str, current_user: dict = Depends(get_current_user)):
    """Get list of organizations this alert is shared with (only for alert owner)."""
    org_id = current_user["sub"]
    conn = await get_db_connection()
    
    try:
        alert = await conn.fetchrow(
            """
            SELECT id FROM alerts
            WHERE alert_id = $1 AND submitter_org_id = (SELECT id FROM organizations WHERE org_id = $2)
            """,
            alert_id, org_id
        )
        
        if not alert:
            raise HTTPException(404, "Alert not found or not owned by you")
        
        shares = await conn.fetch(
            """
            SELECT o.org_id, o.org_name, s.shared_at, s.revoked
            FROM alert_shares s
            JOIN organizations o ON s.shared_with_org_id = o.id
            WHERE s.alert_id = $1
            ORDER BY s.shared_at DESC
            """,
            alert_id
        )
        
        return {
            "alert_id": alert_id,
            "shares": [{
                "org_id": s["org_id"],
                "org_name": s["org_name"],
                "shared_at": s["shared_at"].isoformat() if s["shared_at"] else None,
                "revoked": s["revoked"]
            } for s in shares]
        }
        
    finally:
        await conn.close()


@router.get("/{alert_id}/get-shared", tags=["Alerts - Sharing"])
async def get_shared_alert(alert_id: str, current_user: dict = Depends(get_current_user)):
    """Get encrypted payload and wrapped key for a shared alert (decryption happens client-side)."""
    org_id = current_user["sub"]
    conn = await get_db_connection()
    
    try:
        share = await conn.fetchrow(
            """
            SELECT s.wrapped_key_for_recipient, a.encrypted_payload
            FROM alert_shares s
            JOIN alerts a ON s.alert_id = a.alert_id
            WHERE a.alert_id = $1 
              AND s.shared_with_org_id = (SELECT id FROM organizations WHERE org_id = $2)
              AND s.revoked = FALSE
            """,
            alert_id, org_id
        )
        
        if not share:
            raise HTTPException(404, "Alert not shared with you")
        
        return {
            "alert_id": alert_id,
            "encrypted_payload": base64.b64encode(share["encrypted_payload"]).decode(),
            "wrapped_aes_key": base64.b64encode(share["wrapped_key_for_recipient"]).decode()
        }
        
    finally:
        await conn.close()


@router.delete("/{alert_id}/share/{recipient_org_id}", tags=["Alerts - Sharing"])
async def revoke_share(
    alert_id: str,
    recipient_org_id: str,
    current_user: dict = Depends(get_current_user)
):
    org_id = current_user["sub"]
    conn = await get_db_connection()
    
    try:
        result = await conn.execute(
            """
            UPDATE alert_shares
            SET revoked = TRUE, revoked_at = NOW()
            WHERE alert_id = $1
              AND shared_by_org_id = (SELECT id FROM organizations WHERE org_id = $2)
              AND shared_with_org_id = (SELECT id FROM organizations WHERE org_id = $3)
            """,
            alert_id, org_id, recipient_org_id
        )
        
        if result == "UPDATE 0":
            raise HTTPException(404, "Share not found")
        
        return {"status": "revoked"}
        
    finally:
        await conn.close()