# src/app/api/v1/orgs.py
from fastapi import APIRouter, HTTPException, Depends
from app.db.init_db import get_db_connection
from app.crypto import rsa_utils
from app.api.v1.auth import generate_api_token, verify_token
from pathlib import Path
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class OrgRegistration(BaseModel):
    org_id: str
    org_name: str
    contact_email: Optional[str] = None


class TokenRequest(BaseModel):
    org_id: str
    # In production, add password or other authentication


@router.post("/register")
async def register_organization(org_data: OrgRegistration):
    """
    Register a new organization with RSA keypair generation.
    This generates signing keys and stores the public key in the database.
    """
    try:
        conn = await get_db_connection()
        
        # Check if org already exists
        existing = await conn.fetchrow(
            "SELECT org_id FROM organizations WHERE org_id=$1",
            org_data.org_id
        )
        
        if existing:
            await conn.close()
            raise HTTPException(status_code=409, detail=f"Organization {org_data.org_id} already exists")
        
        # Insert organization
        await conn.execute(
            "INSERT INTO organizations (org_id, org_name) VALUES ($1, $2)",
            org_data.org_id, org_data.org_name
        )
        
        # Generate RSA keypair for signing
        priv_key, pub_key = rsa_utils.generate_rsa_keypair()
        pub_pem = rsa_utils.serialize_public_key(pub_key)
        priv_pem = rsa_utils.serialize_private_key(priv_key)
        
        # Store public key in database
        await conn.execute(
            """
            INSERT INTO rsa_keys (org_id, public_key, key_type, is_active)
            VALUES ((SELECT id FROM organizations WHERE org_id=$1), $2, 'signing', TRUE)
            """,
            org_data.org_id, pub_pem.decode()
        )
        
        # Save keys to files
        keys_dir = Path(__file__).resolve().parents[4] / "keys"
        keys_dir.mkdir(exist_ok=True)
        
        priv_key_path = keys_dir / f"{org_data.org_id}_private.pem"
        pub_key_path = keys_dir / f"{org_data.org_id}_public.pem"
        
        with open(priv_key_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_key_path, "wb") as f:
            f.write(pub_pem)
        
        await conn.close()
        
        return {
            "status": "success",
            "org_id": org_data.org_id,
            "org_name": org_data.org_name,
            "message": "Organization registered successfully. Private key saved to keys directory.",
            "private_key_path": str(priv_key_path),
            "public_key_path": str(pub_key_path),
            "public_key": pub_pem.decode()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.get("/list")
async def list_organizations():
    """
    List all registered organizations (public information).
    """
    try:
        conn = await get_db_connection()
        rows = await conn.fetch(
            "SELECT org_id, org_name, created_at FROM organizations ORDER BY created_at DESC"
        )
        await conn.close()
        
        return {
            "count": len(rows),
            "organizations": [
                {
                    "org_id": r["org_id"],
                    "org_name": r["org_name"],
                    "registered_at": r["created_at"].isoformat() if r["created_at"] else None
                }
                for r in rows
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/{org_id}")
async def get_organization(org_id: str):
    """
    Get details of a specific organization including their public key.
    """
    try:
        conn = await get_db_connection()
        
        org = await conn.fetchrow(
            "SELECT org_id, org_name, created_at FROM organizations WHERE org_id=$1",
            org_id
        )
        
        if not org:
            await conn.close()
            raise HTTPException(status_code=404, detail=f"Organization {org_id} not found")
        
        # Get public key
        key = await conn.fetchrow(
            """
            SELECT public_key, key_type, created_at 
            FROM rsa_keys 
            WHERE org_id=(SELECT id FROM organizations WHERE org_id=$1) AND is_active=TRUE
            """,
            org_id
        )
        
        await conn.close()
        
        return {
            "org_id": org["org_id"],
            "org_name": org["org_name"],
            "registered_at": org["created_at"].isoformat() if org["created_at"] else None,
            "public_key": key["public_key"] if key else None,
            "key_type": key["key_type"] if key else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.post("/token")
async def get_api_token(credentials: TokenRequest):
    """
    Generate API token for an organization.
    In production, this should verify credentials (password, OAuth, etc.)
    """
    try:
        conn = await get_db_connection()
        row = await conn.fetchrow(
            "SELECT id, org_name FROM organizations WHERE org_id=$1",
            credentials.org_id
        )
        await conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Generate token
        token = await generate_api_token(credentials.org_id)
        
        return {
            "token": token,
            "org_id": credentials.org_id,
            "org_name": row["org_name"],
            "token_type": "bearer",
            "message": "Use this token in Authorization header: Bearer <token>"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token generation failed: {str(e)}")


@router.get("/me/info")
async def get_my_organization(org_id: str = Depends(verify_token)):
    """
    Get information about the authenticated organization.
    """
    try:
        conn = await get_db_connection()
        
        org = await conn.fetchrow(
            "SELECT org_id, org_name, created_at FROM organizations WHERE org_id=$1",
            org_id
        )
        
        # Count alerts submitted by this org
        alert_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM alerts 
            WHERE submitter_org_id=(SELECT id FROM organizations WHERE org_id=$1)
            """,
            org_id
        )
        
        await conn.close()
        
        return {
            "org_id": org["org_id"],
            "org_name": org["org_name"],
            "registered_at": org["created_at"].isoformat() if org["created_at"] else None,
            "alerts_submitted": alert_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/me/alerts")
async def get_my_alerts(org_id: str = Depends(verify_token)):
    """
    Get all alerts submitted by the authenticated organization.
    """
    try:
        conn = await get_db_connection()
        
        rows = await conn.fetch(
            """
            SELECT alert_id, created_at, hmac_beacon
            FROM alerts
            WHERE submitter_org_id=(SELECT id FROM organizations WHERE org_id=$1)
            ORDER BY created_at DESC
            """,
            org_id
        )
        
        await conn.close()
        
        return {
            "org_id": org_id,
            "count": len(rows),
            "alerts": [
                {
                    "alert_id": r["alert_id"],
                    "submitted_at": r["created_at"].isoformat() if r["created_at"] else None,
                    "hmac_beacon": r["hmac_beacon"]
                }
                for r in rows
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/me/keys")
async def get_my_keys(org_id: str = Depends(verify_token)):
    """
    Get the RSA keys for the authenticated organization.
    WARNING: In production, private keys should NEVER be exposed via API.
    This is only for demonstration purposes.
    """
    try:
        # Read keys from file system
        keys_dir = Path(__file__).resolve().parents[4] / "keys"
        priv_key_path = keys_dir / f"{org_id}_private.pem"
        pub_key_path = keys_dir / f"{org_id}_public.pem"
        
        if not priv_key_path.exists() or not pub_key_path.exists():
            raise HTTPException(
                status_code=404, 
                detail="Keys not found. Please ensure the organization was properly registered."
            )
        
        with open(priv_key_path, "r") as f:
            private_key = f.read()
        
        with open(pub_key_path, "r") as f:
            public_key = f.read()
        
        return {
            "org_id": org_id,
            "public_key": public_key,
            "private_key": private_key,
            "warning": "Private keys exposed for demo purposes only. NEVER do this in production!"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve keys: {str(e)}")


@router.get("/paillier/public-key")
async def get_paillier_public_key():
    """
    Get the shared Paillier public key used for homomorphic encryption.
    All organizations use this same key to encrypt risk scores,
    enabling homomorphic aggregation without decryption.
    """
    try:
        from app.crypto.paillier_key_manager import get_public_key_json
        return {
            "public_key": get_public_key_json(),
            "info": "Use this public key to encrypt risk scores with Paillier encryption"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve Paillier public key: {str(e)}")
