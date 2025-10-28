'Org management endpoints'
from fastapi import APIRouter, HTTPException, Depends, Request
from app.db.init_db import get_db_connection
from app.crypto import rsa_utils
from app.api.v1.auth import get_current_user  
from pathlib import Path
from app.models.auth_model import OrgRegistration
from app.utils.password import hash_password
from app.utils.security_audit import log_security_event


router = APIRouter()


@router.post("/register")
async def register_organization(org_data: OrgRegistration, request: Request):
    """Register new organization with password and generate RSA keypair."""
    try:
        conn = await get_db_connection()
        
        # Check if org_id already exists
        existing = await conn.fetchrow(
            "SELECT org_id FROM organizations WHERE org_id=$1",
            org_data.org_id
        )
        
        if existing:
            await log_security_event(
                "registration_failed",
                False,
                org_id_attempted=org_data.org_id,
                ip_address=request.client.host,
                details={"reason": "org_id_already_exists"}
            )
            await conn.close()
            raise HTTPException(status_code=409, detail=f"Organization {org_data.org_id} already exists")
        
        # Check if email already exists
        existing_email = await conn.fetchrow(
            "SELECT email FROM organizations WHERE email=$1",
            org_data.email
        )
        
        if existing_email:
            await conn.close()
            raise HTTPException(status_code=409, detail="Email already registered")
        
        # Hash password using SHA-512
        password_hash = hash_password(org_data.password)
        
        # Insert organization with password
        org_id_db = await conn.fetchval(
            """
            INSERT INTO organizations (org_id, org_name, email, password_hash, is_active)
            VALUES ($1, $2, $3, $4, TRUE)
            RETURNING id
            """,
            org_data.org_id, org_data.org_name, org_data.email, password_hash
        )
        
        # Generate RSA keypair for signing
        priv_key, pub_key = rsa_utils.generate_rsa_keypair()
        pub_pem = rsa_utils.serialize_public_key(pub_key)
        priv_pem = rsa_utils.serialize_private_key(priv_key)
        
        # Store ONLY public key in database
        await conn.execute(
            """
            INSERT INTO rsa_keys (org_id, public_key, key_type, is_active)
            VALUES ($1, $2, 'signing', TRUE)
            """,
            org_id_db, pub_pem.decode()
        )
        
        # Save keys to filesystem (for demo purposes)
        keys_dir = Path(__file__).resolve().parents[4] / "keys"
        keys_dir.mkdir(exist_ok=True)
        
        priv_key_path = keys_dir / f"{org_data.org_id}_private.pem"
        pub_key_path = keys_dir / f"{org_data.org_id}_public.pem"
        
        with open(priv_key_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_key_path, "wb") as f:
            f.write(pub_pem)
        
        # Log successful registration
        await log_security_event(
            "registration_success",
            True,
            org_id=org_id_db,
            org_id_attempted=org_data.org_id,
            ip_address=request.client.host
        )
        
        await conn.close()
        
        return {
            "status": "success",
            "org_id": org_data.org_id,
            "org_name": org_data.org_name,
            "email": org_data.email,
            "message": "Organization registered successfully",
            "private_key": priv_pem.decode(),
            "public_key": pub_pem.decode(),
            "warning": "⚠️ SAVE YOUR PRIVATE KEY NOW - it cannot be retrieved later!"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.get("/list")
async def list_organizations():
    """
    List all registered organizations (public information).
    No authentication required.
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
    No authentication required (public information).
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


@router.get("/me/info")
async def get_my_organization(current_user: dict = Depends(get_current_user)):
    """
    Get information about the authenticated organization.
    Requires JWT authentication.
    """
    org_id = current_user["sub"]  # Extract org_id from JWT payload
    
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
async def get_my_alerts(current_user: dict = Depends(get_current_user)):
    """
    Get all alerts submitted by the authenticated organization.
    Requires JWT authentication.
    """
    org_id = current_user["sub"]  # Extract org_id from JWT payload
    
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
async def get_my_keys(current_user: dict = Depends(get_current_user)):
    """
    Get the RSA keys for the authenticated organization.
    Requires JWT authentication.
    """
    org_id = current_user["sub"]  # Extract org_id from JWT payload
    
    try:
        # Read keys from filesystem
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
            "warning": "⚠️ Private keys exposed for demo purposes only."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve keys: {str(e)}")


@router.get("/paillier/public-key")
async def get_paillier_public_key():
    """
    Get the shared Paillier public key used for homomorphic encryption.
    """
    try:
        from app.crypto.paillier_key_manager import get_public_key_json
        return {
            "public_key": get_public_key_json(),
            "info": "Use this public key to encrypt risk scores with Paillier encryption"
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve Paillier public key: {str(e)}"
        )