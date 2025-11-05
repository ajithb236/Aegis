'Org management endpoints'
from fastapi import APIRouter, HTTPException, Depends, Request
from app.db.init_db import get_db_connection
from app.crypto import rsa_utils
from app.api.v1.auth import get_current_user  
from pathlib import Path
from app.models.auth_model import OrgRegistration
from app.models.org_model import (
    RegistrationResponse,
    OrganizationListResponse,
    OrganizationPublic,
    OrganizationDetail,
    OrganizationInfoResponse,
    EncryptedKeyResponse,
    PaillierPublicKeyResponse
)
from app.models.alert_model import MyAlertsResponse, AlertListItem
from app.utils.password import hash_password
from app.utils.security_audit import log_security_event
from app.crypto.password_key_crypto import encrypt_private_key


router = APIRouter()


@router.post("/register", response_model=RegistrationResponse, tags=["Organizations"])
async def register_organization(org_data: OrgRegistration, request: Request):
    """Register new organization with password-protected account."""
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
        
        # Generate RSA keypair for signing
        priv_key, pub_key = rsa_utils.generate_rsa_keypair()
        pub_pem = rsa_utils.serialize_public_key(pub_key)
        priv_pem = rsa_utils.serialize_private_key(priv_key)
        
        # Encrypt private key with password
        encrypted_key_data = encrypt_private_key(priv_pem, org_data.password)
        
        # Insert organization with encrypted key in single query
        org_id_db = await conn.fetchval(
            """
            INSERT INTO organizations (org_id, org_name, email, password_hash, is_active,
                                      encrypted_private_key, key_salt, key_nonce)
            VALUES ($1, $2, $3, $4, TRUE, $5, $6, $7)
            RETURNING id
            """,
            org_data.org_id, org_data.org_name, org_data.email, password_hash,
            encrypted_key_data["encrypted_key"],
            encrypted_key_data["salt"],
            encrypted_key_data["nonce"]
        )
        
        # Store public key in database
        await conn.execute(
            """
            INSERT INTO rsa_keys (org_id, public_key, key_type, is_active)
            VALUES ($1, $2, 'signing', TRUE)
            """,
            org_id_db, pub_pem.decode()
        )
        
        # Log successful registration
        await log_security_event(
            "registration_success",
            True,
            org_id=org_id_db,
            org_id_attempted=org_data.org_id,
            ip_address=request.client.host
        )
        
        await conn.close()
        
        return RegistrationResponse(
            org_id=org_data.org_id,
            org_name=org_data.org_name,
            email=org_data.email,
            message="Organization registered successfully",
            encrypted_private_key=encrypted_key_data["encrypted_key"],
            key_salt=encrypted_key_data["salt"],
            key_nonce=encrypted_key_data["nonce"],
            public_key=pub_pem.decode(),
            warning="⚠️ SAVE ENCRYPTED KEY - Server cannot decrypt. Password lost = Key lost forever."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.get("/list", response_model=OrganizationListResponse, tags=["Organizations"])
async def list_organizations():
    """List all registered organizations."""
    try:
        conn = await get_db_connection()
        rows = await conn.fetch(
            "SELECT org_id, org_name, created_at FROM organizations ORDER BY created_at DESC"
        )
        await conn.close()
        
        orgs = [
            OrganizationPublic(
                org_id=r["org_id"],
                org_name=r["org_name"],
                registered_at=r["created_at"].isoformat() if r["created_at"] else None
            )
            for r in rows
        ]
        
        return OrganizationListResponse(
            count=len(orgs),
            organizations=orgs
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/{org_id}", response_model=OrganizationDetail, tags=["Organizations"])
async def get_organization(org_id: str):
    """Get details of a specific organization including their public key."""
    try:
        conn = await get_db_connection()
        
        org = await conn.fetchrow(
            "SELECT org_id, org_name, created_at FROM organizations WHERE org_id=$1",
            org_id
        )
        
        if not org:
            await conn.close()
            raise HTTPException(status_code=404, detail=f"Organization {org_id} not found")
        
        key = await conn.fetchrow(
            """
            SELECT public_key, key_type, created_at 
            FROM rsa_keys 
            WHERE org_id=(SELECT id FROM organizations WHERE org_id=$1) AND is_active=TRUE
            """,
            org_id
        )
        
        await conn.close()
        
        return OrganizationDetail(
            org_id=org["org_id"],
            org_name=org["org_name"],
            registered_at=org["created_at"].isoformat() if org["created_at"] else None,
            public_key=key["public_key"] if key else None,
            key_type=key["key_type"] if key else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/me/info", response_model=OrganizationInfoResponse, tags=["Organizations - Authenticated"])
async def get_my_organization(current_user: dict = Depends(get_current_user)):
    """Get information about the authenticated organization."""
    org_id = current_user["sub"]
    
    try:
        conn = await get_db_connection()
        
        org = await conn.fetchrow(
            "SELECT org_id, org_name, created_at FROM organizations WHERE org_id=$1",
            org_id
        )
        
        alert_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM alerts 
            WHERE submitter_org_id=(SELECT id FROM organizations WHERE org_id=$1)
            """,
            org_id
        )
        
        await conn.close()
        
        return OrganizationInfoResponse(
            org_id=org["org_id"],
            org_name=org["org_name"],
            registered_at=org["created_at"].isoformat() if org["created_at"] else None,
            alerts_submitted=alert_count
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/me/alerts", response_model=MyAlertsResponse, tags=["Organizations - Authenticated"])
async def get_my_alerts(current_user: dict = Depends(get_current_user)):
    """Get all alerts submitted by the authenticated organization."""
    org_id = current_user["sub"]
    
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
        
        alerts = [
            AlertListItem(
                alert_id=r["alert_id"],
                submitted_at=r["created_at"].isoformat() if r["created_at"] else None,
                hmac_beacon=r["hmac_beacon"]
            )
            for r in rows
        ]
        
        return MyAlertsResponse(
            org_id=org_id,
            count=len(alerts),
            alerts=alerts
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/me/encrypted-key", response_model=EncryptedKeyResponse, tags=["Organizations - Authenticated"])
async def get_my_encrypted_key(current_user: dict = Depends(get_current_user)):
    """Return encrypted private key. Client must decrypt with password."""
    org_id = current_user["sub"]
    
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            """
            SELECT encrypted_private_key, key_salt, key_nonce
            FROM organizations
            WHERE org_id = $1
            """,
            org_id
        )
        
        if not result or not result["encrypted_private_key"]:
            raise HTTPException(status_code=404, detail="Encrypted key not found")
        
        return EncryptedKeyResponse(
            encrypted_private_key=result["encrypted_private_key"],
            salt=result["key_salt"],
            nonce=result["key_nonce"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        await conn.close()


@router.get("/paillier/public-key", response_model=PaillierPublicKeyResponse, tags=["Organizations"])
async def get_paillier_public_key():
    """Get the shared Paillier public key for homomorphic encryption."""
    try:
        from app.crypto.paillier_key_manager import get_public_key_json
        return PaillierPublicKeyResponse(
            public_key=get_public_key_json()
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve Paillier public key: {str(e)}"
        )


@router.get("/server/public-key", tags=["Organizations"])
async def get_server_public_key():
    """Get the server's public key for verifying analytics signatures."""
    try:
        import os
        server_key_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'keys', 'server_public.pem')
        with open(server_key_path, 'r') as f:
            public_key = f.read()
        return {
            "public_key": public_key,
            "algorithm": "RSA-PSS-SHA256",
            "usage": "Server signature verification for analytics responses"
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve server public key: {str(e)}"
        )