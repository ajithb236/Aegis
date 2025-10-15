from fastapi import HTTPException, Header, Depends
from app.db.init_db import get_db_connection
import secrets
from typing import Dict

# In-memory token store (use Redis or database in production)
# Format: {token: org_id}
TOKEN_STORE: Dict[str, str] = {}


async def generate_api_token(org_id: str) -> str:
    """
    Generate a secure API token for an organization.
    In production, store this in Redis with expiration or in database with timestamps.
    """
    token = secrets.token_urlsafe(32)
    TOKEN_STORE[token] = org_id
    return token


async def verify_token(authorization: str = Header(None)) -> str:
    """
    Verify API token from Authorization header.
    Expected format: "Bearer <token>"
    Returns the org_id if valid, raises HTTPException otherwise.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication scheme. Use 'Bearer <token>'",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Check if token exists in store
        org_id = TOKEN_STORE.get(token)
        if not org_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Verify organization still exists in database
        conn = await get_db_connection()
        row = await conn.fetchrow(
            "SELECT id FROM organizations WHERE org_id=$1",
            org_id
        )
        await conn.close()
        
        if not row:
            # Remove invalid token from store
            del TOKEN_STORE[token]
            raise HTTPException(
                status_code=403,
                detail="Organization not found or has been deactivated"
            )
        
        return org_id
        
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Authentication error: {str(e)}"
        )


async def revoke_token(token: str) -> bool:
    """
    Revoke an API token.
    Returns True if token was revoked, False if token didn't exist.
    """
    if token in TOKEN_STORE:
        del TOKEN_STORE[token]
        return True
    return False


def get_all_tokens() -> Dict[str, str]:
    """
    Get all active tokens (for debugging/admin purposes only).
    DO NOT expose this in production!
    """
    return TOKEN_STORE.copy()