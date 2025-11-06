from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.models.auth_model import LoginRequest, TokenResponse, TokenRefreshRequest
from app.db.init_db import get_db_connection
from app.utils.password import verify_password
from app.utils.jwt import create_access_token, create_refresh_token, decode_access_token
from app.utils.security_audit import log_security_event
from datetime import datetime, timedelta

router = APIRouter()
security = HTTPBearer()

# against brute forcing
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest, request: Request):
    """
    Authenticate organization and issue JWT tokens
    """
    conn = await get_db_connection()
    
    try:
        # Fetch organization
        org = await conn.fetchrow(
            """
            SELECT id, org_id, org_name, email, password_hash, is_active,
                   failed_login_attempts, locked_until
            FROM organizations
            WHERE org_id=$1
            """,
            credentials.org_id
        )
        
        if not org:
            await log_security_event(
                "login_failed",
                False,
                org_id_attempted=credentials.org_id,
                ip_address=request.client.host,
                details={"reason": "org_not_found"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if org["locked_until"] and org["locked_until"] > datetime.utcnow():
            minutes_left = int((org["locked_until"] - datetime.utcnow()).total_seconds() / 60)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked. Try again in {minutes_left} minutes"
            )
        
        # Check if account is active
        if not org["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated"
            )
        
        # Verify password using SHA-512
        if not verify_password(credentials.password, org["password_hash"]):
            # Increment failed attempts
            failed_attempts = org["failed_login_attempts"] + 1
            
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                # Lock account
                locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                await conn.execute(
                    """
                    UPDATE organizations
                    SET failed_login_attempts=$1, locked_until=$2
                    WHERE id=$3
                    """,
                    failed_attempts, locked_until, org["id"]
                )
                
                await log_security_event(
                    "account_locked",
                    False,
                    org_id=org["id"],
                    ip_address=request.client.host,
                    details={"attempts": failed_attempts}
                )
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account locked due to too many failed login attempts"
                )
            else:
                await conn.execute(
                    "UPDATE organizations SET failed_login_attempts=$1 WHERE id=$2",
                    failed_attempts, org["id"]
                )
            
            await log_security_event(
                "login_failed",
                False,
                org_id=org["id"],
                ip_address=request.client.host,
                details={"reason": "invalid_password", "attempts": failed_attempts}
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Reset failed attempts and update last login
        await conn.execute(
            """
            UPDATE organizations
            SET failed_login_attempts=0, locked_until=NULL, last_login=$1
            WHERE id=$2
            """,
            datetime.utcnow(), org["id"]
        )
        
        # Create access token
        access_token = create_access_token(
            data={"sub": org["org_id"], "org_id": org["id"], "type": "access"}
        )
        
        # Create refresh token
        refresh_token = create_refresh_token()
        refresh_expires = datetime.utcnow() + timedelta(days=7)
        
        # Store refresh token
        await conn.execute(
            """
            INSERT INTO refresh_tokens (token, org_id, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5)
            """,
            refresh_token,
            org["id"],
            refresh_expires,
            request.headers.get("user-agent"),
            request.client.host
        )
        
        # Log successful login
        await log_security_event(
            "login_success",
            True,
            org_id=org["id"],
            ip_address=request.client.host
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=60 * 60,  # 1 hour in seconds
            org_id=org["org_id"],
            org_name=org["org_name"]
        )
        
    finally:
        await conn.close()


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(token_request: TokenRefreshRequest, request: Request):
    """
    Refresh access token using refresh token
    """
    conn = await get_db_connection()
    
    try:
        # Validate refresh token
        token_record = await conn.fetchrow(
            """
            SELECT rt.id, rt.org_id, rt.expires_at, rt.revoked,
                   o.org_id as org_id_str, o.org_name, o.is_active
            FROM refresh_tokens rt
            JOIN organizations o ON rt.org_id = o.id
            WHERE rt.token=$1
            """,
            token_request.refresh_token
        )
        
        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        if token_record["revoked"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked"
            )
        
        if token_record["expires_at"] < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        
        if not token_record["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated"
            )
        
        # Create new access token
        access_token = create_access_token(
            data={
                "sub": token_record["org_id_str"],
                "org_id": token_record["org_id"],
                "type": "access"
            }
        )
        
        # Create new refresh token
        new_refresh_token = create_refresh_token()
        refresh_expires = datetime.utcnow() + timedelta(days=7)
        
        # Revoke old refresh token
        await conn.execute(
            "UPDATE refresh_tokens SET revoked=TRUE, revoked_at=$1 WHERE id=$2",
            datetime.utcnow(), token_record["id"]
        )
        
        # Store new refresh token
        await conn.execute(
            """
            INSERT INTO refresh_tokens (token, org_id, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5)
            """,
            new_refresh_token,
            token_record["org_id"],
            refresh_expires,
            request.headers.get("user-agent"),
            request.client.host
        )
        
        await log_security_event(
            "token_refresh",
            True,
            org_id=token_record["org_id"],
            ip_address=request.client.host
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=60 * 60,
            org_id=token_record["org_id_str"],
            org_name=token_record["org_name"]
        )
        
    finally:
        await conn.close()


@router.post("/logout")
async def logout(
    refresh_token: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Logout by revoking refresh token
    """
    conn = await get_db_connection()
    
    try:
        # Decode access token to get org_id
        payload = decode_access_token(credentials.credentials)
        
        # Revoke refresh token
        await conn.execute(
            """
            UPDATE refresh_tokens
            SET revoked=TRUE, revoked_at=$1
            WHERE token=$2 AND org_id=$3
            """,
            datetime.utcnow(), refresh_token, payload["org_id"]
        )
        
        await log_security_event(
            "logout",
            True,
            org_id=payload["org_id"]
        )
        
        return {"message": "Logged out successfully"}
        
    finally:
        await conn.close()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependency to get current authenticated user from JWT
    Use this instead of verify_token
    """
    try:
        payload = decode_access_token(credentials.credentials)
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

