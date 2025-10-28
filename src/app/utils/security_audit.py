from app.db.init_db import get_db_connection
from typing import Optional
import json

async def log_security_event(
    event_type: str,
    success: bool,
    org_id: Optional[int] = None,
    org_id_attempted: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None
):
    """Log security-related events for audit trail"""
    conn = await get_db_connection()
    try:
        await conn.execute(
            """
            INSERT INTO security_audit_logs 
            (event_type, org_id, org_id_attempted, success, ip_address, user_agent, details)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            event_type,
            org_id,
            org_id_attempted,
            success,
            ip_address,
            user_agent,
            json.dumps(details) if details else None
        )
    finally:
        await conn.close()