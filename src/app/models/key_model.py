from dataclasses import dataclass
from datetime import datetime

@dataclass
class RSAKey:
    id: int
    org_id: int
    public_key: str
    key_type: str
    is_active: bool
    created_at: datetime
