from dataclasses import dataclass
from datetime import datetime

@dataclass
class Organization:
    id: int
    org_id: str
    org_name: str
    created_at: datetime