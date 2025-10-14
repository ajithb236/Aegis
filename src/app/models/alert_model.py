# src/app/models/alert_model.py
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Alert:
    id: int
    alert_id: str
    submitter_org_id: int
    encrypted_payload: bytes
    wrapped_aes_key: bytes
    signature: bytes
    hmac_beacon: str
    paillier_ciphertext: bytes
    created_at: datetime
