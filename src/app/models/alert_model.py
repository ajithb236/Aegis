from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime


class AlertSubmission(BaseModel):
    """Alert submission request with encrypted data"""
    encrypted_payload: str = Field(..., description="Base64-encoded AES-encrypted alert data")
    wrapped_aes_key: str = Field(..., description="Base64-encoded RSA-wrapped AES key")
    signature: str = Field(..., description="Base64-encoded RSA signature")
    hmac_beacon: str = Field(..., description="HMAC beacon for searchable encryption")
    paillier_ciphertext: Optional[str] = Field(None, description="JSON-serialized Paillier encrypted risk score")
    alert_type: Optional[str] = Field(None, description="Alert type for analytics")
    severity: Optional[str] = Field(None, description="Severity level for analytics")
    
    @validator('encrypted_payload', 'wrapped_aes_key', 'signature', 'hmac_beacon')
    def validate_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Field cannot be empty')
        return v.strip()


class AlertResponse(BaseModel):
    """Response after alert submission"""
    status: str = "success"
    alert_id: str
    message: Optional[str] = "Alert submitted successfully"


class AlertSearchResult(BaseModel):
    """Single alert in search results"""
    alert_id: str
    submitter_org_id: int
    created_at: datetime


class AlertSearchResponse(BaseModel):
    """Response for alert search"""
    count: int
    alerts: list[AlertSearchResult]
    search_beacon: str


class AggregateResponse(BaseModel):
    """Response for homomorphic aggregation"""
    count: int
    total_encrypted: Optional[dict]
    average_encrypted: Optional[dict]
    total_decrypted: float
    average_decrypted: float
    message: str


class AlertListItem(BaseModel):
    """Single alert in organization's alert list"""
    alert_id: str
    submitted_at: str
    hmac_beacon: str


class MyAlertsResponse(BaseModel):
    """Response for organization's submitted alerts"""
    org_id: str
    count: int
    alerts: list[AlertListItem]


class DecryptAlertResponse(BaseModel):
    """Response for alert decryption - client decrypts locally"""
    alert_id: str
    encrypted_payload: str = Field(..., description="Base64-encoded encrypted payload")
    wrapped_aes_key: str = Field(..., description="Base64-encoded wrapped AES key")
    note: str = Field(default="Decrypt with your RSA private key")


class DailyCount(BaseModel):
    date: str
    count: int


class RiskTrend(BaseModel):
    date: str
    average_risk: float
    alert_count: int


class AnalyticsSummaryResponse(BaseModel):
    period_days: int
    total_alerts: int
    alerts_by_type: dict
    daily_counts: list[DailyCount]
    risk_trends: list[RiskTrend]
    participating_orgs: int
    signature: str = Field(..., description="Server signature of analytics data")
    signature_algorithm: str = Field(default="RSA-PSS-SHA256")