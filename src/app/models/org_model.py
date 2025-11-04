from typing import Optional
from pydantic import BaseModel, Field

class OrganizationPublic(BaseModel):
    """Public organization information"""
    org_id: str
    org_name: str
    registered_at: Optional[str] = None


class OrganizationDetail(OrganizationPublic):
    """Detailed organization information including public key"""
    public_key: Optional[str] = None
    key_type: Optional[str] = None


class OrganizationListResponse(BaseModel):
    """Response for listing all organizations"""
    count: int
    organizations: list[OrganizationPublic]


class OrganizationInfoResponse(BaseModel):
    """Response for authenticated org's own info"""
    org_id: str
    org_name: str
    registered_at: Optional[str]
    alerts_submitted: int = 0


class RegistrationResponse(BaseModel):
    """Response after successful registration"""
    status: str = "success"
    org_id: str
    org_name: str
    email: str
    message: str
    encrypted_private_key: str
    key_salt: str
    key_nonce: str
    public_key: str
    warning: str


class KeysResponse(BaseModel):
    """Response for retrieving organization keys"""
    org_id: str
    public_key: str
    private_key: str
    warning: str


class EncryptedKeyResponse(BaseModel):
    """Response for encrypted private key retrieval"""
    encrypted_private_key: str = Field(..., description="Base64-encoded AES-GCM encrypted private key")
    salt: str = Field(..., description="Base64-encoded salt for PBKDF2 key derivation")
    nonce: str = Field(..., description="Base64-encoded nonce/IV for AES-GCM decryption")
    algorithm: str = Field(default="AES-256-GCM-PBKDF2", description="Encryption algorithm used")
    note: str = Field(default="Decrypt with your password on client side. Server cannot decrypt.")


class PaillierPublicKeyResponse(BaseModel):
    """Response for Paillier public key"""
    public_key: dict = Field(..., description="Paillier public key components")
    info: str = Field(default="Use this public key to encrypt risk scores with Paillier encryption")