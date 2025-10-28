'''
Pydantic models for authentication
includes input verification using regex validator
'''
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime
import re

class OrgRegistration(BaseModel):
    org_id: str = Field(..., min_length=3, max_length=128, description="Unique organization identifier")
    org_name: str = Field(..., min_length=3, max_length=255, description="Organization name")
    email: EmailStr = Field(..., description="Organization contact email")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    contact_email: Optional[str] = None  # Deprecated, use email
    
    @validator('org_id')
    def validate_org_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('org_id can only contain letters, numbers, hyphens, and underscores')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class LoginRequest(BaseModel):
    org_id: str = Field(..., description="Organization ID")
    password: str = Field(..., description="Password")
    
    @validator('org_id')
    def normalize_org_id(cls, v):
        return v.lower().strip()


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    org_id: str
    org_name: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class EmailUpdateRequest(BaseModel):
    email: EmailStr
    password: str  # Require password confirmation


class OrgResponse(BaseModel):
    org_id: str
    org_name: str
    email: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    alerts_submitted: int = 0