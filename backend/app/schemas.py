from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .models import IncidentStatus, UserRole


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=80)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    original_filename: str
    media_type: str
    size_bytes: int
    sha256_hash: str
    created_at: datetime


class EvidenceShareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    share_number: int
    sha256_hash: str
    created_at: datetime


class StegoArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    stored_filename: str
    sha256_hash: str
    message_size_bytes: int
    created_at: datetime


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_code: str
    title: str
    description: str
    category: str
    status: IncidentStatus
    reporter_id: int
    created_at: datetime
    evidence: list[EvidenceResponse] = Field(default_factory=list)
