from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SQLAlchemyEnum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class UserRole(str, Enum):
    user = "user"
    admin = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SQLAlchemyEnum(UserRole), default=UserRole.user, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    incidents: Mapped[list["Incident"]] = relationship(back_populates="reporter")


class IncidentStatus(str, Enum):
    submitted = "submitted"
    under_review = "under_review"
    resolved = "resolved"
    closed = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_code: Mapped[str] = mapped_column(String(24), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        SQLAlchemyEnum(IncidentStatus), default=IncidentStatus.submitted, nullable=False
    )
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    reporter: Mapped[User] = relationship(back_populates="incidents")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    privacy_record: Mapped["PrivacyRecord | None"] = relationship(
        back_populates="incident", cascade="all, delete-orphan", uselist=False
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    incident: Mapped[Incident] = relationship(back_populates="evidence")
    shares: Mapped[list["EvidenceShare"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    stego_artifacts: Mapped[list["StegoArtifact"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    text_stego_artifacts: Mapped[list["TextStegoArtifact"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    audio_stego_artifacts: Mapped[list["AudioStegoArtifact"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )


class EvidenceShare(Base):
    __tablename__ = "evidence_shares"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), nullable=False, index=True)
    share_number: Mapped[int] = mapped_column(Integer, nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence: Mapped[Evidence] = relationship(back_populates="shares")


class StegoArtifact(Base):
    __tablename__ = "stego_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), nullable=False, index=True)
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    message_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence: Mapped[Evidence] = relationship(back_populates="stego_artifacts")


class TextStegoArtifact(Base):
    __tablename__ = "text_stego_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), nullable=False, index=True)
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    message_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence: Mapped[Evidence] = relationship(back_populates="text_stego_artifacts")


class AudioStegoArtifact(Base):
    __tablename__ = "audio_stego_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), nullable=False, index=True)
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    message_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence: Mapped[Evidence] = relationship(back_populates="audio_stego_artifacts")


class PrivacyRecord(Base):
    __tablename__ = "privacy_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), unique=True, nullable=False, index=True
    )
    pii_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fields_masked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processing_methods: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    incident: Mapped[Incident] = relationship(back_populates="privacy_record")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_id: Mapped[str] = mapped_column(String(80), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
