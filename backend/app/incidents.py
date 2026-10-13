import hashlib
import re
import secrets
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .deps import get_current_user, require_role
from .models import (
    AuditLog,
    Evidence,
    EvidenceShare,
    Incident,
    IncidentStatus,
    PrivacyRecord,
    StegoArtifact,
    User,
    UserRole,
)
from .privacy import mask_pii
from .schemas import EvidenceShareResponse, IncidentResponse, StegoArtifactResponse
from .visual_cryptography import create_visual_shares
from .steganography import embed_text, extract_text

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
settings = get_settings()
storage_root = Path(__file__).resolve().parent.parent / "storage" / "evidence"
allowed_extensions = {".png", ".jpg", ".jpeg", ".pdf", ".txt", ".wav", ".mp3", ".mp4"}
allowed_media_types = {
    "image/png", "image/jpeg", "application/pdf", "text/plain",
    "audio/wav", "audio/x-wav", "audio/mpeg", "video/mp4",
}
max_file_size = 10 * 1024 * 1024
image_media_types = {"image/png", "image/jpeg"}


def create_incident_code() -> str:
    return f"TS-{secrets.token_hex(8).upper()}"


def sanitize_filename(filename: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)
    return safe_name[:180] or "evidence"


async def store_evidence(upload: UploadFile, incident_code: str) -> tuple[dict, bytes]:
    original_filename = sanitize_filename(upload.filename or "evidence")
    extension = Path(original_filename).suffix.lower()
    if extension not in allowed_extensions or upload.content_type not in allowed_media_types:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported evidence type. Use an approved file extension and media type.",
        )
    content = await upload.read(max_file_size + 1)
    if len(content) > max_file_size:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Evidence file is too large.")
    stored_filename = f"{uuid4().hex}{extension}"
    relative_path = Path(incident_code) / stored_filename
    return {
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "storage_path": str(relative_path),
        "media_type": upload.content_type,
        "size_bytes": len(content),
        "sha256_hash": hashlib.sha256(content).hexdigest(),
    }, content


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    title: str = Form(..., min_length=5, max_length=160),
    description: str = Form(..., min_length=20, max_length=10000),
    category: str = Form(..., min_length=2, max_length=60),
    files: list[UploadFile] = File(default=[]),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    if current_user.role is not UserRole.user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only user accounts can report incidents.",
        )
    incident_code = create_incident_code()
    masked_title = mask_pii(title.strip())
    masked_description = mask_pii(description.strip())
    total_fields_masked = masked_title.fields_masked + masked_description.fields_masked
    incident = Incident(
        incident_code=incident_code,
        title=masked_title.value,
        description=masked_description.value,
        category=category.strip().lower(),
        reporter_id=current_user.id,
        status=IncidentStatus.submitted,
    )
    incident.privacy_record = PrivacyRecord(
        pii_detected=total_fields_masked > 0,
        fields_masked=total_fields_masked,
        processing_methods=["regex_pii_masking", "data_minimization", "pseudonymous_incident_code"],
    )
    staged_files: list[tuple[dict, bytes]] = []
    for upload in files:
        staged_files.append(await store_evidence(upload, incident_code))
    incident_directory = storage_root / incident_code
    incident_directory.mkdir(parents=True, exist_ok=False)
    for metadata, content in staged_files:
        (storage_root / metadata["storage_path"]).write_bytes(content)
    incident.evidence = [
        Evidence(
            **{
                **metadata,
                "storage_path": str(storage_root / metadata["storage_path"]),
            }
        )
        for metadata, _ in staged_files
    ]
    db.add(incident)
    db.add(
        AuditLog(
            actor_id=current_user.id,
            action="incident_created",
            target_type="incident",
            target_id=incident_code,
            outcome="success",
        )
    )
    try:
        db.commit()
        db.refresh(incident)
    except SQLAlchemyError:
        db.rollback()
        shutil.rmtree(incident_directory, ignore_errors=True)
        raise
    return incident


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Incident]:
    query = db.query(Incident).order_by(Incident.created_at.desc())
    if current_user.role is not UserRole.admin:
        query = query.filter(Incident.reporter_id == current_user.id)
    return query.all()


@router.get("/audit/logs", response_model=list[dict], dependencies=[Depends(require_role(UserRole.admin.value))])
def list_audit_logs(db: Session = Depends(get_db)) -> list[dict]:
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
    return [
        {
            "id": log.id,
            "actor_id": log.actor_id,
            "action": log.action,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "outcome": log.outcome,
            "created_at": log.created_at,
        }
        for log in logs
    ]


@router.get("/{incident_code}", response_model=IncidentResponse)
def get_incident(
    incident_code: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    incident = db.query(Incident).filter(Incident.incident_code == incident_code).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if current_user.role is not UserRole.admin and incident.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot access this incident")
    return incident


@router.post(
    "/{incident_code}/evidence/{evidence_id}/visual-shares",
    response_model=list[EvidenceShareResponse],
)
def generate_visual_shares(
    incident_code: str,
    evidence_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[EvidenceShare]:
    incident = db.query(Incident).filter(Incident.incident_code == incident_code).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if current_user.role is not UserRole.admin and incident.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot access this incident")
    evidence = (
        db.query(Evidence)
        .filter(Evidence.id == evidence_id, Evidence.incident_id == incident.id)
        .first()
    )
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    if evidence.media_type not in image_media_types:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Visual cryptography supports PNG and JPEG evidence only.",
        )
    try:
        share_one, share_two = create_visual_shares(Path(evidence.storage_path).read_bytes())
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Evidence is not a valid image") from exc

    shares_directory = Path(evidence.storage_path).parent / "shares"
    shares_directory.mkdir(parents=True, exist_ok=True)
    generated: list[EvidenceShare] = []
    for share_number, content in enumerate((share_one, share_two), start=1):
        stored_filename = f"{Path(evidence.stored_filename).stem}.share-{share_number}.png"
        share_path = shares_directory / stored_filename
        share_path.write_bytes(content)
        generated.append(
            EvidenceShare(
                evidence_id=evidence.id,
                share_number=share_number,
                stored_filename=stored_filename,
                storage_path=str(share_path),
                sha256_hash=hashlib.sha256(content).hexdigest(),
            )
        )
    db.query(EvidenceShare).filter(EvidenceShare.evidence_id == evidence.id).delete()
    db.add_all(generated)
    db.add(
        AuditLog(
            actor_id=current_user.id,
            action="visual_shares_generated",
            target_type="evidence",
            target_id=str(evidence.id),
            outcome="success",
        )
    )
    db.commit()
    for share in generated:
        db.refresh(share)
    return generated


@router.post(
    "/{incident_code}/evidence/{evidence_id}/steganography",
    response_model=StegoArtifactResponse,
)
def hide_text_in_image(
    incident_code: str,
    evidence_id: int,
    secret: str = Form(..., min_length=1, max_length=5000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StegoArtifact:
    incident = db.query(Incident).filter(Incident.incident_code == incident_code).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if current_user.role is not UserRole.admin and incident.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot access this incident")
    evidence = db.query(Evidence).filter(
        Evidence.id == evidence_id, Evidence.incident_id == incident.id
    ).first()
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    if evidence.media_type not in image_media_types:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Image steganography supports PNG and JPEG evidence only.",
        )
    try:
        carrier_bytes, message_size = embed_text(Path(evidence.storage_path).read_bytes(), secret)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    artifact_directory = Path(evidence.storage_path).parent / "steganography"
    artifact_directory.mkdir(parents=True, exist_ok=True)
    stored_filename = f"{Path(evidence.stored_filename).stem}.stego.png"
    artifact_path = artifact_directory / stored_filename
    artifact_path.write_bytes(carrier_bytes)
    artifact = StegoArtifact(
        evidence_id=evidence.id,
        stored_filename=stored_filename,
        storage_path=str(artifact_path),
        sha256_hash=hashlib.sha256(carrier_bytes).hexdigest(),
        message_size_bytes=message_size,
    )
    db.add(artifact)
    db.add(
        AuditLog(
            actor_id=current_user.id,
            action="image_message_embedded",
            target_type="evidence",
            target_id=str(evidence.id),
            outcome="success",
        )
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.get(
    "/{incident_code}/steganography/{artifact_id}/message",
    response_model=dict[str, str],
)
def extract_hidden_text(
    incident_code: str,
    artifact_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    incident = db.query(Incident).filter(Incident.incident_code == incident_code).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if current_user.role is not UserRole.admin and incident.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot access this incident")
    artifact = db.query(StegoArtifact).join(Evidence).filter(
        StegoArtifact.id == artifact_id, Evidence.incident_id == incident.id
    ).first()
    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Steganography artifact not found")
    try:
        message = extract_text(Path(artifact.storage_path).read_bytes())
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.add(
        AuditLog(
            actor_id=current_user.id,
            action="hidden_message_extracted",
            target_type="evidence",
            target_id=str(artifact.evidence_id),
            outcome="success",
        )
    )
    db.commit()
    return {"message": message}


@router.patch("/{incident_code}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_code: str,
    new_status: IncidentStatus,
    current_user: User = Depends(require_role(UserRole.admin.value)),
    db: Session = Depends(get_db),
) -> Incident:
    incident = db.query(Incident).filter(Incident.incident_code == incident_code).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    incident.status = new_status
    db.add(
        AuditLog(
            actor_id=current_user.id,
            action="incident_status_updated",
            target_type="incident",
            target_id=incident_code,
            outcome="success",
        )
    )
    db.commit()
    db.refresh(incident)
    return incident
