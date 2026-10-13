# TraceShield

TraceShield is a privacy-preserving cyber incident reporting and secure evidence protection system.

## Phase 1: Foundation

The initial scaffold contains a React/TypeScript client in `frontend/` and a FastAPI service in `backend/`. The API includes environment-driven MySQL connectivity and health endpoints.

### Run the frontend

```powershell
cd frontend
npm install
npm run dev
```

### Run the backend

```powershell
cd backend
Copy-Item .env.example .env
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API is available at `http://localhost:8000`. Check `/api/health` and `/api/health/database`.

Do not commit `.env`, passwords, database credentials, uploaded evidence, or generated evidence shares.

## Phase 2: Authentication and RBAC

The project now includes secure user registration and login with password hashing, JWT-based sessions, and role checks for user and admin access.

### Backend auth endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/auth/admin/users`

The frontend includes a basic registration/login UI for testing token issuance and protected access.

## Phase 3: Incident reporting and evidence

Authenticated users can submit an incident with a title, category, description, and optional evidence files. Evidence is validated by extension and media type, capped at 10 MB per file, stored outside the frontend public folder, and recorded with a SHA-256 integrity hash.

Incident endpoints:

- `POST /api/incidents`
- `GET /api/incidents`
- `GET /api/incidents/{incident_code}`
- `PATCH /api/incidents/{incident_code}/status` for admins

Regular users can only view their own incidents. Admins can review all incidents. Public registration always creates a normal user account; elevated admin access must be provisioned separately. The public dashboard is the default frontend page. Reporting redirects unauthenticated visitors to login, and admin accounts cannot submit incidents.

## Privacy processing and audit logging

Incident titles and descriptions are processed before storage with deterministic masking for email addresses, phone numbers, and IPv4 addresses. A `privacy_records` row stores only processing metadata (whether PII was detected, how many fields were masked, and which privacy methods ran). It does not duplicate raw PII.

Security-relevant incident creation and status changes are written to `audit_logs`. Audit records contain actor, action, target, outcome, and timestamp, but never passwords, tokens, or incident descriptions. Admins can retrieve the latest audit entries through `GET /api/incidents/audit/logs`.

## Visual cryptography

For PNG and JPEG evidence, an authorized incident owner or admin can call:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/visual-shares
```

The service creates two PNG shares using a 2-out-of-2 visual cryptography scheme. Each share is stored privately with its own SHA-256 hash. A single share is not sufficient to reconstruct the evidence image; both shares are required for visual reconstruction. The generated share metadata is stored in `evidence_shares`.

## Image steganography

For PNG and JPEG evidence, an authorized incident owner or admin can hide a short UTF-8 message in a derived PNG carrier:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/steganography
```

The message is embedded in the image's least-significant color bits. The original evidence remains unchanged. The derived carrier is stored privately, its SHA-256 hash and message byte length are recorded in `stego_artifacts`, and the message can be extracted only by an authorized incident owner or admin:

```text
GET /api/incidents/{incident_code}/steganography/{artifact_id}/message
```

This demonstrates concealment, not encryption: anyone who obtains the carrier and knows the encoding scheme could extract the message, so confidential production data should be encrypted separately.

## Planned phases

1. Foundation and MySQL connection
2. Authentication, password hashing, and RBAC
3. Incident reporting and validated evidence uploads
4. Visual cryptography and image, text, and audio steganography
5. Privacy preservation, anonymization, PII masking, integrity checks, and defensive controls
6. Admin dashboard and audit logging
