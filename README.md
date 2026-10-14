# TraceShield

## Privacy-Preserving Cyber Incident Reporting and Secure Evidence Protection System

TraceShield is an information security project that provides a controlled platform for reporting cyber incidents and protecting sensitive digital evidence. It combines incident reporting, privacy preservation, evidence integrity, visual cryptography, steganography, authentication, role-based access control, and auditability.

This README is also structured as a reference for preparing the project presentation, project report, demonstration script, and viva explanation.

## 1. Project overview

Cyber incident reports can contain personal information, confidential messages, screenshots, documents, and media files. If these reports are stored or shared without protection, the information may be exposed, modified, or accessed by unauthorized people.

TraceShield addresses this problem by:

1. Allowing a user to report a cyber incident.
2. Masking common personally identifiable information before storage.
3. Validating and privately storing uploaded evidence.
4. Generating SHA-256 integrity hashes.
5. Splitting supported images into visual cryptography shares.
6. Hiding messages in image, text, and audio evidence through steganography.
7. Restricting access using authentication and RBAC.
8. Giving administrators an investigation dashboard.
9. Recording security-relevant actions in audit logs.

## 2. Problem statement

Traditional incident reporting systems may expose reporter identity, store evidence in publicly reachable folders, lack integrity verification, and provide limited accountability for administrative access. TraceShield is designed to minimize these risks while keeping the reporting and investigation process practical.

## 3. Objectives

- Build a secure cyber incident reporting platform.
- Protect reporter privacy through PII masking and data minimization.
- Preserve evidence confidentiality through authorization and private storage.
- Demonstrate visual cryptography for image sharing.
- Demonstrate image, text, and audio steganography.
- Verify evidence integrity using SHA-256 hashes.
- Enforce user/admin permissions.
- Prevent common web application threats.
- Maintain an auditable investigation history.

## 4. Technology stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Database | MySQL |
| ORM | SQLAlchemy |
| Authentication | JWT access tokens |
| Password hashing | Argon2 |
| Image processing | Pillow |
| Audio processing | Python standard-library WAV support |
| API documentation | FastAPI Swagger UI |

## 5. System architecture

```text
User/Admin browser
        |
        | React + TypeScript frontend
        v
FastAPI REST API
        |
        +--> Authentication and RBAC
        +--> Privacy processing
        +--> Evidence validation and hashing
        +--> Visual cryptography
        +--> Image/text/audio steganography
        +--> Audit logging and rate limiting
        |
        +--> MySQL metadata database
        +--> Private evidence storage
```

The database stores metadata, relationships, hashes, privacy information, and audit records. Original evidence and derived files are stored outside the frontend public directory.

## 6. User roles

### Regular user

A regular user can:

- Register and log in.
- Submit a cyber incident.
- Upload evidence.
- View their own incident data.
- Generate visual shares.
- Hide and extract messages from supported evidence.
- Download their authorized files.
- Log out.

A regular user cannot view another user's incidents, change incident status, or view admin audit logs.

### Administrator

An administrator can:

- View all incidents.
- Review masked incident descriptions and evidence metadata.
- Preview image evidence.
- Download authorized original evidence.
- Download visual shares and protected artifacts.
- Reconstruct visual shares.
- Update incident status.
- Review audit logs.

Administrators cannot create incidents. Public registration always creates a regular `user` account.

## 7. End-to-end project flow

```text
Open public dashboard
        |
Register or log in
        |
User submits incident and evidence
        |
PII masking + pseudonymous incident code
        |
File validation + private storage + SHA-256 hash
        |
Optional evidence protection
        |
Admin reviews authorized incident
        |
Admin retrieves evidence and updates status
        |
Security actions are recorded in audit logs
```

## 8. Functional modules

### Module 1: Public dashboard

The public dashboard is the default page. A visitor can view the TraceShield purpose and platform capabilities. The `Register / Login` button opens authentication only when selected. Selecting `Report an incident` without logging in redirects the visitor to login.

### Module 2: Authentication and account management

Endpoints:

```text
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
GET  /api/auth/admin/users
```

Passwords are never stored directly. They are hashed using Argon2. Login returns a JWT access token, which is required for protected API operations.

### Module 3: Incident reporting

Endpoints:

```text
POST  /api/incidents
GET   /api/incidents
GET   /api/incidents/{incident_code}
PATCH /api/incidents/{incident_code}/status
```

Users submit:

- Incident title
- Category
- Description
- Optional evidence files

The backend creates a pseudonymous incident code such as `TS-1794C5E86660F94B`.

### Module 4: Privacy preservation

The system masks common PII in incident titles and descriptions before storage:

- Email addresses
- Phone numbers
- IPv4 addresses

Privacy metadata records whether PII was detected, how many fields were masked, and which processing methods were used. Raw PII is not duplicated in the privacy record.

### Module 5: Evidence validation and integrity

Supported upload types include:

- PNG and JPEG
- PDF
- TXT
- WAV
- MP3
- MP4

Each file is limited to 10 MB. The backend checks the extension and declared media type, generates a randomized storage filename, stores the file privately, and calculates a SHA-256 hash.

SHA-256 is used to answer:

> Is the evidence file the same as the file that was originally submitted?

It verifies integrity; it does not encrypt the file.

### Module 6: Visual cryptography

Visual cryptography is used for supported PNG and JPEG evidence.

```text
Original image
      |
      +--> Share 1
      +--> Share 2
                 |
                 +--> Reconstruct using both shares
```

TraceShield uses a 2-out-of-2 model. One share alone is not sufficient to reconstruct the image. Both shares are stored privately with individual SHA-256 hashes.

Endpoint:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/visual-shares
```

### Module 7: Image steganography

Image steganography hides a short UTF-8 message inside a derived PNG carrier using least-significant-bit encoding.

```text
Original image + secret message
              |
              v
Protected carrier image
```

The image normally looks unchanged to the human eye. The message is read through extraction, not by visually inspecting the image.

Endpoints:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/steganography
GET  /api/incidents/{incident_code}/steganography/{artifact_id}/message
```

Steganography is concealment, not encryption.

### Module 8: Text steganography

Text steganography hides a UTF-8 message using invisible zero-width characters in a derived text carrier. The visible text remains readable, while the hidden payload can be extracted by an authorized user.

Endpoints:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/text-steganography
GET  /api/incidents/{incident_code}/text-steganography/{artifact_id}/message
```

### Module 9: Audio steganography

Audio steganography hides a UTF-8 message in the least-significant bits of uncompressed 16-bit PCM WAV sample bytes.

Endpoints:

```text
POST /api/incidents/{incident_code}/evidence/{evidence_id}/audio-steganography
GET  /api/incidents/{incident_code}/audio-steganography/{artifact_id}/message
```

Only suitable WAV files are supported. MP3 and unsupported WAV formats are rejected for this operation.

### Module 10: Admin investigation and retrieval

The admin dashboard displays incident status, category, masked description, reporter reference, evidence count, and audit activity.

Authorized retrieval endpoints include:

```text
GET  /api/incidents/{incident_code}/evidence/{evidence_id}/download
GET  /api/incidents/{incident_code}/evidence/{evidence_id}/preview
GET  /api/incidents/{incident_code}/evidence/{evidence_id}/shares/{share_id}/download
POST /api/incidents/{incident_code}/evidence/{evidence_id}/visual-shares/reconstruct
GET  /api/incidents/{incident_code}/evidence/{evidence_id}/artifacts/{artifact_type}/{artifact_id}/download
```

Image evidence can be previewed. Other evidence types are downloaded. Original evidence, shares, reconstructed images, and steganography carriers are not placed in a public frontend folder.

### Module 11: Audit logging

Audit records contain:

- Actor ID
- Action
- Target type
- Target ID
- Outcome
- Timestamp

Examples of audited actions:

- Incident creation
- Status update
- Visual-share generation
- Hidden-message extraction
- Evidence download
- Visual-share reconstruction

Passwords, JWT tokens, and full incident descriptions are not written to audit logs.

### Module 12: Defensive security controls

The application includes:

- Parameterized SQLAlchemy database operations
- JWT authentication
- Role-based authorization
- Argon2 password hashing
- File extension and media-type validation
- Maximum upload size
- Randomized storage filenames
- Private evidence storage
- SHA-256 integrity hashes
- In-process rate limiting
- Security response headers
- React escaped JSX rendering
- Restrictive Content Security Policy

Rate limits:

| Endpoint | Limit |
|---|---|
| Login | 5 requests/minute/client |
| Registration | 5 requests/minute/client |
| Incident creation | 10 requests/minute/client |

Rate-limited requests receive HTTP `429` and a `Retry-After` header.

## 9. Database design

| Table | Purpose |
|---|---|
| `users` | Credentials, roles, account status |
| `incidents` | Incident code, masked content, category, status, reporter |
| `evidence` | File metadata, private path, media type, hash |
| `evidence_shares` | Visual cryptography share metadata and hashes |
| `stego_artifacts` | Image steganography carrier metadata |
| `text_stego_artifacts` | Text steganography carrier metadata |
| `audio_stego_artifacts` | Audio steganography carrier metadata |
| `privacy_records` | Minimal PII-processing metadata |
| `audit_logs` | Security-relevant activity history |

## 10. Demonstration script

Use this order for a project presentation:

1. Open the public dashboard.
2. Show that reporting redirects an unauthenticated visitor to login.
3. Register a normal user.
4. Log in as the user.
5. Submit an incident with an image, text file, or WAV file.
6. Show the pseudonymous incident code and SHA-256 hash.
7. Enter a hidden message and demonstrate the appropriate steganography operation.
8. Extract the message and show that it is not visible to the naked eye in the image carrier.
9. Generate two visual shares for an image.
10. Log out and log in as an administrator.
11. Show the admin incident queue.
12. Preview or download authorized evidence.
13. Download Share 1 and Share 2 or click Reconstruct directly.
14. Update the incident status.
15. Show the corresponding audit logs.

Important explanation:

- Downloading Share 1 and Share 2 is optional before reconstruction.
- The backend already stores both shares, so `Reconstruct` can be clicked directly.
- `Preview` displays the original image.
- `Download` retrieves the original evidence.
- `Hide in image` creates a carrier containing a hidden message.
- `Extract message` reads that hidden message.

## 11. Installation and setup

### Backend

From the repository root:

```powershell
cd D:\IS_lab\IS_prjt
.\.venv\Scripts\Activate.ps1
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend runs at:

```text
http://localhost:8000
```

### Frontend

Open another terminal:

```powershell
cd D:\IS_lab\IS_prjt\frontend
npm install
npm run dev
```

The frontend normally runs at:

```text
http://localhost:5173
```

### Environment configuration

Create `backend/.env` from `backend/.env.example` and configure:

```env
ENVIRONMENT=development
FRONTEND_ORIGIN=http://localhost:5173
MYSQL_URL=mysql+pymysql://username:password@localhost:3306/traceshield
SECRET_KEY=replace-with-a-long-random-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

Do not commit `.env`, database credentials, passwords, uploaded evidence, or generated shares.

### Health checks

```text
GET http://localhost:8000/api/health
GET http://localhost:8000/api/health/database
```

Swagger API documentation:

```text
http://localhost:8000/docs
```

## 12. Security design explanation

TraceShield uses different mechanisms for different security goals:

| Mechanism | Security goal |
|---|---|
| Authentication | Verify who is using the system |
| RBAC | Decide what that user is allowed to do |
| PII masking | Reduce exposure of personal information |
| Data minimization | Avoid storing unnecessary information |
| SHA-256 | Detect evidence changes |
| Visual cryptography | Require multiple shares to reconstruct an image |
| Steganography | Conceal a message in a carrier |
| Private storage | Prevent public URL access to evidence |
| Audit logging | Track security-relevant actions |
| Rate limiting | Reduce repeated automated requests |
| Security headers | Reduce browser-based attack risks |

Visual cryptography, steganography, and encryption are not interchangeable. TraceShield demonstrates visual cryptography and steganography; highly confidential production messages should additionally be encrypted.

## 13. Project status

### Implemented

- React/FastAPI/MySQL foundation
- User authentication and Argon2 password hashing
- JWT sessions
- User/admin RBAC
- Incident reporting
- Evidence validation and private storage
- PII masking and privacy records
- SHA-256 integrity hashes
- Visual cryptography
- Image steganography
- Text steganography
- Audio steganography
- Rate limiting
- Security headers and XSS-safe rendering
- Admin dashboard
- Secure evidence preview and retrieval
- Audit logging

### Optional future improvements

- Alembic database migrations
- Automated unit and integration tests
- HTTPS deployment
- Redis-backed rate limiting for multiple workers
- Malware scanning for uploaded evidence
- Object storage such as S3 or MinIO
- Database backups and monitoring
- Refresh-token rotation
- Stronger production secret management

## 14. Conclusion

TraceShield provides a secure and privacy-aware workflow for cyber incident reporting and evidence handling. It protects users through authentication, RBAC, privacy processing, private storage, integrity verification, visual cryptography, steganography, defensive controls, and auditability. The project demonstrates how multiple information security concepts can work together in one practical web application.
