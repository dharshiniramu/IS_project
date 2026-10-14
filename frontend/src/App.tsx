import { useEffect, useMemo, useState, type FormEvent } from 'react'
import './App.css'

type UserRole = 'user' | 'admin'
type AuthMode = 'register' | 'login'
type View = 'home' | 'auth' | 'report' | 'profile'
type IncidentStatus = 'submitted' | 'under_review' | 'resolved' | 'closed'

type User = {
  id: number
  username: string
  email: string
  role: UserRole
  is_active: boolean
  created_at: string
}

type AuthResponse = {
  access_token: string
  user: User
}

type Evidence = {
  id: number
  original_filename: string
  media_type: string
  size_bytes: number
  sha256_hash: string
  created_at: string
  shares?: EvidenceShare[]
  stego_artifacts?: ProtectedArtifact[]
  text_stego_artifacts?: ProtectedArtifact[]
  audio_stego_artifacts?: ProtectedArtifact[]
}

type EvidenceShare = { id: number; share_number: number; stored_filename: string; sha256_hash: string }
type ProtectedArtifact = { id: number; stored_filename: string; sha256_hash: string; message_size_bytes: number }

type SubmittedIncident = {
  incident_code: string
  evidence: Evidence[]
}

type Incident = {
  incident_code: string
  title: string
  description: string
  category: string
  status: IncidentStatus
  reporter_id: number
  created_at: string
  evidence: Evidence[]
}

type AuditLog = {
  id: number
  actor_id: number
  action: string
  target_type: string
  target_id: string
  outcome: string
  created_at: string
}

type ProtectionArtifact = {
  id: number
  stored_filename?: string
  sha256_hash: string
  message_size_bytes?: number
}

type StoredArtifact = ProtectionArtifact & {
  type: 'steganography' | 'text-steganography' | 'audio-steganography'
}

const API_BASE = 'http://localhost:8000'
const initialForm = { username: '', email: '', password: '' }

function App() {
  const [view, setView] = useState<View>('home')
  const [mode, setMode] = useState<AuthMode>('register')
  const [form, setForm] = useState(initialForm)
  const [token, setToken] = useState(localStorage.getItem('traceshield-token') ?? '')
  const [currentUser, setCurrentUser] = useState<User | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [incidentForm, setIncidentForm] = useState({ title: '', description: '', category: 'phishing' })
  const [evidenceFiles, setEvidenceFiles] = useState<File[]>([])
  const [submittedIncident, setSubmittedIncident] = useState<SubmittedIncident | null>(null)
  const [secret, setSecret] = useState('')
  const [protectionMessage, setProtectionMessage] = useState('')
  const [artifacts, setArtifacts] = useState<Record<number, StoredArtifact[]>>({})
  const [adminIncidents, setAdminIncidents] = useState<Incident[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [adminLoading, setAdminLoading] = useState(false)

  const fetchProtectedFile = async (path: string, filename: string, preview = false) => {
    setError('')
    try {
      const response = await fetch(`${API_BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) {
        const data = (await response.json()) as { detail?: string }
        throw new Error(data.detail ?? `Unable to retrieve file (${response.status})`)
      }

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      if (preview) {
        window.open(url, '_blank', 'noopener,noreferrer')
      } else {
        const link = document.createElement('a')
        link.href = url
        link.download = filename
        link.click()
      }
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    } catch (fileError) {
      setError(fileError instanceof Error ? fileError.message : 'Unable to retrieve protected file')
    }
  }

  const reconstructShares = async (incident: Incident, evidence: Evidence) => {
    const shares = evidence.shares ?? []
    if (shares.length < 2) return
    setError('')
    try {
      const response = await fetch(`${API_BASE}/api/incidents/${incident.incident_code}/evidence/${evidence.id}/visual-shares/reconstruct?share_one_id=${shares[0].id}&share_two_id=${shares[1].id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) {
        const data = (await response.json()) as { detail?: string }
        throw new Error(data.detail ?? `Unable to reconstruct shares (${response.status})`)
      }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `${evidence.original_filename}.reconstructed.png`
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    } catch (reconstructError) {
      setError(reconstructError instanceof Error ? reconstructError.message : 'Unable to reconstruct visual shares')
    }
  }
  const authTitle = useMemo(() => mode === 'register' ? 'Create your account' : 'Welcome back', [mode])

  useEffect(() => {
    const storedToken = localStorage.getItem('traceshield-token')
    if (storedToken) void fetchCurrentUser(storedToken)
  }, [])

  const fetchCurrentUser = async (authToken: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${authToken}` } })
      if (!response.ok) throw new Error('Unable to load profile')
      setCurrentUser((await response.json()) as User)
    } catch {
      setToken('')
      localStorage.removeItem('traceshield-token')
      setCurrentUser(null)
    }

  }

  const loadAdminDashboard = async (authToken: string = token) => {
    setAdminLoading(true)
    setError('')
    try {
      const headers = { Authorization: `Bearer ${authToken}` }
      const [incidentsResponse, logsResponse] = await Promise.all([
        fetch(`${API_BASE}/api/incidents`, { headers }),
        fetch(`${API_BASE}/api/incidents/audit/logs`, { headers }),
      ])
      const incidentsData = (await incidentsResponse.json()) as Incident[] | { detail?: string }
      const logsData = (await logsResponse.json()) as AuditLog[] | { detail?: string }
      if (!incidentsResponse.ok) throw new Error('detail' in incidentsData ? incidentsData.detail ?? 'Unable to load incidents' : 'Unable to load incidents')
      if (!logsResponse.ok) throw new Error('detail' in logsData ? logsData.detail ?? 'Unable to load audit logs' : 'Unable to load audit logs')
      setAdminIncidents(incidentsData as Incident[])
      setAuditLogs(logsData as AuditLog[])
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to load admin dashboard')
    } finally {
      setAdminLoading(false)
    }
  }

  const openAuth = (nextMode: AuthMode = 'register') => {
    setMode(nextMode)
    setMessage('')
    setError('')
    setView('auth')
  }

  const openReport = () => {
    if (!currentUser) {
      openAuth('login')
      setMessage('Please log in as a user to report an incident.')
      return
    }
    if (currentUser.role !== 'user') {
      setError('Admin accounts cannot report incidents.')
      setView('home')
      return
    }
    setView('report')
  }

  const handleAuthSubmit = async (event: FormEvent) => {
    event.preventDefault()
    setMessage('')
    setError('')
    try {
      const body = mode === 'register'
        ? { username: form.username, email: form.email, password: form.password }
        : { email: form.email, password: form.password }
      const response = await fetch(`${API_BASE}/api/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = (await response.json()) as Partial<AuthResponse> & { detail?: string }
      if (!response.ok) throw new Error(data.detail ?? `Authentication failed (${response.status})`)
      if (mode === 'register') {
        setMessage('Registration successful. You can log in now.')
        setMode('login')
        setForm({ ...initialForm, email: form.email })
        return
      }
      if (!data.access_token || !data.user) throw new Error('API returned an incomplete login response')
      setToken(data.access_token)
      localStorage.setItem('traceshield-token', data.access_token)
      setCurrentUser(data.user)
      setView(data.user.role === 'user' ? 'report' : 'profile')
      setMessage('Login successful.')
      if (data.user.role === 'admin') void loadAdminDashboard(data.access_token)
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Authentication failed')
    }

  }

  const updateIncidentStatus = async (incidentCode: string, newStatus: IncidentStatus) => {
    setError('')
    try {
      const response = await fetch(`${API_BASE}/api/incidents/${incidentCode}/status?new_status=${newStatus}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` },
      })
      const data = (await response.json()) as Incident | { detail?: string }
      if (!response.ok) throw new Error('detail' in data ? data.detail ?? 'Unable to update status' : 'Unable to update status')
      setAdminIncidents((existing) => existing.map((incident) => incident.incident_code === incidentCode ? data as Incident : incident))
      setMessage(`Incident ${incidentCode} updated to ${newStatus.replace('_', ' ')}.`)
      void loadAdminDashboard()
    } catch (updateError) {
      setError(updateError instanceof Error ? updateError.message : 'Unable to update incident status')
    }
  }

  const handleIncidentSubmit = async (event: FormEvent) => {
    event.preventDefault()
    setMessage('')
    setError('')
    const body = new FormData()
    body.append('title', incidentForm.title)
    body.append('description', incidentForm.description)
    body.append('category', incidentForm.category)
    evidenceFiles.forEach((file) => body.append('files', file))
    try {
      const response = await fetch(`${API_BASE}/api/incidents`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body,
      })
      const data = (await response.json()) as { detail?: string; incident_code?: string; evidence?: Evidence[] }
      if (!response.ok) throw new Error(data.detail ?? `Incident submission failed (${response.status})`)
      setMessage(`Incident ${data.incident_code ?? ''} submitted securely.`)
      if (data.incident_code) {
        setSubmittedIncident({ incident_code: data.incident_code, evidence: data.evidence ?? [] })
      }
      setIncidentForm({ title: '', description: '', category: 'phishing' })
      setEvidenceFiles([])
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Incident submission failed')
    }
  }

  const runProtectionAction = async (
    evidence: Evidence,
    action: 'visual-shares' | 'steganography' | 'text-steganography' | 'audio-steganography',
  ) => {
    setError('')
    setProtectionMessage('')
    const requiresSecret = action !== 'visual-shares'
    if (requiresSecret && !secret.trim()) {
      setError('Enter a hidden message before embedding it.')
      return
    }
    const body = new FormData()
    if (requiresSecret) body.append('secret', secret)
    try {
      const response = await fetch(
        `${API_BASE}/api/incidents/${submittedIncident?.incident_code}/evidence/${evidence.id}/${action}`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          body,
        },
      )
      const data = (await response.json()) as ProtectionArtifact[] | ProtectionArtifact | { detail?: string }
      if (!response.ok) {
        throw new Error('detail' in data ? data.detail ?? `Protection failed (${response.status})` : `Protection failed (${response.status})`)
      }
      if (!Array.isArray(data) && 'detail' in data) throw new Error(data.detail ?? `Protection failed (${response.status})`)
      const artifacts: ProtectionArtifact[] = Array.isArray(data) ? data : [data as ProtectionArtifact]
      if (action !== 'visual-shares') {
        setArtifacts((existing) => ({
          ...existing,
          [evidence.id]: [
            ...(existing[evidence.id] ?? []),
            ...artifacts.map((artifact) => ({ ...artifact, type: action })),
          ],
        }))
      }
      setProtectionMessage(
        `${action === 'visual-shares' ? 'Visual shares generated' : 'Protected artifact created'}: ${artifacts.map((artifact) => artifact.sha256_hash).join(', ')}`,
      )
      setSecret('')
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : 'Evidence protection failed')
    }
  }

  const extractMessage = async (artifactType: StoredArtifact['type'], artifactId: number) => {
    setError('')
    setProtectionMessage('')
    try {
      const response = await fetch(
        `${API_BASE}/api/incidents/${submittedIncident?.incident_code}/${artifactType}/${artifactId}/message`,
        { headers: { Authorization: `Bearer ${token}` } },
      )
      const data = (await response.json()) as { message?: string; detail?: string }
      if (!response.ok) throw new Error(data.detail ?? `Message extraction failed (${response.status})`)
      setProtectionMessage(`Hidden message: ${data.message ?? ''}`)
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : 'Message extraction failed')
    }
  }

  const handleLogout = () => {
    setToken('')
    setCurrentUser(null)
    setAdminIncidents([])
    setAuditLogs([])
    localStorage.removeItem('traceshield-token')
    setView('home')
    setMessage('Logged out successfully.')
  }

  return (
    <main className="site-shell">
      <header className="topbar">
        <button className="brand" type="button" onClick={() => setView('home')}>
          <span className="brand-mark">T</span><span>TraceShield</span>
        </button>
        <nav>
          {currentUser && <span className="signed-in">Signed in as {currentUser.username}</span>}
          {currentUser ? (
            <button className="outline-button" type="button" onClick={handleLogout}>Log out</button>
          ) : (
            <button className="outline-button" type="button" onClick={() => openAuth('login')}>Register / Login</button>
          )}
        </nav>
      </header>

      {view === 'home' && (
        <>
          <section className="hero">
            <p className="eyebrow">Privacy-preserving incident response</p>
            <h1>Protect the evidence.<br /><span>Preserve the truth.</span></h1>
            <p className="hero-copy">A secure workspace for reporting cyber incidents and protecting sensitive digital evidence from submission through investigation.</p>
            <div className="hero-actions">
              <button className="primary-button" type="button" onClick={openReport}>Report an incident</button>
              <button className="secondary-button" type="button" onClick={() => setMessage('TraceShield foundation services are ready.')}>View platform status</button>
            </div>
            {message && <p className="status success">{message}</p>}
            {error && <p className="status error">{error}</p>}
          </section>
          <section className="feature-grid" aria-label="TraceShield capabilities">
            <article className="feature-card"><span>01</span><h2>Private by design</h2><p>PII minimization and pseudonymous incident identifiers reduce unnecessary exposure.</p></article>
            <article className="feature-card highlighted"><span>02</span><h2>Evidence integrity</h2><p>Validated uploads and SHA-256 fingerprints help prove that evidence was not altered.</p></article>
            <article className="feature-card"><span>03</span><h2>Controlled access</h2><p>Authentication, role-based permissions, and audit trails keep investigations accountable.</p></article>
          </section>
        </>
      )}

      {view === 'auth' && (
        <section className="content-card">
          <button className="back-button" type="button" onClick={() => setView('home')}>← Back to dashboard</button>
          <div className="tab-row">
            <button className={mode === 'register' ? 'tab selected' : 'tab'} type="button" onClick={() => setMode('register')}>Register</button>
            <button className={mode === 'login' ? 'tab selected' : 'tab'} type="button" onClick={() => setMode('login')}>Login</button>
          </div>
          <h2>{authTitle}</h2>
          <form onSubmit={handleAuthSubmit} className="auth-form">
            {mode === 'register' && <label>Username<input required minLength={3} value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} placeholder="trace-user" /></label>}
            <label>Email<input required type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} placeholder="user@traceshield.local" /></label>
            <label>Password<input required minLength={8} type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} placeholder="At least 8 characters" /></label>
            <button className="primary-button" type="submit">{mode === 'register' ? 'Create account' : 'Sign in'}</button>
          </form>
          {message && <p className="status success">{message}</p>}
          {error && <p className="status error">{error}</p>}
        </section>
      )}

      {view === 'report' && currentUser?.role === 'user' && (
        <section className="content-card">
          <button className="back-button" type="button" onClick={() => setView('home')}>← Back to dashboard</button>
          <h2>Report an incident</h2>
          <p className="card-copy">Avoid unnecessary personal information. Evidence is validated and stored privately.</p>
          <form onSubmit={handleIncidentSubmit} className="auth-form">
            <label>Incident title<input required minLength={5} value={incidentForm.title} onChange={(event) => setIncidentForm({ ...incidentForm, title: event.target.value })} /></label>
            <label>Category<select value={incidentForm.category} onChange={(event) => setIncidentForm({ ...incidentForm, category: event.target.value })}><option value="phishing">Phishing</option><option value="malware">Malware</option><option value="account_compromise">Account compromise</option><option value="data_exposure">Data exposure</option><option value="other">Other</option></select></label>
            <label>Description<textarea required minLength={20} rows={6} value={incidentForm.description} onChange={(event) => setIncidentForm({ ...incidentForm, description: event.target.value })} /></label>
            <label>Evidence (optional, max 10 MB each)<input type="file" multiple accept=".png,.jpg,.jpeg,.pdf,.txt,.wav,.mp3,.mp4" onChange={(event) => setEvidenceFiles(Array.from(event.target.files ?? []))} /></label>
            <button className="primary-button" type="submit">Submit incident</button>
          </form>
          {submittedIncident && (
            <section className="protection-panel">
              <h3>Protect submitted evidence</h3>
              <p className="card-copy">Incident code: <strong>{submittedIncident.incident_code}</strong></p>
              <label>Hidden message<input value={secret} onChange={(event) => setSecret(event.target.value)} maxLength={5000} placeholder="Message for image, text, or WAV evidence" /></label>
              {submittedIncident.evidence.length === 0 && <p className="card-copy">No evidence was attached to this incident.</p>}
              {submittedIncident.evidence.map((evidence) => {
                const isImage = evidence.media_type === 'image/png' || evidence.media_type === 'image/jpeg'
                const isText = evidence.media_type === 'text/plain'
                const isAudio = evidence.media_type === 'audio/wav' || evidence.media_type === 'audio/x-wav'
                return (
                  <div className="evidence-tool" key={evidence.id}>
                    <strong>{evidence.original_filename}</strong>
                    <span className="evidence-hash">SHA-256: {evidence.sha256_hash}</span>
                    <div className="tool-actions">
                      {isImage && <><button className="secondary-button" type="button" onClick={() => void runProtectionAction(evidence, 'visual-shares')}>Generate visual shares</button><button className="secondary-button" type="button" onClick={() => void runProtectionAction(evidence, 'steganography')}>Hide in image</button></>}
                      {isText && <button className="secondary-button" type="button" onClick={() => void runProtectionAction(evidence, 'text-steganography')}>Hide in text</button>}
                      {isAudio && <button className="secondary-button" type="button" onClick={() => void runProtectionAction(evidence, 'audio-steganography')}>Hide in audio</button>}
                    </div>
                    {(artifacts[evidence.id] ?? []).map((artifact) => (
                      <div className="artifact-row" key={`${artifact.type}-${artifact.id}`}>
                        <span>{artifact.stored_filename ?? 'Protected artifact'} ({artifact.sha256_hash})</span>
                        <button className="secondary-button" type="button" onClick={() => void extractMessage(artifact.type, artifact.id)}>Extract message</button>
                      </div>
                    ))}
                  </div>
                )
              })}
              {protectionMessage && <p className="status success">{protectionMessage}</p>}
            </section>
          )}
          {message && <p className="status success">{message}</p>}
          {error && <p className="status error">{error}</p>}
        </section>
      )}

      {view === 'profile' && currentUser && (
        <section className="content-card">
          {currentUser.role === 'admin' ? (
            <section className="admin-dashboard">
              <div className="admin-heading">
                <div><h2>Admin dashboard</h2><p className="card-copy">Review incidents, update investigation status, and monitor security activity.</p></div>
                <button className="secondary-button" type="button" onClick={() => void loadAdminDashboard()}>Refresh</button>
              </div>
              {adminLoading && <p className="card-copy">Loading investigation data...</p>}
              <div className="admin-stats">
                <div><strong>{adminIncidents.length}</strong><span>Incidents</span></div>
                <div><strong>{adminIncidents.filter((incident) => incident.status === 'submitted').length}</strong><span>New</span></div>
                <div><strong>{auditLogs.length}</strong><span>Audit events</span></div>
              </div>
              <h3>Incident queue</h3>
              {adminIncidents.length === 0 && !adminLoading && <p className="card-copy">No incidents have been submitted.</p>}
              {adminIncidents.map((incident) => (
                <article className="incident-row" key={incident.incident_code}>
                  <div className="incident-row-heading"><strong>{incident.incident_code}</strong><span className={`status-badge ${incident.status}`}>{incident.status.replace('_', ' ')}</span></div>
                  <h4>{incident.title}</h4>
                  <p>{incident.description}</p>
                  <span className="evidence-hash">{incident.category} · Reporter #{incident.reporter_id} · {new Date(incident.created_at).toLocaleString()}</span>
                  <span className="evidence-hash">{incident.evidence.length} evidence file(s)</span>
                  <label>Update status<select value={incident.status} onChange={(event) => void updateIncidentStatus(incident.incident_code, event.target.value as IncidentStatus)}><option value="submitted">Submitted</option><option value="under_review">Under review</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></label>
                  <div className="evidence-investigation">
                    <strong>Evidence investigation</strong>
                    {incident.evidence.map((evidence) => <div className="investigation-file" key={evidence.id}>
                      <span>{evidence.original_filename} · {Math.ceil(evidence.size_bytes / 1024)} KB</span>
                      <div className="tool-actions">
                        {evidence.media_type.startsWith('image/') && <button className="secondary-button" type="button" onClick={() => void fetchProtectedFile(`/api/incidents/${incident.incident_code}/evidence/${evidence.id}/preview`, evidence.original_filename, true)}>Preview</button>}
                        <button className="secondary-button" type="button" onClick={() => void fetchProtectedFile(`/api/incidents/${incident.incident_code}/evidence/${evidence.id}/download`, evidence.original_filename)}>Download</button>
                      </div>
                      {(evidence.shares ?? []).length > 0 && <div className="artifact-list"><span>Visual shares</span>{evidence.shares?.map((share) => <button className="secondary-button" type="button" key={share.id} onClick={() => void fetchProtectedFile(`/api/incidents/${incident.incident_code}/evidence/${evidence.id}/shares/${share.id}/download`, share.stored_filename)}>Share {share.share_number}</button>)}{(evidence.shares ?? []).length >= 2 && <button className="secondary-button" type="button" onClick={() => void reconstructShares(incident, evidence)}>Reconstruct</button>}</div>}
                      {([
                        ['image', evidence.stego_artifacts ?? []],
                        ['text', evidence.text_stego_artifacts ?? []],
                        ['audio', evidence.audio_stego_artifacts ?? []],
                      ] as const).map(([type, protectedArtifacts]) => protectedArtifacts.map((artifact) => <div className="artifact-list" key={`${type}-${artifact.id}`}><span>{type} protected artifact</span><button className="secondary-button" type="button" onClick={() => void fetchProtectedFile(`/api/incidents/${incident.incident_code}/evidence/${evidence.id}/artifacts/${type}/${artifact.id}/download`, artifact.stored_filename)}>Download</button></div>))}
                    </div>)}
                  </div>
                </article>
              ))}
              <h3>Recent audit logs</h3>
              <div className="audit-list">
                {auditLogs.map((log) => <div className="audit-row" key={log.id}><strong>{log.action}</strong><span>{log.target_id}</span><time>{new Date(log.created_at).toLocaleString()}</time></div>)}
              </div>
            </section>
          ) : <><h2>Profile</h2><p className="card-copy">Signed in as <strong>{currentUser.username}</strong> ({currentUser.role}).</p></>}
        </section>
      )}
    </main>
  )
}

export default App
