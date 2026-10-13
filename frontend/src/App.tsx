import { useEffect, useMemo, useState, type FormEvent } from 'react'
import './App.css'

type UserRole = 'user' | 'admin'
type AuthMode = 'register' | 'login'
type View = 'home' | 'auth' | 'report' | 'profile'

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
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Authentication failed')
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
      const data = (await response.json()) as { detail?: string; incident_code?: string }
      if (!response.ok) throw new Error(data.detail ?? `Incident submission failed (${response.status})`)
      setMessage(`Incident ${data.incident_code ?? ''} submitted securely.`)
      setIncidentForm({ title: '', description: '', category: 'phishing' })
      setEvidenceFiles([])
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Incident submission failed')
    }
  }

  const handleLogout = () => {
    setToken('')
    setCurrentUser(null)
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
          {message && <p className="status success">{message}</p>}
          {error && <p className="status error">{error}</p>}
        </section>
      )}

      {view === 'profile' && currentUser && (
        <section className="content-card">
          <h2>{currentUser.role === 'admin' ? 'Admin dashboard' : 'Profile'}</h2>
          <p className="card-copy">Signed in as <strong>{currentUser.username}</strong> ({currentUser.role}).</p>
          {currentUser.role === 'admin' && <p className="status success">Admin accounts can investigate incidents but cannot report them.</p>}
        </section>
      )}
    </main>
  )
}

export default App
