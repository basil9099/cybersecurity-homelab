import { useState, useRef } from 'react'
import ScanForm from './components/ScanForm.jsx'
import ResultsPanel from './components/ResultsPanel.jsx'

const API_BASE = import.meta.env.VITE_API_URL ?? ''

export default function App() {
  const [scanning, setScanning]   = useState(false)
  const [results, setResults]     = useState({})
  const [progress, setProgress]   = useState([])   // modules currently running
  const [error, setError]         = useState('')
  const [target, setTarget]       = useState('')
  const esRef = useRef(null)

  async function handleScanStart({ target: url, headers, modules }) {
    setError('')
    setResults({})
    setProgress([])
    setTarget(url)
    setScanning(true)

    // Close any previous SSE connection
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }

    let jobId
    try {
      const resp = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: url, headers, modules }),
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.detail ?? `HTTP ${resp.status}`)
      }
      const data = await resp.json()
      jobId = data.job_id
    } catch (err) {
      setError(`Failed to start scan: ${err.message}`)
      setScanning(false)
      return
    }

    // Stream results via SSE
    const es = new EventSource(`${API_BASE}/scan/${jobId}/stream`)
    esRef.current = es

    es.onmessage = (e) => {
      const event = JSON.parse(e.data)

      if (event.event === 'module_start') {
        setProgress(prev => [...prev, event.module])
      }

      if (event.event === 'module_done') {
        setProgress(prev => prev.filter(m => m !== event.module))
        setResults(prev => ({ ...prev, [event.module]: event.result }))
      }

      if (event.event === 'done') {
        setScanning(false)
        es.close()
        esRef.current = null
      }

      if (event.event === 'keepalive') {
        // no-op
      }
    }

    es.onerror = () => {
      setError('Lost connection to the scan stream. The scan may still be running — refresh to check.')
      setScanning(false)
      es.close()
    }
  }

  const hasResults = Object.keys(results).length > 0 || progress.length > 0

  return (
    <div style={styles.app}>
      {/* ── Header ─────────────────────────────────────────── */}
      <header style={styles.header}>
        <div style={styles.headerInner}>
          <div style={styles.logoRow}>
            <span style={styles.logoIcon}>🛡</span>
            <div>
              <h1 style={styles.logoTitle}>API Security Tester</h1>
              <p style={styles.logoSub}>
                Point it at any endpoint — learn how attackers probe APIs and how to defend them.
              </p>
            </div>
          </div>
          <div style={styles.chips}>
            <Chip color="#ff4444">Rate Limiting</Chip>
            <Chip color="#ff8c00">Auth Bypass</Chip>
            <Chip color="#f0c040">SQL Injection</Chip>
            <Chip color="#58a6ff">AuthZ Flaws</Chip>
          </div>
        </div>
      </header>

      {/* ── Main ────────────────────────────────────────────── */}
      <main style={styles.main}>
        {/* Legal warning */}
        <div style={styles.warning}>
          <strong>⚠ Authorisation Required</strong> — Only scan APIs you own or have
          explicit written permission to test. Unauthorised scanning may violate computer
          misuse laws (CFAA, CMA, and equivalents).
        </div>

        {/* Scan form */}
        <section style={styles.card}>
          <h2 style={styles.sectionTitle}>Configure Scan</h2>
          <ScanForm onScanStart={handleScanStart} scanning={scanning} />
        </section>

        {/* Error banner */}
        {error && (
          <div style={styles.errorBanner}>
            {error}
          </div>
        )}

        {/* Progress indicator */}
        {scanning && !hasResults && (
          <div style={styles.card}>
            <div style={styles.scanningMsg}>
              <div style={styles.scanPulse} />
              Connecting to <code style={styles.code}>{target}</code>…
            </div>
          </div>
        )}

        {/* Results */}
        {hasResults && (
          <ResultsPanel
            results={results}
            progress={progress}
            scanning={scanning}
          />
        )}

        {/* How it works */}
        {!hasResults && !scanning && (
          <section style={styles.card}>
            <h2 style={styles.sectionTitle}>How It Works</h2>
            <div style={styles.grid}>
              <HowItWorksCard
                icon="⏱"
                title="Rate Limit Testing"
                color="#ff4444"
                points={[
                  'Sends 25 rapid requests in parallel',
                  'Detects missing HTTP 429 responses',
                  'Checks for X-RateLimit-* headers',
                  'Missing limits = brute-force, scraping risk',
                ]}
              />
              <HowItWorksCard
                icon="🔑"
                title="Auth Bypass Testing"
                color="#ff8c00"
                points={[
                  'Tries empty / null / undefined bearer tokens',
                  'Tests alg:none JWT (CVE-2015-9235)',
                  'Spoofs IP with X-Forwarded-For: 127.0.0.1',
                  'Tries X-Original-URL path overrides',
                ]}
              />
              <HowItWorksCard
                icon="💉"
                title="SQL Injection Testing"
                color="#f0c040"
                points={[
                  'Injects payloads into all URL parameters',
                  'Error-based: detects DB error strings',
                  'Time-based blind: measures SLEEP() delays',
                  'Boolean blind: compares response sizes',
                ]}
              />
              <HowItWorksCard
                icon="🔓"
                title="Authorization Flaw Testing"
                color="#58a6ff"
                points={[
                  'IDOR: probes adjacent numeric IDs',
                  'Verb tampering: tries DELETE/PUT/PATCH',
                  'Admin path discovery (20+ common paths)',
                  'Role-escalation headers (X-Role: admin)',
                ]}
              />
            </div>
          </section>
        )}
      </main>

      {/* ── Footer ─────────────────────────────────────────── */}
      <footer style={styles.footer}>
        Part of the{' '}
        <a href="https://github.com/basil9099/cybersecurity-homelab" target="_blank" rel="noreferrer">
          cybersecurity-homelab
        </a>{' '}
        project — built for learning, not attacking.
      </footer>

      {/* Global keyframe for spinner animation */}
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
      `}</style>
    </div>
  )
}

function Chip({ children, color }) {
  return (
    <span style={{ ...styles.chip, color, borderColor: color + '55', background: color + '18' }}>
      {children}
    </span>
  )
}

function HowItWorksCard({ icon, title, color, points }) {
  return (
    <div style={{ ...styles.howCard, borderColor: color + '44' }}>
      <div style={styles.howHeader}>
        <span style={styles.howIcon}>{icon}</span>
        <span style={{ ...styles.howTitle, color }}>{title}</span>
      </div>
      <ul style={styles.howList}>
        {points.map((p, i) => (
          <li key={i} style={styles.howItem}>
            <span style={{ color, flexShrink: 0 }}>›</span> {p}
          </li>
        ))}
      </ul>
    </div>
  )
}

const styles = {
  app: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    background: '#161b22',
    borderBottom: '1px solid #30363d',
    padding: '20px 0',
  },
  headerInner: {
    maxWidth: '960px',
    margin: '0 auto',
    padding: '0 20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '16px',
  },
  logoRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '14px',
  },
  logoIcon: {
    fontSize: '2rem',
  },
  logoTitle: {
    fontSize: '1.25rem',
    fontWeight: 700,
    color: '#e6edf3',
  },
  logoSub: {
    fontSize: '0.8rem',
    color: '#8b949e',
    marginTop: '2px',
  },
  chips: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
  },
  chip: {
    fontSize: '0.72rem',
    fontWeight: 600,
    border: '1px solid',
    borderRadius: '20px',
    padding: '3px 10px',
    letterSpacing: '0.02em',
  },
  main: {
    maxWidth: '960px',
    margin: '0 auto',
    padding: '28px 20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
    flex: 1,
    width: '100%',
  },
  warning: {
    background: '#2d2200',
    border: '1px solid #f0c04055',
    borderRadius: '8px',
    color: '#f0c040',
    fontSize: '0.83rem',
    padding: '12px 16px',
    lineHeight: 1.5,
  },
  card: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '10px',
    padding: '24px',
  },
  sectionTitle: {
    color: '#e6edf3',
    fontSize: '1rem',
    fontWeight: 700,
    marginBottom: '18px',
  },
  errorBanner: {
    background: '#3a0f0f',
    border: '1px solid #ff444455',
    borderRadius: '8px',
    color: '#ff8888',
    fontSize: '0.875rem',
    padding: '12px 16px',
  },
  scanningMsg: {
    color: '#8b949e',
    fontSize: '0.875rem',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  scanPulse: {
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    background: '#58a6ff',
    animation: 'pulse 1.4s ease-in-out infinite',
    flexShrink: 0,
  },
  code: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '0.82rem',
    color: '#79c0ff',
    background: '#0d1117',
    padding: '2px 6px',
    borderRadius: '4px',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))',
    gap: '14px',
  },
  howCard: {
    border: '1px solid',
    borderRadius: '8px',
    padding: '16px',
    background: '#0d1117',
  },
  howHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '12px',
  },
  howIcon: {
    fontSize: '1.1rem',
  },
  howTitle: {
    fontWeight: 700,
    fontSize: '0.875rem',
  },
  howList: {
    listStyle: 'none',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  howItem: {
    fontSize: '0.78rem',
    color: '#8b949e',
    lineHeight: 1.5,
    display: 'flex',
    gap: '5px',
  },
  footer: {
    background: '#161b22',
    borderTop: '1px solid #30363d',
    color: '#8b949e',
    fontSize: '0.78rem',
    padding: '16px 20px',
    textAlign: 'center',
  },
}
