import { useState } from 'react'

const MODULE_OPTIONS = [
  {
    id: 'rate_limit',
    label: 'Rate Limiting',
    icon: '⏱',
    description: 'Burst requests to detect missing throttling',
  },
  {
    id: 'auth_bypass',
    label: 'Auth Bypass',
    icon: '🔑',
    description: 'Empty tokens, alg:none JWT, IP-spoof headers',
  },
  {
    id: 'sql_injection',
    label: 'SQL Injection',
    icon: '💉',
    description: 'Error-based, boolean-blind, time-based, UNION',
  },
  {
    id: 'authz_flaws',
    label: 'Authorization Flaws',
    icon: '🔓',
    description: 'IDOR, verb tampering, admin paths, role headers',
  },
]

export default function ScanForm({ onScanStart, scanning }) {
  const [target, setTarget] = useState('')
  const [headersRaw, setHeadersRaw] = useState('')
  const [modules, setModules] = useState(MODULE_OPTIONS.map(m => m.id))
  const [headerError, setHeaderError] = useState('')

  function toggleModule(id) {
    setModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    )
  }

  function parseHeaders(raw) {
    if (!raw.trim()) return {}
    const result = {}
    for (const line of raw.split('\n')) {
      const colon = line.indexOf(':')
      if (colon === -1) continue
      const key = line.slice(0, colon).trim()
      const val = line.slice(colon + 1).trim()
      if (key) result[key] = val
    }
    return result
  }

  function handleSubmit(e) {
    e.preventDefault()
    setHeaderError('')

    let headers = {}
    try {
      headers = parseHeaders(headersRaw)
    } catch {
      setHeaderError('Could not parse headers — use "Key: Value" format, one per line.')
      return
    }

    if (modules.length === 0) {
      alert('Select at least one scanner module.')
      return
    }

    onScanStart({ target, headers, modules })
  }

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      {/* Target URL */}
      <div style={styles.field}>
        <label style={styles.label} htmlFor="target">
          Target URL
        </label>
        <input
          id="target"
          type="url"
          required
          placeholder="https://api.example.com/v1/users"
          value={target}
          onChange={e => setTarget(e.target.value)}
          style={styles.input}
          disabled={scanning}
        />
        <p style={styles.hint}>
          Only scan APIs you own or have explicit written authorisation to test.
        </p>
      </div>

      {/* Headers */}
      <div style={styles.field}>
        <label style={styles.label} htmlFor="headers">
          HTTP Headers <span style={styles.optional}>(optional)</span>
        </label>
        <textarea
          id="headers"
          rows={4}
          placeholder={'Authorization: Bearer eyJ...\nCookie: session=abc123'}
          value={headersRaw}
          onChange={e => setHeadersRaw(e.target.value)}
          style={{ ...styles.input, ...styles.textarea }}
          disabled={scanning}
        />
        {headerError && <p style={styles.error}>{headerError}</p>}
        <p style={styles.hint}>One header per line in "Key: Value" format.</p>
      </div>

      {/* Module selection */}
      <div style={styles.field}>
        <label style={styles.label}>Scanner Modules</label>
        <div style={styles.modules}>
          {MODULE_OPTIONS.map(m => (
            <label
              key={m.id}
              style={{
                ...styles.moduleCard,
                ...(modules.includes(m.id) ? styles.moduleCardActive : {}),
                ...(scanning ? styles.moduleCardDisabled : {}),
              }}
            >
              <input
                type="checkbox"
                checked={modules.includes(m.id)}
                onChange={() => toggleModule(m.id)}
                disabled={scanning}
                style={styles.checkbox}
              />
              <span style={styles.moduleIcon}>{m.icon}</span>
              <div>
                <div style={styles.moduleName}>{m.label}</div>
                <div style={styles.moduleDesc}>{m.description}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <button type="submit" disabled={scanning || !target} style={styles.button}>
        {scanning ? (
          <>
            <span style={styles.spinner} /> Scanning…
          </>
        ) : (
          '▶  Start Scan'
        )}
      </button>
    </form>
  )
}

const styles = {
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '24px',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  label: {
    fontSize: '0.875rem',
    fontWeight: 600,
    color: '#e6edf3',
    letterSpacing: '0.01em',
  },
  optional: {
    fontWeight: 400,
    color: '#8b949e',
    fontSize: '0.8rem',
  },
  input: {
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#e6edf3',
    fontFamily: 'inherit',
    fontSize: '0.9rem',
    padding: '10px 14px',
    outline: 'none',
    transition: 'border-color 0.15s',
  },
  textarea: {
    resize: 'vertical',
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontSize: '0.82rem',
  },
  hint: {
    fontSize: '0.78rem',
    color: '#8b949e',
  },
  error: {
    fontSize: '0.78rem',
    color: '#ff4444',
  },
  modules: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
    gap: '10px',
  },
  moduleCard: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '10px',
    padding: '12px',
    border: '1px solid #30363d',
    borderRadius: '8px',
    cursor: 'pointer',
    transition: 'border-color 0.15s, background 0.15s',
    userSelect: 'none',
  },
  moduleCardActive: {
    borderColor: '#58a6ff',
    background: '#1f3a5f22',
  },
  moduleCardDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  },
  checkbox: {
    marginTop: '3px',
    accentColor: '#58a6ff',
    flexShrink: 0,
  },
  moduleIcon: {
    fontSize: '1.2rem',
    flexShrink: 0,
    marginTop: '1px',
  },
  moduleName: {
    fontWeight: 600,
    fontSize: '0.875rem',
    color: '#e6edf3',
  },
  moduleDesc: {
    fontSize: '0.75rem',
    color: '#8b949e',
    marginTop: '2px',
  },
  button: {
    background: '#238636',
    border: '1px solid #2ea043',
    borderRadius: '6px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '0.925rem',
    fontWeight: 600,
    padding: '12px 24px',
    alignSelf: 'flex-start',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    transition: 'background 0.15s',
  },
  spinner: {
    display: 'inline-block',
    width: '14px',
    height: '14px',
    border: '2px solid #ffffff44',
    borderTop: '2px solid #fff',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite',
  },
}
