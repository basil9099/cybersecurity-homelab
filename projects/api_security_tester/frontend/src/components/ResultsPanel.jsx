import { useState } from 'react'
import VulnerabilityCard from './VulnerabilityCard.jsx'

const MODULE_LABELS = {
  rate_limit:     { label: 'Rate Limiting',        icon: '⏱' },
  auth_bypass:    { label: 'Auth Bypass',           icon: '🔑' },
  sql_injection:  { label: 'SQL Injection',         icon: '💉' },
  authz_flaws:    { label: 'Authorization Flaws',   icon: '🔓' },
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'pass']

function severityScore(s) {
  const scores = { critical: 0, high: 1, medium: 2, low: 3, info: 4, pass: 5 }
  return scores[s] ?? 99
}

function SummaryBar({ results }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, pass: 0 }
  for (const r of Object.values(results)) {
    for (const f of r.findings ?? []) {
      if (counts[f.severity] !== undefined) counts[f.severity]++
      else counts.low++
    }
  }

  const items = [
    { key: 'critical', color: '#ff4444', label: 'Critical' },
    { key: 'high',     color: '#ff8c00', label: 'High'     },
    { key: 'medium',   color: '#f0c040', label: 'Medium'   },
    { key: 'low',      color: '#58a6ff', label: 'Low'      },
    { key: 'pass',     color: '#3fb950', label: 'Pass'     },
  ]

  return (
    <div style={styles.summaryBar}>
      {items.map(({ key, color, label }) => (
        <div key={key} style={styles.summaryItem}>
          <span style={{ ...styles.summaryDot, background: color }} />
          <span style={{ color, fontWeight: 700 }}>{counts[key]}</span>
          <span style={styles.summaryLabel}>{label}</span>
        </div>
      ))}
    </div>
  )
}

function RawRequests({ requests }) {
  const [open, setOpen] = useState(false)
  if (!requests?.length) return null
  return (
    <div style={styles.rawSection}>
      <button onClick={() => setOpen(o => !o)} style={styles.rawToggle}>
        {open ? '▲' : '▼'} Raw Requests ({requests.length})
      </button>
      {open && (
        <pre style={styles.rawPre}>
          {JSON.stringify(requests, null, 2)}
        </pre>
      )}
    </div>
  )
}

export default function ResultsPanel({ results, progress, scanning }) {
  const [activeTab, setActiveTab] = useState(null)

  const moduleKeys = Object.keys(results)
  const firstKey = moduleKeys[0]
  const currentTab = activeTab ?? firstKey

  // Running modules that haven't returned yet
  const runningModules = progress.filter(p => !results[p])

  if (!moduleKeys.length && !runningModules.length) return null

  const currentResult = results[currentTab]
  const sortedFindings = currentResult
    ? [...(currentResult.findings ?? [])].sort(
        (a, b) => severityScore(a.severity) - severityScore(b.severity)
      )
    : []

  return (
    <div style={styles.panel}>
      <div style={styles.panelHeader}>
        <h2 style={styles.panelTitle}>Scan Results</h2>
        {!scanning && moduleKeys.length > 0 && (
          <SummaryBar results={results} />
        )}
      </div>

      {/* Tabs */}
      <div style={styles.tabs}>
        {[...moduleKeys, ...runningModules].map(key => {
          const meta = MODULE_LABELS[key] ?? { label: key, icon: '🔍' }
          const isRunning = runningModules.includes(key)
          const isActive = currentTab === key
          const moduleFindings = results[key]?.findings ?? []
          const hasCritical = moduleFindings.some(f => f.severity === 'critical')
          const hasHigh = moduleFindings.some(f => f.severity === 'high')

          return (
            <button
              key={key}
              onClick={() => !isRunning && setActiveTab(key)}
              style={{
                ...styles.tab,
                ...(isActive ? styles.tabActive : {}),
                ...(isRunning ? styles.tabRunning : {}),
              }}
              disabled={isRunning}
            >
              {meta.icon}{' '}
              {meta.label}
              {isRunning && <span style={styles.tabSpinner} />}
              {hasCritical && <span style={styles.tabBadge('#ff4444')}>●</span>}
              {!hasCritical && hasHigh && <span style={styles.tabBadge('#ff8c00')}>●</span>}
            </button>
          )
        })}
      </div>

      {/* Content */}
      {currentResult ? (
        <div style={styles.content}>
          {currentResult.error && (
            <div style={styles.errorBanner}>
              Scanner error: {currentResult.error}
            </div>
          )}

          {sortedFindings.length === 0 && !currentResult.error && (
            <p style={styles.empty}>No findings returned by this scanner.</p>
          )}

          <div style={styles.findingsList}>
            {sortedFindings.map((f, i) => (
              <VulnerabilityCard key={i} finding={f} />
            ))}
          </div>

          <RawRequests requests={currentResult.raw_requests} />
        </div>
      ) : (
        runningModules.includes(currentTab ?? '') && (
          <div style={styles.content}>
            <div style={styles.running}>
              <div style={styles.loadingDots}>
                <span /><span /><span />
              </div>
              Running {MODULE_LABELS[currentTab]?.label ?? currentTab} scanner…
            </div>
          </div>
        )
      )}
    </div>
  )
}

// tiny helper — not a real styled-component call
const styles = {
  panel: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  panelHeader: {
    padding: '16px 20px',
    borderBottom: '1px solid #30363d',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '12px',
  },
  panelTitle: {
    fontSize: '1rem',
    fontWeight: 700,
    color: '#e6edf3',
  },
  summaryBar: {
    display: 'flex',
    gap: '16px',
    flexWrap: 'wrap',
  },
  summaryItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    fontSize: '0.82rem',
  },
  summaryDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  summaryLabel: {
    color: '#8b949e',
  },
  tabs: {
    display: 'flex',
    gap: 0,
    borderBottom: '1px solid #30363d',
    overflowX: 'auto',
  },
  tab: {
    background: 'transparent',
    border: 'none',
    borderBottom: '2px solid transparent',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '0.825rem',
    fontWeight: 500,
    padding: '10px 18px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    whiteSpace: 'nowrap',
    transition: 'color 0.15s',
  },
  tabActive: {
    color: '#58a6ff',
    borderBottomColor: '#58a6ff',
  },
  tabRunning: {
    cursor: 'default',
    opacity: 0.7,
  },
  tabSpinner: {
    display: 'inline-block',
    width: '10px',
    height: '10px',
    border: '1.5px solid #8b949e44',
    borderTop: '1.5px solid #8b949e',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite',
  },
  tabBadge: color => ({
    color,
    fontSize: '0.6rem',
    lineHeight: 1,
  }),
  content: {
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  findingsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  errorBanner: {
    background: '#3a0f0f',
    border: '1px solid #ff444455',
    borderRadius: '6px',
    color: '#ff8888',
    fontSize: '0.85rem',
    padding: '10px 14px',
  },
  empty: {
    color: '#8b949e',
    fontSize: '0.875rem',
  },
  running: {
    color: '#8b949e',
    fontSize: '0.875rem',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '20px 0',
  },
  loadingDots: {
    display: 'flex',
    gap: '4px',
  },
  rawSection: {
    marginTop: '8px',
    borderTop: '1px solid #30363d',
    paddingTop: '12px',
  },
  rawToggle: {
    background: 'transparent',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '0.78rem',
    padding: '5px 12px',
  },
  rawPre: {
    marginTop: '10px',
    fontSize: '0.73rem',
    maxHeight: '400px',
    overflowY: 'auto',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    padding: '12px',
    color: '#8b949e',
  },
}
