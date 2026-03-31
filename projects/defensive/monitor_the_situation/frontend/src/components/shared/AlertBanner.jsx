import { useState } from 'react'
import useApi from '../../hooks/useApi'

const styles = {
  banner: {
    background: 'rgba(255,68,68,0.1)',
    borderBottom: '1px solid var(--critical)',
    padding: '6px 16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '12px',
  },
  alerts: {
    display: 'flex',
    gap: '16px',
    overflow: 'hidden',
  },
  alert: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    whiteSpace: 'nowrap',
  },
  icon: {
    color: 'var(--critical)',
    fontWeight: 700,
  },
  title: {
    color: 'var(--text)',
    fontWeight: 500,
  },
  dismiss: {
    background: 'none',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    padding: '2px 8px',
    borderRadius: '3px',
    cursor: 'pointer',
    fontSize: '10px',
    flexShrink: 0,
  },
  hidden: {
    display: 'none',
  },
}

export default function AlertBanner() {
  const { data } = useApi('/api/alerts?severity=critical&acknowledged=false&limit=3', 15000)
  const [dismissed, setDismissed] = useState(false)

  if (dismissed || !data?.length) return null

  return (
    <div style={styles.banner}>
      <div style={styles.alerts}>
        {data.map((alert) => (
          <span key={alert.id} style={styles.alert}>
            <span style={styles.icon}>!</span>
            <span style={styles.title}>{alert.title}</span>
          </span>
        ))}
      </div>
      <button style={styles.dismiss} onClick={() => setDismissed(true)}>
        DISMISS
      </button>
    </div>
  )
}
