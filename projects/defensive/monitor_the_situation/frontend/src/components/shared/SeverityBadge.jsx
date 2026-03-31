const COLORS = {
  CRITICAL: { bg: 'rgba(255,68,68,0.15)', text: 'var(--critical)' },
  HIGH: { bg: 'rgba(255,140,0,0.15)', text: 'var(--high)' },
  MEDIUM: { bg: 'rgba(240,192,64,0.15)', text: 'var(--medium)' },
  LOW: { bg: 'rgba(88,166,255,0.15)', text: 'var(--low)' },
  INFO: { bg: 'rgba(139,148,158,0.15)', text: 'var(--info)' },
}

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'INFO').toUpperCase()
  const colors = COLORS[sev] || COLORS.INFO

  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 8px',
      borderRadius: '3px',
      fontSize: '10px',
      fontWeight: 700,
      textTransform: 'uppercase',
      background: colors.bg,
      color: colors.text,
    }}>
      {sev}
    </span>
  )
}
