const CATEGORIES = [
  { label: 'Scanner', color: '#58a6ff' },
  { label: 'Brute Force', color: '#ff8c00' },
  { label: 'Malware', color: '#ff4444' },
  { label: 'Exploitation', color: '#d63384' },
  { label: 'Botnet', color: '#8b5cf6' },
  { label: 'Spam', color: '#8b949e' },
]

const styles = {
  legend: {
    position: 'absolute',
    bottom: 8,
    left: 8,
    display: 'flex',
    gap: '10px',
    fontSize: '10px',
    color: 'var(--text-muted)',
    background: 'rgba(13,17,23,0.85)',
    padding: '4px 8px',
    borderRadius: '4px',
  },
  item: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  dot: (color) => ({
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: color,
  }),
  stats: {
    position: 'absolute',
    bottom: 8,
    right: 8,
    fontSize: '10px',
    color: 'var(--text-muted)',
    background: 'rgba(13,17,23,0.85)',
    padding: '4px 8px',
    borderRadius: '4px',
    fontFamily: 'var(--font-mono)',
  },
}

export default function MapLegend({ stats }) {
  return (
    <>
      <div style={styles.legend}>
        {CATEGORIES.map((c) => (
          <div key={c.label} style={styles.item}>
            <div style={styles.dot(c.color)} />
            <span>{c.label}</span>
          </div>
        ))}
      </div>
      {stats && (
        <div style={styles.stats}>
          {stats.total_events?.toLocaleString()} events | {stats.unique_ips?.toLocaleString()} IPs | 24h: {stats.events_last_24h?.toLocaleString()}
        </div>
      )}
    </>
  )
}
