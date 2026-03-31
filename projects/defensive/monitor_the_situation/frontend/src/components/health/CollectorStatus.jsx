import useApi from '../../hooks/useApi'

const STATUS_COLORS = {
  ok: 'var(--pass)',
  error: 'var(--critical)',
  degraded: 'var(--medium)',
  unknown: 'var(--text-muted)',
}

const styles = {
  container: {
    display: 'flex',
    gap: '8px',
    padding: '4px 8px',
    alignItems: 'center',
    flexWrap: 'wrap',
  },
  label: {
    fontSize: '10px',
    fontWeight: 700,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginRight: '4px',
  },
  collector: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    fontSize: '10px',
  },
  dot: (status) => ({
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: STATUS_COLORS[status] || 'var(--text-muted)',
  }),
  name: {
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  },
}

export default function CollectorStatus() {
  const { data } = useApi('/api/health/collectors', 15000)

  if (!data) return null

  return (
    <div style={styles.container}>
      <span style={styles.label}>Collectors</span>
      {data.map((c) => (
        <div key={c.collector_name} style={styles.collector}>
          <div style={styles.dot(c.status)} />
          <span style={styles.name}>{c.collector_name}</span>
        </div>
      ))}
    </div>
  )
}
