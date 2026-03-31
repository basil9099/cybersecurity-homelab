import { useMemo } from 'react'
import useApi from '../../hooks/useApi'
import MiniChart from '../shared/MiniChart'

const styles = {
  container: { height: '100%', display: 'flex', flexDirection: 'column' },
  statsRow: {
    display: 'flex',
    gap: '12px',
    marginBottom: '8px',
    flexShrink: 0,
  },
  stat: {
    flex: 1,
    background: 'var(--surface2)',
    borderRadius: '4px',
    padding: '6px 10px',
    textAlign: 'center',
  },
  statValue: {
    fontSize: '18px',
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
  },
  statLabel: {
    fontSize: '9px',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
  },
  chartArea: { flex: 1, minHeight: 0 },
}

export default function CVEVelocityChart() {
  const { data: stats } = useApi('/api/cves/stats', 30000)
  const { data: velocity } = useApi('/api/cves/velocity?days=14', 30000)

  const points = useMemo(() => {
    if (!velocity) return []
    return velocity.map((v) => v.count)
  }, [velocity])

  return (
    <div style={styles.container}>
      <div style={styles.statsRow}>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: 'var(--text)' }}>{stats?.total_cves ?? '—'}</div>
          <div style={styles.statLabel}>Total CVEs</div>
        </div>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: 'var(--critical)' }}>{stats?.critical_count ?? '—'}</div>
          <div style={styles.statLabel}>Critical</div>
        </div>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: 'var(--high)' }}>{stats?.high_count ?? '—'}</div>
          <div style={styles.statLabel}>High</div>
        </div>
        <div style={styles.stat}>
          <div style={{ ...styles.statValue, color: 'var(--pass)' }}>{stats?.with_exploit ?? '—'}</div>
          <div style={styles.statLabel}>w/ Exploit</div>
        </div>
      </div>
      <div style={styles.chartArea}>
        <MiniChart data={points} color="var(--accent)" height={80} label="CVEs/day (14d)" />
      </div>
    </div>
  )
}
