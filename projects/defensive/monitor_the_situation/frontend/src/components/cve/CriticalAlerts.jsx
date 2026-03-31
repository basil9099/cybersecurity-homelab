import useApi from '../../hooks/useApi'
import SeverityBadge from '../shared/SeverityBadge'
import TimeAgo from '../shared/TimeAgo'

const styles = {
  list: { display: 'flex', flexDirection: 'column', gap: '4px' },
  item: {
    background: 'var(--surface2)',
    border: '1px solid var(--border)',
    borderRadius: '4px',
    padding: '8px 10px',
    borderLeft: '3px solid var(--critical)',
  },
  cveId: {
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
    fontWeight: 600,
    color: 'var(--critical)',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '6px',
  },
  desc: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    marginTop: '4px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  score: {
    fontFamily: 'var(--font-mono)',
    fontSize: '13px',
    fontWeight: 700,
  },
  epss: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  },
  empty: {
    color: 'var(--text-muted)',
    fontSize: '12px',
    textAlign: 'center',
    padding: '20px',
  },
}

export default function CriticalAlerts() {
  const { data, loading } = useApi('/api/cves/critical?limit=8', 30000)

  if (loading) return <div style={styles.empty}>Loading...</div>
  if (!data?.length) return <div style={styles.empty}>No critical CVEs</div>

  return (
    <div style={styles.list}>
      {data.map((cve) => (
        <div key={cve.cve_id} style={styles.item}>
          <div style={styles.row}>
            <span style={styles.cveId}>{cve.cve_id}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ ...styles.score, color: 'var(--critical)' }}>
                {cve.cvss_score}
              </span>
              {cve.epss_score != null && (
                <span style={styles.epss}>
                  EPSS: {(cve.epss_score * 100).toFixed(1)}%
                </span>
              )}
            </div>
          </div>
          <div style={styles.desc}>{cve.description}</div>
        </div>
      ))}
    </div>
  )
}
