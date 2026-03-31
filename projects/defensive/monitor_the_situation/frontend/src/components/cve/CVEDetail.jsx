import SeverityBadge from '../shared/SeverityBadge'

const styles = {
  overlay: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
  },
  modal: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    padding: '20px',
    maxWidth: '600px',
    width: '90%',
    maxHeight: '80vh',
    overflow: 'auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '12px',
  },
  cveId: {
    fontFamily: 'var(--font-mono)',
    fontSize: '16px',
    fontWeight: 700,
    color: 'var(--accent)',
  },
  close: {
    background: 'none',
    border: 'none',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    fontSize: '18px',
  },
  section: {
    marginBottom: '12px',
  },
  label: {
    fontSize: '10px',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    marginBottom: '4px',
  },
  desc: {
    fontSize: '13px',
    lineHeight: 1.6,
  },
}

export default function CVEDetail({ cve, onClose }) {
  if (!cve) return null

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div style={styles.header}>
          <span style={styles.cveId}>{cve.cve_id}</span>
          <button style={styles.close} onClick={onClose}>x</button>
        </div>
        <div style={styles.section}>
          <SeverityBadge severity={cve.cvss_severity} />
          <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)' }}>
            CVSS {cve.cvss_score}
          </span>
        </div>
        <div style={styles.section}>
          <div style={styles.label}>Description</div>
          <div style={styles.desc}>{cve.description}</div>
        </div>
        {cve.epss_score != null && (
          <div style={styles.section}>
            <div style={styles.label}>EPSS</div>
            <div>{(cve.epss_score * 100).toFixed(2)}% probability of exploitation</div>
          </div>
        )}
      </div>
    </div>
  )
}
