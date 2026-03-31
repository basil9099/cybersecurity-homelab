const styles = {
  frame: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: '4px',
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 10px',
    borderBottom: '1px solid var(--border)',
    background: 'var(--surface2)',
    flexShrink: 0,
  },
  title: {
    fontSize: '11px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '1px',
    color: 'var(--text-muted)',
  },
  content: {
    flex: 1,
    overflow: 'auto',
    padding: '8px',
  },
}

export default function PanelFrame({ title, children }) {
  return (
    <div style={styles.frame}>
      <div style={styles.header}>
        <span style={styles.title}>{title}</span>
      </div>
      <div style={styles.content}>
        {children}
      </div>
    </div>
  )
}
