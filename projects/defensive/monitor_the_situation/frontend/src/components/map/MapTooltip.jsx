const styles = {
  tooltip: {
    position: 'absolute',
    top: 10,
    right: 10,
    background: 'var(--surface2)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    padding: '10px 14px',
    fontSize: '12px',
    zIndex: 10,
    minWidth: '160px',
  },
  label: {
    color: 'var(--text-muted)',
    fontSize: '10px',
    textTransform: 'uppercase',
    marginBottom: '2px',
  },
  value: {
    fontFamily: 'var(--font-mono)',
    marginBottom: '6px',
  },
}

export default function MapTooltip({ event }) {
  if (!event) return null

  return (
    <div style={styles.tooltip}>
      <div style={styles.label}>IP</div>
      <div style={styles.value}>{event.ip}</div>
      <div style={styles.label}>Location</div>
      <div style={styles.value}>{event.city}, {event.country}</div>
      <div style={styles.label}>Category</div>
      <div style={styles.value}>{event.category}</div>
      <div style={styles.label}>Source</div>
      <div style={styles.value}>{event.source}</div>
      {event.count > 1 && (
        <>
          <div style={styles.label}>Events</div>
          <div style={styles.value}>{event.count}</div>
        </>
      )}
    </div>
  )
}
