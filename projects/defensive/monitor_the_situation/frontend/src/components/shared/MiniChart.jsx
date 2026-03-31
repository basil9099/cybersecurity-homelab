const styles = {
  container: {
    width: '100%',
    height: '100%',
    position: 'relative',
  },
  label: {
    position: 'absolute',
    bottom: 2,
    right: 4,
    fontSize: '9px',
    color: 'var(--text-muted)',
  },
}

export default function MiniChart({ data = [], color = 'var(--accent)', height = 60, label = '' }) {
  if (!data.length) return null

  const max = Math.max(...data, 1)
  const w = 100
  const h = height
  const step = w / Math.max(data.length - 1, 1)

  const points = data.map((v, i) => {
    const x = i * step
    const y = h - (v / max) * (h - 4) - 2
    return `${x},${y}`
  }).join(' ')

  const areaPoints = `0,${h} ${points} ${w},${h}`

  return (
    <div style={styles.container}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        style={{ width: '100%', height: '100%' }}
      >
        <polygon
          points={areaPoints}
          fill={color}
          fillOpacity="0.15"
        />
        <polyline
          points={points}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      {label && <span style={styles.label}>{label}</span>}
    </div>
  )
}
