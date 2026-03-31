import { useState, useEffect } from 'react'
import useFullscreen from '../../hooks/useFullscreen'

const styles = {
  bar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 16px',
    background: 'var(--surface)',
    borderBottom: '1px solid var(--border)',
    fontSize: '13px',
  },
  left: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  title: {
    fontWeight: 700,
    fontSize: '15px',
    color: 'var(--accent)',
    letterSpacing: '0.5px',
  },
  dot: (connected) => ({
    width: 8,
    height: 8,
    borderRadius: '50%',
    background: connected ? 'var(--pass)' : 'var(--critical)',
    animation: connected ? 'pulse 2s infinite' : 'none',
  }),
  status: {
    color: 'var(--text-muted)',
    fontSize: '12px',
  },
  right: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  btn: {
    background: 'var(--surface2)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    padding: '2px 10px',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '12px',
  },
  clock: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    fontSize: '12px',
  },
}

export default function StatusBar({ connected }) {
  const [time, setTime] = useState(new Date())
  const { isFullscreen, toggle } = useFullscreen()

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div style={styles.bar}>
      <div style={styles.left}>
        <span style={styles.title}>MONITOR THE SITUATION</span>
        <div style={styles.dot(connected)} />
        <span style={styles.status}>
          {connected ? 'LIVE' : 'DISCONNECTED'}
        </span>
      </div>
      <div style={styles.right}>
        <button style={styles.btn} onClick={toggle}>
          {isFullscreen ? 'EXIT FS' : 'FULLSCREEN'}
        </button>
        <span style={styles.clock}>
          {time.toLocaleTimeString()} UTC
        </span>
      </div>
    </div>
  )
}
