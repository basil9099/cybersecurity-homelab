import { useMemo } from 'react'
import useApi from '../../hooks/useApi'

const SENTIMENT_COLORS = {
  alert: 'var(--critical)',
  analysis: 'var(--accent)',
  neutral: 'var(--text-muted)',
}

const styles = {
  ticker: {
    background: 'var(--surface)',
    borderTop: '1px solid var(--border)',
    borderBottom: '1px solid var(--border)',
    overflow: 'hidden',
    height: '100%',
    display: 'flex',
    alignItems: 'center',
  },
  track: {
    display: 'flex',
    gap: '40px',
    whiteSpace: 'nowrap',
    animation: 'ticker 60s linear infinite',
  },
  item: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '12px',
    flexShrink: 0,
  },
  dot: (sentiment) => ({
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: SENTIMENT_COLORS[sentiment] || 'var(--text-muted)',
    flexShrink: 0,
  }),
  source: {
    color: 'var(--text-muted)',
    fontSize: '10px',
  },
  title: {
    maxWidth: '400px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  label: {
    fontSize: '10px',
    fontWeight: 700,
    color: 'var(--accent)',
    marginRight: '8px',
    textTransform: 'uppercase',
  },
}

export default function SocialTicker() {
  const { data } = useApi('/api/social/feed?limit=20', 15000)

  const items = useMemo(() => {
    if (!data) return []
    // Duplicate for seamless loop
    return [...data, ...data]
  }, [data])

  if (!items.length) return <div style={styles.ticker}><span style={styles.label}>INTEL FEED</span></div>

  return (
    <div style={styles.ticker}>
      <span style={styles.label}>INTEL</span>
      <div style={styles.track}>
        {items.map((post, i) => (
          <span key={i} style={styles.item}>
            <span style={styles.dot(post.sentiment)} />
            <span style={styles.source}>{post.author}</span>
            <span style={styles.title}>{post.title}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
