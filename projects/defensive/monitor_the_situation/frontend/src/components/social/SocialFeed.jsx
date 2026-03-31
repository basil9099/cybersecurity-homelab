import useApi from '../../hooks/useApi'
import TimeAgo from '../shared/TimeAgo'

const SENTIMENT_COLORS = {
  alert: 'var(--critical)',
  analysis: 'var(--accent)',
  neutral: 'var(--text-muted)',
}

const styles = {
  list: { display: 'flex', flexDirection: 'column', gap: '6px' },
  post: {
    background: 'var(--surface2)',
    borderRadius: '4px',
    padding: '10px 12px',
    border: '1px solid var(--border)',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '4px',
  },
  author: {
    fontSize: '12px',
    fontWeight: 600,
    color: 'var(--accent)',
  },
  sentiment: (s) => ({
    fontSize: '9px',
    padding: '1px 5px',
    borderRadius: '3px',
    background: SENTIMENT_COLORS[s] || 'var(--info)',
    color: '#fff',
    textTransform: 'uppercase',
    fontWeight: 600,
  }),
  title: {
    fontSize: '13px',
    marginBottom: '4px',
  },
  content: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: '-webkit-box',
    WebkitLineClamp: 2,
    WebkitBoxOrient: 'vertical',
  },
  meta: {
    display: 'flex',
    gap: '8px',
    marginTop: '4px',
    fontSize: '10px',
    color: 'var(--text-muted)',
  },
}

export default function SocialFeed() {
  const { data, loading } = useApi('/api/social/feed?limit=15', 15000)

  if (loading) return <div>Loading...</div>
  if (!data?.length) return <div>No posts</div>

  return (
    <div style={styles.list}>
      {data.map((post) => (
        <div key={post.id} style={styles.post}>
          <div style={styles.header}>
            <span style={styles.author}>{post.author}</span>
            <span style={styles.sentiment(post.sentiment)}>{post.sentiment}</span>
          </div>
          <div style={styles.title}>{post.title}</div>
          <div style={styles.content}>{post.content}</div>
          <div style={styles.meta}>
            <span>{post.source}</span>
            <span>cred: {(post.credibility * 100).toFixed(0)}%</span>
            <TimeAgo date={post.published_date} />
          </div>
        </div>
      ))}
    </div>
  )
}
