import useApi from '../../hooks/useApi'

const FLAG_MAP = {
  RU: '\u{1F1F7}\u{1F1FA}', CN: '\u{1F1E8}\u{1F1F3}', KP: '\u{1F1F0}\u{1F1F5}',
  IR: '\u{1F1EE}\u{1F1F7}', US: '\u{1F1FA}\u{1F1F8}',
}

const styles = {
  list: { display: 'flex', flexDirection: 'column', gap: '4px' },
  item: {
    background: 'var(--surface2)',
    borderRadius: '4px',
    padding: '8px 10px',
    border: '1px solid var(--border)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '4px',
  },
  rank: {
    fontFamily: 'var(--font-mono)',
    fontSize: '14px',
    fontWeight: 700,
    color: 'var(--accent)',
    minWidth: '20px',
  },
  name: {
    fontSize: '13px',
    fontWeight: 600,
  },
  aliases: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  meta: {
    display: 'flex',
    gap: '8px',
    fontSize: '10px',
    color: 'var(--text-muted)',
    marginTop: '4px',
  },
  tag: {
    background: 'var(--accent-dim)',
    color: 'var(--accent)',
    padding: '1px 6px',
    borderRadius: '3px',
    fontSize: '10px',
  },
  score: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    color: 'var(--medium)',
  },
  empty: {
    color: 'var(--text-muted)',
    fontSize: '12px',
    textAlign: 'center',
    padding: '20px',
  },
}

export default function ActorLeaderboard() {
  const { data, loading } = useApi('/api/actors?limit=10', 60000)

  if (loading) return <div style={styles.empty}>Loading...</div>
  if (!data?.length) return <div style={styles.empty}>No actor data</div>

  return (
    <div style={styles.list}>
      {data.map((entry) => {
        const actor = entry.actor
        const flag = FLAG_MAP[actor.country_origin] || ''
        const aliases = Array.isArray(actor.aliases)
          ? actor.aliases
          : (typeof actor.aliases === 'string' ? JSON.parse(actor.aliases || '[]') : [])

        return (
          <div key={actor.id} style={styles.item}>
            <div style={styles.header}>
              <span style={styles.rank}>#{entry.rank}</span>
              <span>{flag}</span>
              <span style={styles.name}>{actor.name}</span>
              <span style={styles.score}>{actor.rank_score}</span>
            </div>
            <div style={styles.aliases}>
              {aliases.slice(0, 3).join(' / ')}
            </div>
            <div style={styles.meta}>
              <span>{actor.campaign_count} campaigns</span>
              <span>{actor.technique_count} techniques</span>
              <span style={styles.tag}>{actor.sophistication}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
