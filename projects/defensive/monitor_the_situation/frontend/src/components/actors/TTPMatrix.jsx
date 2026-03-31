const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

const styles = {
  matrix: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '2px',
  },
  cell: (count) => ({
    width: '16px',
    height: '16px',
    borderRadius: '2px',
    background: count > 10 ? 'var(--critical)' : count > 5 ? 'var(--high)' : count > 0 ? 'var(--accent)' : 'var(--surface2)',
    opacity: count > 0 ? 0.4 + Math.min(count / 15, 0.6) : 0.2,
    cursor: count > 0 ? 'pointer' : 'default',
    title: '',
  }),
}

export default function TTPMatrix({ ttps = [] }) {
  if (!ttps.length) return null

  const byTactic = {}
  for (const ttp of ttps) {
    const t = ttp.tactic || 'unknown'
    byTactic[t] = (byTactic[t] || 0) + (ttp.usage_count || 1)
  }

  return (
    <div style={styles.matrix}>
      {TACTIC_ORDER.map((tactic) => (
        <div
          key={tactic}
          style={styles.cell(byTactic[tactic] || 0)}
          title={`${tactic}: ${byTactic[tactic] || 0}`}
        />
      ))}
    </div>
  )
}
