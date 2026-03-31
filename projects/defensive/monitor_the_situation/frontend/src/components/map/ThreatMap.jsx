import { useState, useMemo } from 'react'
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps'
import { scaleLinear } from 'd3-scale'
import useApi from '../../hooks/useApi'
import MapTooltip from './MapTooltip'
import MapLegend from './MapLegend'

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const CATEGORY_COLORS = {
  scanner: '#58a6ff',
  brute_force: '#ff8c00',
  malware: '#ff4444',
  exploitation: '#d63384',
  botnet: '#8b5cf6',
  spam: '#8b949e',
}

const styles = {
  container: { position: 'relative', width: '100%', height: '100%' },
  tooltip: {
    position: 'absolute',
    background: 'var(--surface2)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    padding: '8px 12px',
    fontSize: '12px',
    pointerEvents: 'none',
    zIndex: 10,
  },
}

export default function ThreatMap() {
  const { data: events } = useApi('/api/threat-map?limit=500', 30000)
  const { data: stats } = useApi('/api/threat-map/stats', 30000)
  const [tooltip, setTooltip] = useState(null)

  const markers = useMemo(() => {
    if (!events) return []
    // Deduplicate by rounding coordinates
    const seen = new Map()
    for (const e of events) {
      if (!e.latitude || !e.longitude) continue
      const key = `${e.latitude.toFixed(1)},${e.longitude.toFixed(1)}`
      if (seen.has(key)) {
        seen.get(key).count++
      } else {
        seen.set(key, { ...e, count: 1 })
      }
    }
    return Array.from(seen.values())
  }, [events])

  const sizeScale = scaleLinear().domain([1, 20]).range([3, 12]).clamp(true)

  return (
    <div style={styles.container}>
      <ComposableMap
        projectionConfig={{ scale: 140, center: [10, 20] }}
        style={{ width: '100%', height: '100%' }}
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rpiKey || geo.properties.name}
                geography={geo}
                fill="#21262d"
                stroke="#30363d"
                strokeWidth={0.5}
                style={{
                  default: { outline: 'none' },
                  hover: { fill: '#2d333b', outline: 'none' },
                  pressed: { outline: 'none' },
                }}
              />
            ))
          }
        </Geographies>

        {markers.map((m, i) => (
          <Marker
            key={i}
            coordinates={[m.longitude, m.latitude]}
            onMouseEnter={() => setTooltip(m)}
            onMouseLeave={() => setTooltip(null)}
          >
            <circle
              r={sizeScale(m.count)}
              fill={CATEGORY_COLORS[m.category] || '#58a6ff'}
              fillOpacity={0.7}
              stroke={CATEGORY_COLORS[m.category] || '#58a6ff'}
              strokeWidth={1}
              strokeOpacity={0.3}
            />
          </Marker>
        ))}
      </ComposableMap>

      {tooltip && <MapTooltip event={tooltip} />}
      <MapLegend stats={stats} />
    </div>
  )
}
