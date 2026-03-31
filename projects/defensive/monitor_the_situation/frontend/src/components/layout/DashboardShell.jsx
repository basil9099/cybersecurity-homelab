import { useEffect } from 'react'
import useWebSocket from '../../hooks/useWebSocket'
import useApi from '../../hooks/useApi'
import StatusBar from './StatusBar'
import PanelFrame from './PanelFrame'
import ThreatMap from '../map/ThreatMap'
import CVEVelocityChart from '../cve/CVEVelocityChart'
import CriticalAlerts from '../cve/CriticalAlerts'
import ActorLeaderboard from '../actors/ActorLeaderboard'
import ExploitTimeline from '../exploits/ExploitTimeline'
import WeaponizationAlerts from '../exploits/WeaponizationAlerts'
import SocialTicker from '../social/SocialTicker'
import CollectorStatus from '../health/CollectorStatus'
import AlertBanner from '../shared/AlertBanner'

const styles = {
  shell: {
    display: 'grid',
    gridTemplateAreas: `
      "status status status"
      "alert alert alert"
      "cvevel cvevel cvecrit"
      "actors map exploits"
      "actors map exploits2"
      "ticker ticker ticker"
      "health health health"
    `,
    gridTemplateColumns: '300px 1fr 300px',
    gridTemplateRows: 'auto auto 180px 1fr 1fr 50px auto',
    height: '100vh',
    gap: '2px',
    background: 'var(--bg)',
    padding: '2px',
  },
}

export default function DashboardShell() {
  const { connected, lastMessage } = useWebSocket([
    'threat_map', 'cves', 'exploits', 'social', 'alerts', 'system',
  ])

  return (
    <div style={styles.shell}>
      <div style={{ gridArea: 'status' }}>
        <StatusBar connected={connected} />
      </div>

      <div style={{ gridArea: 'alert' }}>
        <AlertBanner />
      </div>

      <div style={{ gridArea: 'cvevel' }}>
        <PanelFrame title="CVE Velocity">
          <CVEVelocityChart />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'cvecrit' }}>
        <PanelFrame title="Critical CVEs">
          <CriticalAlerts />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'actors' }}>
        <PanelFrame title="Threat Actors">
          <ActorLeaderboard />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'map' }}>
        <PanelFrame title="Global Threat Map">
          <ThreatMap />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'exploits' }}>
        <PanelFrame title="Exploit Timeline">
          <ExploitTimeline />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'exploits2' }}>
        <PanelFrame title="Weaponization Alerts">
          <WeaponizationAlerts />
        </PanelFrame>
      </div>

      <div style={{ gridArea: 'ticker' }}>
        <SocialTicker />
      </div>

      <div style={{ gridArea: 'health' }}>
        <CollectorStatus />
      </div>
    </div>
  )
}
