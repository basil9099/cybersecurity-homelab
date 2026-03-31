import { DashboardProvider } from './context/DashboardContext'
import DashboardShell from './components/layout/DashboardShell'

export default function App() {
  return (
    <DashboardProvider>
      <DashboardShell />
    </DashboardProvider>
  )
}
