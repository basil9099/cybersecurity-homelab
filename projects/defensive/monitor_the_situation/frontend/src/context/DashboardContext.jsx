import { createContext, useContext, useState } from 'react'

const DashboardContext = createContext()

export function DashboardProvider({ children }) {
  const [refreshInterval, setRefreshInterval] = useState(30000)
  const [selectedCve, setSelectedCve] = useState(null)
  const [selectedActor, setSelectedActor] = useState(null)

  return (
    <DashboardContext.Provider value={{
      refreshInterval, setRefreshInterval,
      selectedCve, setSelectedCve,
      selectedActor, setSelectedActor,
    }}>
      {children}
    </DashboardContext.Provider>
  )
}

export function useDashboard() {
  return useContext(DashboardContext)
}
