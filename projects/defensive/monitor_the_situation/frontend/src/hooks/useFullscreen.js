import { useState, useCallback } from 'react'

export default function useFullscreen() {
  const [isFullscreen, setIsFullscreen] = useState(false)

  const toggle = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => setIsFullscreen(true))
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false))
    }
  }, [])

  return { isFullscreen, toggle }
}
