import { useState, useEffect, useRef, useCallback } from 'react'

export default function useWebSocket(channels = []) {
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState(null)
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

    ws.onopen = () => {
      setConnected(true)
      if (channels.length > 0) {
        ws.send(JSON.stringify({ subscribe: channels }))
      }
    }

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        setLastMessage(msg)
      } catch {}
    }

    ws.onclose = () => {
      setConnected(false)
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
  }, [channels.join(',')])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [connect])

  const subscribe = useCallback((newChannels) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ subscribe: newChannels }))
    }
  }, [])

  return { connected, lastMessage, subscribe }
}
