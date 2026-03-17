import { useEffect, useState, useRef } from 'react'

export function useLiveFeed() {
  const [incidents, setIncidents]   = useState([])
  const [status,    setStatus]      = useState('connecting')  // 'connecting' | 'connected' | 'disconnected'
  const [stats, setStats]           = useState({ total: 0, critical: 0, blocked: 0, clean: 0 })
  const [surgeAlert, setSurgeAlert] = useState(null)
  const wsRef = useRef(null)

  useEffect(() => {
    function connect() {
      const url = `${import.meta.env.VITE_WS_URL || 'ws://localhost:8000'}/ws/live`
      const ws  = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => setStatus('connected')

      ws.onmessage = (e) => {
        const data = JSON.parse(e.data)
        if (data.type === 'ping') return
        if (data.type === 'heartbeat') return   // ignore heartbeats
        if (data.type === 'surge_alert') {
          setSurgeAlert(data)
          return
        }

        const payload = data.data || data; // Flatten payload if nested
        // Normalize fields if missing
        if (payload.received_at && !payload.timestamp) payload.timestamp = payload.received_at;
        if (payload.source && !payload.ingestion_source) payload.ingestion_source = payload.source;

        setIncidents(prev => [payload, ...prev].slice(0, 200))
        setStats(prev => ({
          total:    prev.total + 1,
          critical: prev.critical + (payload.severity === 'Critical' ? 1 : 0),
          blocked:  prev.blocked + (payload.sentinel_score >= 61 ? 1 : 0),
          clean:    prev.clean + (payload.severity === 'Clean' ? 1 : 0),
        }))
      }

      ws.onclose = () => {
        setStatus('disconnected')
        // Auto-reconnect after 3 seconds
        setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        setStatus('disconnected')
        ws.close()
      }
    }

    connect()
    return () => wsRef.current?.close()
  }, [])

  return { incidents, status, stats, surgeAlert, setIncidents, setStats, setSurgeAlert }
}
