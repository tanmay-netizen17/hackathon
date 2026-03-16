import React, { useState, useEffect, useRef } from 'react'
import { createWebSocket, getHealth } from './api/sentinelApi'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import IncidentLog from './pages/IncidentLog'
import Settings from './pages/Settings'
import './index.css'

export const ThemeContext = React.createContext({})

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [incidents, setIncidents] = useState([])
  const [wsConnected, setWsConnected] = useState(false)
  const [stats, setStats] = useState({ total: 0, critical: 0, blocked: 0, clean: 0 })
  const [surgeAlert, setSurgeAlert] = useState(null)
  const [localMode, setLocalMode] = useState(false)
  const wsRef = useRef(null)

  // ── WebSocket live feed ─────────────────────────────────────────────────
  useEffect(() => {
    let reconnectTimer
    const connect = () => {
      wsRef.current = createWebSocket(
        (msg) => {
          if (msg.type === 'ping') return
          if (msg.type === 'surge_alert') {
            setSurgeAlert(msg)
            return
          }
          setIncidents(prev => {
            const updated = [msg, ...prev].slice(0, 200)
            return updated
          })
          setStats(prev => ({
            total:    prev.total + 1,
            critical: prev.critical + (msg.severity === 'Critical' ? 1 : 0),
            blocked:  prev.blocked + (msg.sentinel_score >= 61 ? 1 : 0),
            clean:    prev.clean + (msg.severity === 'Clean' ? 1 : 0),
          }))
          setWsConnected(true)
        },
        () => {
          setWsConnected(false)
          reconnectTimer = setTimeout(connect, 5000)
        }
      )
    }
    connect()
    return () => {
      clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [])

  // ── Top-level incident injected from scan page ─────────────────────────
  const addIncident = (incident) => {
    setIncidents(prev => [incident, ...prev].slice(0, 200))
    setStats(prev => ({
      total:    prev.total + 1,
      critical: prev.critical + (incident.severity === 'Critical' ? 1 : 0),
      blocked:  prev.blocked + (incident.sentinel_score >= 61 ? 1 : 0),
      clean:    prev.clean + (incident.severity === 'Clean' ? 1 : 0),
    }))
  }

  const pages = { dashboard: Dashboard, scan: ScanPage, log: IncidentLog, settings: Settings }
  const ActivePage = pages[page] || Dashboard

  return (
    <ThemeContext.Provider value={{ incidents, stats, wsConnected, addIncident, surgeAlert, setSurgeAlert, localMode, setLocalMode }}>
      <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)' }}>
        <Sidebar current={page} onNavigate={setPage} wsConnected={wsConnected} localMode={localMode} />
        <main style={{ flex: 1, overflowY: 'auto', padding: '28px 32px' }}>
          <ActivePage onNavigate={setPage} />
        </main>
      </div>
    </ThemeContext.Provider>
  )
}
