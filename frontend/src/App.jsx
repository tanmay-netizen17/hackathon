import React, { useState, useEffect } from 'react'
import { Routes, Route, useNavigate, BrowserRouter, NavLink, useLocation } from 'react-router-dom'
import { ModeProvider, useMode } from './context/ModeContext'
import { useLiveFeed } from './hooks/useLiveFeed'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import IncidentLog from './pages/IncidentLog'
import RedTeam from './pages/RedTeam'
import Settings from './pages/Settings'
import AlertToast from './components/AlertToast'
import { useAlerts } from './hooks/useAlerts'
import './index.css'

// SVG icon primitives (extracted from Sidebar for direct use in App.jsx)
const GridIcon = ({ size = 16, style }) => (
  <svg width={size} height={size} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect>
  </svg>
)
const SearchIcon = ({ size = 16, style }) => (
  <svg width={size} height={size} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
  </svg>
)
const ShieldIcon = ({ size = 16, style }) => (
  <svg width={size} height={size} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
)
const CrosshairIcon = ({ size = 16, style }) => (
  <svg width={size} height={size} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line>
  </svg>
)
const SlidersIcon = ({ size = 16, style }) => (
  <svg width={size} height={size} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line>
  </svg>
)
function ShieldLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <path d="M14 2L4 6.5V13.5C4 19.2 8.4 24.6 14 26C19.6 24.6 24 19.2 24 13.5V6.5L14 2Z"
        fill="#0A84FF" fillOpacity="0.15" stroke="#0A84FF" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 14l3 3 5-5" stroke="#0A84FF" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

const NAV_ITEMS = [
  { path:'/',          label:'Overview', Icon: GridIcon },
  { path:'/scan',      label:'Scan',     Icon: SearchIcon },
  { path:'/incidents', label:'Incidents',Icon: ShieldIcon },
  { path:'/red-team',  label:'Red Team', Icon: CrosshairIcon },
  { path:'/settings',  label:'Settings', Icon: SlidersIcon },
]

export const ThemeContext = React.createContext({})

function AgentStatusPanel() {
  const { wsConnected } = React.useContext(ThemeContext)
  return (
    <div style={{ margin: '0 12px 12px', padding: '12px', background: 'var(--bg-sunken)', borderRadius: 8, border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>Agent Status</div>
      {[{ label: 'Live Feed', connected: wsConnected }].map(agent => (
        <div key={agent.label} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: agent.connected ? '#10B981' : '#6B7280' }} />
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{agent.label}</span>
        </div>
      ))}
    </div>
  )
}

function AppInner() {
  const [collapsed, setCollapsed] = useState(false)
  const SIDEBAR_W  = collapsed ? 64  : 240
  const TRANSITION = 'width 0.25s cubic-bezier(0.4,0,0.2,1)'
  const navigate = useNavigate()

  const { incidents, status, stats, surgeAlert, setIncidents, setStats } = useLiveFeed()
  const { mode, localServerOnline } = useMode()
  
  const wsConnected = status === 'connected'
  const localMode = mode === 'local'

  useAlerts({
    onAlert: (alert) => {
      window.__sentinelAddAlert?.(alert)
    }
  })

  const addIncident = (incident) => {
    setIncidents(prev => [incident, ...prev].slice(0, 200))
    setStats(prev => ({
      total:    prev.total + 1,
      critical: prev.critical + (incident.severity === 'Critical' ? 1 : 0),
      blocked:  prev.blocked + (incident.sentinel_score >= 61 ? 1 : 0),
      clean:    prev.clean + (incident.severity === 'Clean' ? 1 : 0),
    }))
  }

  return (
    <ThemeContext.Provider value={{ incidents, stats, wsConnected, addIncident, surgeAlert, localMode }}>
      <div style={{ display:'flex', minHeight:'100vh', background: 'var(--bg-primary)' }}>
        
        {/* SIDEBAR */}
        <aside style={{
          width:      SIDEBAR_W,
          minWidth:   SIDEBAR_W,
          flexShrink: 0,
          height:     '100vh',
          position:   'sticky',
          top:        0,
          background: '#FFFFFF',
          borderRight:'1px solid var(--border)',
          display:    'flex',
          flexDirection:'column',
          overflow:   'hidden',
          transition: TRANSITION,
          zIndex:     100,
        }}>
          {/* Logo row + collapse toggle */}
          <div style={{
            height:      64,
            display:     'flex',
            alignItems:  'center',
            justifyContent: collapsed ? 'center' : 'space-between',
            padding:     collapsed ? '0' : '0 20px',
            borderBottom:'1px solid var(--border-light)',
            flexShrink:  0,
          }}>
            {!collapsed && (
              <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                <ShieldLogo size={24} />
                <span style={{ fontWeight:700, fontSize:15, color:'var(--text-primary)', whiteSpace:'nowrap', fontFamily: 'Syne, sans-serif' }}>
                  SentinelAI
                </span>
              </div>
            )}
            {collapsed && <ShieldLogo size={24} />}

            <button
              onClick={() => setCollapsed(c => !c)}
              style={{
                background:'none', border:'none', cursor:'pointer',
                padding:6, borderRadius:6, color:'var(--text-muted)',
                display:'flex', alignItems:'center',
                flexShrink: 0,
                marginLeft: collapsed ? 0 : 4,
              }}
              title={collapsed ? 'Expand' : 'Collapse'}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round"
                style={{ transform: collapsed ? 'rotate(180deg)' : 'rotate(0deg)',
                         transition: 'transform 0.25s' }}>
                <polyline points="15 18 9 12 15 6"/>
              </svg>
            </button>
          </div>

          {/* Nav items */}
          <nav style={{ flex:1, padding:'16px 12px', overflowY:'auto', overflowX:'hidden' }}>
            {NAV_ITEMS.map(({ path, label, Icon }) => (
              <NavLink key={path} to={path} style={{ textDecoration:'none' }}>
                {({ isActive }) => (
                  <div style={{
                    display:      'flex',
                    alignItems:   'center',
                    gap:          collapsed ? 0 : 12,
                    justifyContent: collapsed ? 'center' : 'flex-start',
                    padding:      '12px',
                    borderRadius: 10,
                    marginBottom: 4,
                    color:        isActive ? 'var(--accent)' : 'var(--text-secondary)',
                    background:   isActive ? 'rgba(10, 132, 255, 0.08)' : 'transparent',
                    fontWeight:   isActive ? 600 : 400,
                    fontSize:     14,
                    borderLeft:   isActive && !collapsed ? '3px solid var(--accent)' : '3px solid transparent',
                    transition:   'all 0.15s ease',
                    cursor:       'pointer',
                    whiteSpace:   'nowrap',
                    overflow:     'hidden',
                  }}
                  title={collapsed ? label : ''}
                  >
                    <Icon size={18} style={{ flexShrink:0 }} />
                    {!collapsed && <span>{label}</span>}
                  </div>
                )}
              </NavLink>
            ))}
          </nav>

          {!collapsed && <AgentStatusPanel />}

          {!collapsed && (
            <div style={{ padding:'12px 20px', fontSize:11, color:'var(--text-muted)', fontFamily:'monospace', opacity: 0.6 }}>
              SentinelAI v1.0 · Build 20260317
            </div>
          )}
        </aside>

        {/* MAIN AREA */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0 }}>
           <main style={{ flex:1, padding: '24px 32px', overflowY:'auto' }}>
            <Routes>
              <Route path="/"              element={<Dashboard onNavigate={navigate} />} />
              <Route path="/scan"          element={<ScanPage />} />
              <Route path="/incidents"     element={<IncidentLog />} />
              <Route path="/red-team"      element={<RedTeam />} />
              <Route path="/settings"      element={<Settings />} />
            </Routes>
          </main>
        </div>

        <AlertToast />
      </div>
    </ThemeContext.Provider>
  )
}

export default function App() {
  return (
    <ModeProvider>
      <BrowserRouter>
        <AppInner />
      </BrowserRouter>
    </ModeProvider>
  )
}
