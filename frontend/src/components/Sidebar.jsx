import React from 'react'

const NAV = [
  { key: 'dashboard', label: 'Dashboard', icon: '⬡' },
  { key: 'scan',      label: 'Analyse',   icon: '⊕' },
  { key: 'log',       label: 'SOC Log',   icon: '☰' },
  { key: 'settings',  label: 'Settings',  icon: '⚙' },
]

export default function Sidebar({ current, onNavigate, wsConnected, localMode }) {
  return (
    <nav style={{
      width: 220, background: '#0F172A', display: 'flex', flexDirection: 'column',
      padding: '0 0 16px', position: 'sticky', top: 0, height: '100vh',
      flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: '20px 20px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32, background: 'linear-gradient(135deg,#6366F1,#8B5CF6)',
            borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16,
          }}>🛡️</div>
          <div>
            <div style={{ color: '#fff', fontWeight: 700, fontSize: 15, fontFamily: 'DM Sans' }}>SentinelAI</div>
            <div style={{ color: '#94A3B8', fontSize: 10 }}>Cyber Defense Platform</div>
          </div>
        </div>
      </div>

      {/* WS status */}
      <div style={{ padding: '6px 20px', display: 'flex', alignItems: 'center', gap: 6 }}>
        <div style={{
          width: 7, height: 7, borderRadius: '50%',
          background: wsConnected ? '#10B981' : '#EF4444',
          animation: wsConnected ? 'pulseDot 2s infinite' : 'none',
        }} />
        <span style={{ color: '#64748B', fontSize: 11 }}>
          {wsConnected ? 'Live feed active' : 'Reconnecting…'}
        </span>
      </div>
      
      {/* Local Mode Badge */}
      <div style={{ padding: '4px 20px 16px', minHeight: 40 }}>
        {localMode && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 8px', background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 4,
            color: '#10B981', fontSize: 10, fontWeight: 600,
          }}>
            🔒 Air-gapped Mode
          </span>
        )}
      </div>

      {/* Nav items */}
      <div style={{ flex: 1 }}>
        {NAV.map(item => {
          const active = current === item.key
          return (
            <button key={item.key} onClick={() => onNavigate(item.key)} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              width: '100%', padding: '10px 20px',
              background: active ? 'rgba(99,102,241,0.18)' : 'transparent',
              border: 'none', cursor: 'pointer', textAlign: 'left',
              borderLeft: active ? '3px solid #6366F1' : '3px solid transparent',
              transition: 'all 0.15s',
            }}>
              <span style={{ fontSize: 16, opacity: active ? 1 : 0.5 }}>{item.icon}</span>
              <span style={{
                color: active ? '#fff' : '#94A3B8',
                fontSize: 13, fontWeight: active ? 600 : 400,
              }}>{item.label}</span>
            </button>
          )
        })}
      </div>

      {/* Footer */}
      <div style={{ padding: '12px 20px', borderTop: '1px solid #1E293B' }}>
        <div style={{ color: '#475569', fontSize: 10 }}>IndiaNext Hackathon 2026</div>
        <div style={{ color: '#334155', fontSize: 10 }}>v1.0.0 — SentinelAI</div>
      </div>
    </nav>
  )
}
