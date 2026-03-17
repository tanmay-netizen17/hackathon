import { useState, useEffect, useCallback, useRef } from 'react'

const BACKEND   = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const DASHBOARD = '/incidents'

/**
 * AlertToast — Premium threat notification panel.
 * Slides in from top-right when the email daemon detects a phishing email.
 * Only shows when an actually suspicious email is found — not on every site visit.
 */
export default function AlertToast() {
  const [alerts, setAlerts]   = useState([])
  const seenIds               = useRef(new Set())

  const addAlert = useCallback((alert) => {
    const id = alert.incident_id || alert.received_at || `a_${Date.now()}`
    if (seenIds.current.has(id)) return
    seenIds.current.add(id)

    setAlerts(prev => [{ ...alert, _id: id }, ...prev].slice(0, 4))

    // Auto-dismiss
    const ms = (alert.sentinel_score || 0) >= 81 ? 18000 : 9000
    setTimeout(() => setAlerts(p => p.filter(a => a._id !== id)), ms)
  }, [])

  // Poll /alerts/stream every 3s for daemon-pushed alerts
  useEffect(() => {
    const tick = async () => {
      try {
        const r = await fetch(`${BACKEND}/alerts/stream`)
        if (!r.ok) return
        const data = await r.json()
        ;(data.pushed_alerts || []).forEach(addAlert)
      } catch {}
    }
    tick()
    const iv = setInterval(tick, 3000)
    return () => clearInterval(iv)
  }, [addAlert])

  if (!alerts.length) return null

  return (
    <div style={{
      position:      'fixed',
      top:           20,
      right:         20,
      zIndex:        9999,
      display:       'flex',
      flexDirection: 'column',
      gap:           10,
      maxWidth:      400,
      pointerEvents: 'none',
    }}>
      {alerts.map(a => (
        <Toast
          key={a._id}
          alert={a}
          onDismiss={() => setAlerts(p => p.filter(x => x._id !== a._id))}
        />
      ))}
    </div>
  )
}

// ─── Individual Toast card ────────────────────────────────────────────────────
function Toast({ alert, onDismiss }) {
  const score    = alert.sentinel_score || 0
  const severity = alert.severity       || 'Unknown'
  const from     = alert.from           || alert.source || 'Email Daemon'
  const subject  = alert.subject        || alert.threat_brief || 'Threat detected'

  const isCrit = score >= 81
  const isHigh = score >= 65

  // Dark-coded palette (consistent with browser extension)
  const pal = isCrit
    ? { bg: 'rgba(15,10,30,0.97)', border: '#F04438', accent: '#FF6B6B', sub: '#FDA4AF', badge: '#F04438' }
    : isHigh
    ? { bg: 'rgba(20,14,10,0.96)', border: '#F97316', accent: '#FDBA74', sub: '#FED7AA', badge: '#F97316' }
    : { bg: 'rgba(10,15,25,0.95)', border: '#FBBF24', accent: '#FDE68A', sub: '#FEF3C7', badge: '#FBBF24' }

  const label = isCrit ? 'CRITICAL EMAIL' : isHigh ? 'HIGH-RISK EMAIL' : 'SUSPICIOUS EMAIL'

  return (
    <div style={{
      background:     pal.bg,
      border:         `1.5px solid ${pal.border}`,
      borderRadius:   14,
      padding:        '14px 16px',
      boxShadow:      `0 8px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04), 0 0 32px ${pal.border}22`,
      backdropFilter: 'blur(16px)',
      animation:      'sgSlideIn 0.35s cubic-bezier(0.22,1,0.36,1)',
      pointerEvents:  'all',
      position:       'relative',
      overflow:       'hidden',
    }}>
      <style>{`
        @keyframes sgSlideIn {
          from { transform: translateX(110%) scale(0.95); opacity: 0; }
          to   { transform: translateX(0)   scale(1);    opacity: 1; }
        }
      `}</style>

      {/* Glow strip at top */}
      <div style={{
        position:   'absolute',
        top:        0, left: 0, right: 0,
        height:     2,
        background: `linear-gradient(90deg, transparent, ${pal.border}, transparent)`,
      }} />

      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Shield SVG */}
          <svg width="30" height="30" viewBox="0 0 32 32" fill="none" style={{ flexShrink: 0 }}>
            <path d="M16 2L4 7v9c0 8.4 5.2 13.8 12 15 6.8-1.2 12-6.6 12-15V7L16 2z"
                  fill={pal.border} fillOpacity="0.2" stroke={pal.border} strokeWidth="1.5"/>
            <path d="M16 6L7 10v6c0 5.6 3.6 9.6 9 10.5 5.4-.9 9-4.9 9-10.5v-6L16 6z"
                  fill={pal.border} fillOpacity="0.4"/>
            <text x="16" y="20" textAnchor="middle" fill="white" fontSize="9" fontWeight="800"
                  fontFamily="system-ui">SG</text>
          </svg>

          <div>
            <div style={{
              fontSize:      10,
              fontWeight:    800,
              letterSpacing: '0.1em',
              color:         pal.accent,
              textTransform: 'uppercase',
              marginBottom:  2,
            }}>
              {label}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{
                background:    pal.badge,
                color:         '#fff',
                fontSize:      10,
                fontWeight:    700,
                padding:       '2px 8px',
                borderRadius:  20,
                letterSpacing: '0.04em',
              }}>
                {score}/100
              </span>
              <span style={{ fontSize: 11, color: '#64748B' }}>
                {severity}
              </span>
            </div>
          </div>
        </div>

        <button
          onClick={onDismiss}
          style={{
            background:  'rgba(255,255,255,0.06)',
            border:      '1px solid rgba(255,255,255,0.1)',
            borderRadius: 6,
            color:       '#64748B',
            cursor:      'pointer',
            width:       24, height: 24,
            display:     'flex', alignItems: 'center', justifyContent: 'center',
            fontSize:    14, lineHeight: 1,
            flexShrink:  0,
          }}
        >×</button>
      </div>

      {/* Email details */}
      <div style={{
        background:   'rgba(255,255,255,0.04)',
        border:       '1px solid rgba(255,255,255,0.07)',
        borderRadius: 8,
        padding:      '8px 10px',
        marginBottom: 10,
      }}>
        <div style={{
          fontSize:       12,
          fontWeight:     600,
          color:          pal.sub,
          overflow:       'hidden',
          textOverflow:   'ellipsis',
          whiteSpace:     'nowrap',
          marginBottom:   3,
        }}>
          {subject.slice(0, 55)}
        </div>
        <div style={{ fontSize: 11, color: '#64748B' }}>
          From: {from.slice(0, 48)}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8 }}>
        <a
          href={DASHBOARD}
          target="_blank"
          rel="noreferrer"
          style={{
            flex:           1,
            textAlign:      'center',
            fontSize:       11,
            fontWeight:     700,
            color:          pal.accent,
            textDecoration: 'none',
            padding:        '7px 0',
            border:         `1px solid ${pal.border}44`,
            borderRadius:   8,
            cursor:         'pointer',
            background:     `${pal.badge}11`,
          }}
        >
          Investigate →
        </a>
        <button
          onClick={onDismiss}
          style={{
            fontSize:     11,
            background:   'rgba(255,255,255,0.04)',
            border:       '1px solid rgba(255,255,255,0.08)',
            borderRadius: 8,
            padding:      '7px 14px',
            cursor:       'pointer',
            color:        '#64748B',
          }}
        >
          Dismiss
        </button>
      </div>
    </div>
  )
}
