import React, { useContext } from 'react'
import { ThemeContext } from '../App'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import ModelHealth from './ModelHealth'

const SEV_COLORS = {
  Clean: '#10B981', Suspicious: '#F59E0B', 'Likely Malicious': '#F97316', Critical: '#EF4444',
}

function StatCard({ label, value, color, icon }) {
  return (
    <div className="card" style={{ padding: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 12, color: '#9CA3AF', fontWeight: 500, marginBottom: 4 }}>{label.toUpperCase()}</div>
          <div style={{ fontSize: 32, fontWeight: 700, color, fontFamily: 'IBM Plex Mono' }}>{value}</div>
        </div>
        <div style={{ fontSize: 28 }}>{icon}</div>
      </div>
    </div>
  )
}

function LiveFeedItem({ incident, idx }) {
  const color = SEV_COLORS[incident.severity] || '#10B981'
  return (
    <div style={{
      display: 'flex', gap: 12, padding: '12px 16px',
      borderBottom: '1px solid #F3F4F6',
      animation: `slideInRight 0.35s ease ${idx * 0.06}s both`,
    }}>
      <div style={{
        minWidth: 44, height: 44, borderRadius: 8,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: color + '18', fontSize: 18, fontWeight: 700,
        color, fontFamily: 'IBM Plex Mono',
      }}>{incident.sentinel_score}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{
            fontSize: 12, padding: '2px 8px', borderRadius: 4,
            background: color + '18', color, fontWeight: 600,
          }}>{incident.severity}</span>
          <span style={{ fontSize: 11, color: '#9CA3AF' }}>
            {incident.timestamp ? new Date(incident.timestamp).toLocaleTimeString() : ''}
          </span>
        </div>
        <div style={{ fontSize: 13, color: '#374151', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {incident.threat_brief?.split('.')[0] || incident.primary_threat || 'Threat detected'}
        </div>
        <div style={{ fontSize: 11, color: '#9CA3AF', marginTop: 2 }}>
          {incident.incident_id} · {incident.ingestion_source}
        </div>
      </div>
    </div>
  )
}

export default function Dashboard({ onNavigate }) {
  const { incidents, stats, wsConnected, surgeAlert, setSurgeAlert } = useContext(ThemeContext)

  // Distribution data for donut chart
  const sevCounts = incidents.reduce((acc, inc) => {
    acc[inc.severity] = (acc[inc.severity] || 0) + 1; return acc
  }, {})
  const pieData = Object.entries(sevCounts).map(([k, v]) => ({ name: k, value: v }))

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'DM Sans', fontSize: 24, fontWeight: 700, color: '#0F172A', margin: 0 }}>
            Security Dashboard
          </h1>
          <p style={{ color: '#6B7280', fontSize: 14, marginTop: 2 }}>
            {wsConnected ? (
              <><span className="pulse-dot" style={{ marginRight: 6 }} />Live monitoring active</>
            ) : 'Connecting to live feed…'}
          </p>
        </div>
        <button onClick={() => onNavigate('scan')} style={{
          padding: '10px 20px', background: '#6366F1', color: '#fff',
          border: 'none', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13,
        }}>+ Analyse Threat</button>
      </div>

      {surgeAlert && (
        <div style={{
          width: '100%', padding: '12px 20px', background: '#FEF2F2', border: '1px solid #FCA5A5',
          borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24,
          animation: 'pulseDot 2s ease-in-out infinite'
        }}>
          <span style={{ color: '#DC2626', fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>🚨</span>
            {surgeAlert.message}
          </span>
          <button 
            onClick={() => setSurgeAlert(null)} 
            style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: '#F87171', cursor: 'pointer', fontSize: 14, padding: 4 }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 24 }}>
        <StatCard label="Total Scans" value={stats.total} color="#6366F1" icon="🔍" />
        <StatCard label="Critical" value={stats.critical} color="#EF4444" icon="🚨" />
        <StatCard label="Blocked" value={stats.blocked} color="#F97316" icon="🛡️" />
        <StatCard label="Clean" value={stats.clean} color="#10B981" icon="✅" />
      </div>

      {/* Live feed + chart */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
        {/* Feed */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '14px 16px', borderBottom: '1px solid #F3F4F6', display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>Live Threat Stream</span>
            <span style={{ fontSize: 12, color: '#9CA3AF' }}>{incidents.length} incidents</span>
          </div>
          <div style={{ maxHeight: 420, overflowY: 'auto' }}>
            {incidents.length === 0 ? (
              <div style={{ padding: 32, textAlign: 'center', color: '#9CA3AF', fontSize: 13 }}>
                No incidents yet. Use the Analyse tab or wait for passive agents.
              </div>
            ) : incidents.slice(0, 20).map((inc, i) => (
              <LiveFeedItem key={inc.incident_id || i} incident={inc} idx={i} />
            ))}
          </div>
        </div>

        {/* Chart */}
        <div>
          <ModelHealth />

          <div className="card" style={{ padding: 20, marginBottom: 16 }}>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 14 }}>Threat Distribution</div>
            {pieData.length === 0 ? (
              <div style={{ color: '#9CA3AF', fontSize: 12, textAlign: 'center', padding: 20 }}>No data yet</div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                      {pieData.map((entry, index) => (
                        <Cell key={index} fill={SEV_COLORS[entry.name] || '#94A3B8'} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(v, n) => [v, n]} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {pieData.map(d => (
                    <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <div style={{ width: 10, height: 10, borderRadius: 2, background: SEV_COLORS[d.name] || '#94A3B8' }} />
                        <span style={{ color: '#374151' }}>{d.name}</span>
                      </div>
                      <span style={{ color: '#6B7280', fontFamily: 'IBM Plex Mono' }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* MITRE summary */}
          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>ATT&CK Tactics Seen</div>
            {incidents.length === 0 ? (
              <div style={{ color: '#9CA3AF', fontSize: 12 }}>No tactics recorded yet</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[...new Set(incidents.map(i => i.mitre_label).filter(Boolean))].slice(0, 5).map(label => (
                  <div key={label} style={{
                    padding: '4px 8px', background: '#EEF2FF', borderRadius: 4,
                    fontSize: 12, color: '#3730A3', fontWeight: 500,
                  }}>{label}</div>
                ))}
              </div>
            )}
          </div>

          {/* Secure-by-Design Badge */}
          <div style={{ marginTop: 16, padding: '12px 16px', background: '#F0FDF4', borderRadius: 8, border: '1px solid #BBF7D0' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ color: '#16A34A', fontSize: 16 }}>🛡️</span>
              <span style={{ color: '#16A34A', fontWeight: 700, fontSize: 13 }}>Secure-by-Design</span>
            </div>
            <div style={{ color: '#4ADE80', fontSize: 11, fontWeight: 500 }}>
              Rate limited · Input sanitised · Audit logged · OWASP headers active
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
