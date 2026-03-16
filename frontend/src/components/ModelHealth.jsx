import React, { useState, useEffect } from 'react'
import { getModelHealth, setThreshold } from '../api/sentinelApi'

export default function ModelHealth() {
  const [health, setHealth] = useState(null)
  const [thresholdVal, setThresholdVal] = useState(40)

  useEffect(() => {
    getModelHealth().then(setHealth).catch(console.error)
    const intv = setInterval(() => {
      getModelHealth().then(setHealth).catch(console.error)
    }, 15000)
    return () => clearInterval(intv)
  }, [])

  const handleThresholdChange = (e) => {
    const val = parseInt(e.target.value, 10)
    setThresholdVal(val)
    setThreshold(val).catch(console.error)
  }

  if (!health) return <div className="card" style={{ padding: 20 }}>Loading Health...</div>

  const statusColor = health.health_status === 'healthy' ? '#10B981' : health.health_status === 'warning' ? '#F59E0B' : '#EF4444'

  return (
    <div className="card" style={{ padding: 20, marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div style={{ fontWeight: 600, fontSize: 13 }}>Model Health & Diagnostics</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor }}></div>
          <span style={{ fontSize: 11, color: '#6B7280', textTransform: 'capitalize' }}>{health.health_status}</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
        <div style={{ background: '#F8FAFC', padding: 10, borderRadius: 6 }}>
          <div style={{ fontSize: 10, color: '#9CA3AF', marginBottom: 4 }}>FALSE POSITIVE RATE</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#0F172A', fontFamily: 'IBM Plex Mono' }}>
            {(health.false_positive_rate * 100).toFixed(1)}%
          </div>
        </div>
        <div style={{ background: '#F8FAFC', padding: 10, borderRadius: 6 }}>
          <div style={{ fontSize: 10, color: '#9CA3AF', marginBottom: 4 }}>RETRAINING QUEUE</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#0F172A', fontFamily: 'IBM Plex Mono' }}>
            {health.pending_retraining}
          </div>
        </div>
      </div>

      <div style={{ borderTop: '1px solid #F3F4F6', paddingTop: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#374151' }}>Detection Sensitivity</div>
          <div style={{ fontSize: 12, color: '#6366F1', fontWeight: 700, fontFamily: 'IBM Plex Mono' }}>{thresholdVal}</div>
        </div>
        <input
          type="range"
          min={0} max={100} step={5}
          value={thresholdVal}
          onChange={handleThresholdChange}
          style={{ width: '100%', accentColor: '#6366F1', cursor: 'pointer' }}
        />
        <p style={{ fontSize: 10, color: '#9CA3AF', marginTop: 8, lineHeight: 1.4, margin: '8px 0 0 0' }}>
          Alerts fire above score <strong>{thresholdVal}</strong>.<br />
          {thresholdVal < 40 && "High sensitivity (more alerts)."}
          {thresholdVal >= 40 && thresholdVal < 70 && "Balanced."}
          {thresholdVal >= 70 && "High precision (fewer, more certain alerts)."}
        </p>
      </div>
    </div>
  )
}
