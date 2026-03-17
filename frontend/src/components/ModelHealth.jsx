import React, { useState, useEffect } from 'react'
import { api } from '../api/spectraApi'
import { SectionHeader } from './SectionHeader'

export default function ModelHealth() {
  const [health, setHealth] = useState(null)
  const [thresholdVal, setThresholdVal] = useState(40)

  useEffect(() => {
    api.modelHealth().then(setHealth).catch(console.error)
    const intv = setInterval(() => {
      api.modelHealth().then(setHealth).catch(console.error)
    }, 15000)
    return () => clearInterval(intv)
  }, [])

  const handleThresholdChange = (e) => {
    const val = parseInt(e.target.value, 10)
    setThresholdVal(val)
    api.setThreshold(val).catch(console.error)
  }

  if (!health) return <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>Loading Analytics…</div>

  const statusColor = health.health_status === 'healthy' ? 'var(--clean)' : health.health_status === 'warning' ? 'var(--suspicious)' : 'var(--critical)'

  return (
    <div className="card" style={{ padding: 24, marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, margin: 0 }}>Ensemble Health</h3>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-sunken)', padding: '4px 10px', borderRadius: 20 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor }}></div>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>{health.health_status}</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-primary)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '0.04em' }}>FALSE POSITIVE RATE</div>
          <div className="count-up" style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {(health.false_positive_rate * 100).toFixed(1)}<span style={{ fontSize: 16, color: 'var(--text-muted)' }}>%</span>
          </div>
        </div>
        <div style={{ background: 'var(--bg-primary)', padding: 16, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '0.04em' }}>RETRAINING QUEUE</div>
          <div className="count-up" style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {health.pending_retraining}
          </div>
        </div>
      </div>

      {/* Threshold Slider */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Detection Sensitivity</div>
          <div style={{ background: 'var(--accent-dim)', color: 'var(--accent-hover)', padding: '2px 8px', borderRadius: 4, fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600 }}>
            {thresholdVal}
          </div>
        </div>
        <input
          type="range"
          min={0} max={100} step={5}
          value={thresholdVal}
          onChange={handleThresholdChange}
          style={{ width: '100%', accentColor: 'var(--text-primary)', cursor: 'pointer', height: 4, background: 'var(--border)', outline: 'none', borderRadius: 2 }}
        />
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 12, lineHeight: 1.5, fontFamily: 'var(--font-body)' }}>
          Alerts fire above score <strong>{thresholdVal}</strong>.
          <br />
          {thresholdVal < 40 && "High sensitivity (more alerts)."}
          {thresholdVal >= 40 && thresholdVal < 70 && "Balanced."}
          {thresholdVal >= 70 && "High precision (fewer, more certain alerts)."}
        </p>
      </div>
    </div>
  )
}
