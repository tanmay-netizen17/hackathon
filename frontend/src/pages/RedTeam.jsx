import React, { useState, useEffect } from 'react'
import { SectionHeader } from '../components/SectionHeader'

function ModelHealthPanel() {
  const [health, setHealth]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  useEffect(() => {
    const base = import.meta.env.VITE_API_URL || 'http://localhost:8000'
    fetch(`${base}/model-health`)
      .then(r => r.json())
      .then(data => { setHealth(data); setLoading(false) })
      .catch(err => { setError(err.message); setLoading(false) })
  }, [])

  if (loading) return (
    <div style={{ padding:24, color:'#9CA3AF', fontSize:13 }}>Loading analytics…</div>
  )

  if (error) return (
    <div style={{ padding:24, color:'#F04438', fontSize:13 }}>
      Could not load model health: {error}
    </div>
  )

  // Default values if backend returns empty object
  const fp   = health?.false_positive_rate    ?? 0
  const res  = health?.adversarial_resilience ?? 100
  const conf = health?.average_confidence     ?? 0
  const status = health?.health_status        ?? 'Healthy'

  const statusColor = status === 'Healthy'  ? '#12B76A'
                    : status === 'Degraded' ? '#F79009'
                    :                         '#F04438'

  return (
    <div style={{ padding:20 }}>
      <div style={{ fontWeight:600, fontSize:15, color:'#0D1117', marginBottom:16 }}>
        Model Health
      </div>

      {[
        { label:'False positive rate',    value: fp   + '%',  good: fp   < 10 },
        { label:'Adversarial resilience', value: res  + '%',  good: res  > 75 },
        { label:'Avg confidence',         value: conf + '%',  good: conf > 60 },
      ].map(m => (
        <div key={m.label} style={{
          padding:'12px 14px', marginBottom:8,
          background:'#F8F9FA', borderRadius:8,
        }}>
          <div style={{ fontSize:11, color:'#6B7280', marginBottom:4 }}>{m.label}</div>
          <div style={{
            fontSize:22, fontWeight:700,
            fontFamily:'monospace',
            color: m.good ? '#12B76A' : '#F04438',
          }}>
            {m.value}
          </div>
        </div>
      ))}

      <div style={{
        marginTop:8, padding:'10px 14px', borderRadius:8, fontSize:13, fontWeight:600,
        background: status === 'Healthy' ? '#F0FDF4' : '#FEF3F2',
        color: statusColor,
        border: `1px solid ${statusColor}33`,
      }}>
        Status: {status}
      </div>
    </div>
  )
}

export default function RedTeam() {
  const [inputType, setInputType] = useState('text')
  const [inputValue, setInputValue] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  // Button should be enabled whenever inputValue has content
  const canRun = inputValue.trim().length > 0 && !loading

  async function runAttack() {
    if (!canRun) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const base = import.meta.env.VITE_API_URL || 'http://localhost:8000'
      const res  = await fetch(`${base}/red-team/run`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          input_type:  inputType,
          input_value: inputValue.trim(),
          incident_id: '',
        }),
      })
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      setResult(data)
    } catch (err) {
      setError(err.message || 'Failed to connect to backend')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-enter" style={{ maxWidth: 1000, margin: '0 auto' }}>
      <div style={{ marginBottom: 40 }}>
        <SectionHeader number="04" title="Red Team Operations" subtitle="Stress-test the ensemble with automated adversarial mutations." />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 32, marginBottom: 40 }}>
        {/* Left: Input */}
        <div>
          <div className="card" style={{ padding: 24 }}>
            <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
              {['URL', 'Text'].map(t => (
                <button key={t} onClick={() => setInputType(t.toLowerCase())} style={{
                  padding: '6px 16px', background: inputType === t.toLowerCase() ? 'var(--bg-sunken)' : 'transparent',
                  border: 'none', borderRadius: 6, fontWeight: inputType === t.toLowerCase() ? 600 : 500,
                  color: inputType === t.toLowerCase() ? 'var(--text-primary)' : 'var(--text-muted)', cursor: 'pointer',
                  fontFamily: 'var(--font-body)', fontSize: 13,
                }}>{t}</button>
              ))}
            </div>

            <textarea
              rows={4} value={inputValue} onChange={e => setInputValue(e.target.value)}
              placeholder={`Paste baseline malicious ${inputType} here…`}
              style={{
                width: '100%', padding: '16px', border: '1px solid var(--border)', borderRadius: 8,
                background: 'var(--bg-sunken)', color: 'var(--text-primary)',
                fontFamily: inputType === 'url' ? 'var(--font-mono)' : 'var(--font-body)',
                fontSize: 14, resize: 'vertical', outline: 'none',
              }}
            />

            <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={runAttack}
                disabled={!canRun}
                style={{
                  background:   canRun ? '#0D1117' : '#E5E7EB',
                  color:        canRun ? '#fff'    : '#9CA3AF',
                  border:       'none',
                  borderRadius: 8,
                  padding:      '12px 24px',
                  fontSize:     14,
                  fontWeight:   600,
                  cursor:       canRun ? 'pointer' : 'not-allowed',
                  display:      'flex',
                  alignItems:   'center',
                  gap:          8,
                  transition:   'all 0.2s',
                }}
              >
                {loading ? 'Running attacks…' : 'Execute Attack Suite →'}
              </button>
            </div>

            {error && (
              <div style={{ marginTop:12, color:'#F04438', fontSize:13 }}>{error}</div>
            )}

            {result && (
              <div style={{ marginTop:24 }}>
                {/* Resilience score banner */}
                <div style={{
                  padding:'16px 20px', borderRadius:10, marginBottom:16,
                  background: result.resilience_score >= 75 ? '#F0FDF4'
                            : result.resilience_score >= 50 ? '#FFFAEB' : '#FEF3F2',
                  border: `1px solid ${result.resilience_score >= 75 ? '#86EFAC'
                          : result.resilience_score >= 50 ? '#FCD34D' : '#FCA5A5'}`,
                  display:'flex', justifyContent:'space-between', alignItems:'center',
                }}>
                  <div>
                    <div style={{ fontWeight:700, fontSize:15, color:'#0D1117' }}>
                      Resilience Score
                    </div>
                    <div style={{ fontSize:12, color:'#6B7280', marginTop:2 }}>
                      {result.attacks_caught}/{result.attacks_total} attacks still detected after mutation
                    </div>
                  </div>
                  <div style={{ textAlign:'right' }}>
                    <div style={{
                      fontSize:32, fontWeight:800, fontFamily:'monospace', color:'#0D1117',
                    }}>
                      {result.resilience_score}
                      <span style={{ fontSize:14, fontWeight:400 }}>/100</span>
                    </div>
                    <div style={{ fontSize:12, fontWeight:600,
                      color: result.resilience_score >= 75 ? '#12B76A'
                           : result.resilience_score >= 50 ? '#F79009' : '#F04438',
                    }}>
                      {result.verdict}
                    </div>
                  </div>
                </div>

                {/* Attack result cards */}
                {result.attack_results?.map((attack, i) => (
                  <div key={i} style={{
                    padding:'14px 16px', marginBottom:8, borderRadius:8,
                    background: attack.still_detected ? '#F0FDF4' : '#FEF3F2',
                    border: `1px solid ${attack.still_detected ? '#86EFAC' : '#FCA5A5'}`,
                    borderLeft: `4px solid ${attack.still_detected ? '#12B76A' : '#F04438'}`,
                  }}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
                      <div>
                        <div style={{ fontWeight:600, fontSize:13, color:'#0D1117',
                                      textTransform:'capitalize' }}>
                          {(i+1).toString().padStart(2,'0')} — {attack.attack_type?.replace(/_/g,' ')}
                        </div>
                        <div style={{ fontSize:12, color:'#6B7280', marginTop:3 }}>
                          {attack.description}
                        </div>
                      </div>
                      <div style={{ textAlign:'right', flexShrink:0, marginLeft:12 }}>
                        <div style={{ fontSize:13, fontWeight:700,
                          color: attack.still_detected ? '#12B76A' : '#F04438' }}>
                          {attack.verdict}
                        </div>
                        <div style={{ fontSize:11, color:'#9CA3AF', fontFamily:'monospace', marginTop:2 }}>
                          {attack.original_score?.toFixed(2)} → {attack.perturbed_score?.toFixed(2)}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Health context */}
        <div>
           <ModelHealthPanel />
        </div>
      </div>
    </div>
  )
}
