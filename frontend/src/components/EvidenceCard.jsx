import React, { useState } from 'react'

function EvidenceCard({ detector, data }) {
  const [open, setOpen] = useState(true)

  // Colour based on score
  const colour = data.score >= 0.8 ? '#F04438'
               : data.score >= 0.6 ? '#EF6820'
               : data.score >= 0.4 ? '#F79009'
               : '#12B76A'

  return (
    <div style={{ border:`2px solid ${colour}20`, borderLeft:`4px solid ${colour}`,
                  borderRadius:10, marginBottom:12, overflow:'hidden' }}>
      
      {/* Header */}
      <div onClick={() => setOpen(!open)} style={{
        padding:'14px 18px', cursor:'pointer', display:'flex',
        justifyContent:'space-between', alignItems:'center',
        background: data.score >= 0.5 ? `${colour}08` : '#FAFAFA'
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <span style={{
            fontFamily:'var(--font-mono)', fontSize:18, fontWeight:700, color: colour
          }}>
            {data.score_pct ?? Math.round(data.score * 100)}%
          </span>
          <div>
            <div style={{ fontWeight:600, fontSize:14, color:'#0D1117' }}>
              {detector === 'url'      ? 'URL Detector'
               : detector === 'nlp'   ? 'NLP / Phishing Detector'
               : detector === 'deepfake' ? 'Media Authenticity Engine'
               : detector === 'anomaly'  ? 'Behaviour Anomaly Engine'
               : detector}
            </div>
            <div style={{ fontSize:12, color:'#6B7280' }}>
              Method: {data.method} &nbsp;·&nbsp;
              {data.score >= 0.5 ? '⚠ Malicious signal detected' : '✓ No threat signal'}
            </div>
          </div>
        </div>
        
        {/* Mini score bar */}
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <div style={{ width:120, height:6, background:'#E5E7EB', borderRadius:3 }}>
            <div style={{
              width:`${(data.score_pct ?? Math.round(data.score*100))}%`,
              height:'100%', background: colour, borderRadius:3,
              transition:'width 0.8s ease-out'
            }}/>
          </div>
          <span style={{ fontSize:12 }}>{open ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Body */}
      {open && (
        <div style={{ padding:'16px 18px', borderTop:'1px solid #F0F0F0' }}>
          
          {/* Evidence notes — plain English explanation */}
          {data.evidence_notes?.length > 0 && (
            <div style={{ marginBottom:14 }}>
              <div style={{ fontSize:11, fontWeight:600, color:'#6B7280',
                            letterSpacing:'0.06em', marginBottom:8 }}>
                EVIDENCE
              </div>
              {data.evidence_notes.map((note, i) => (
                <div key={i} style={{
                  display:'flex', gap:8, marginBottom:6, fontSize:13, color:'#374151'
                }}>
                  <span style={{ color: colour, flexShrink:0 }}>→</span>
                  <span>{note}</span>
                </div>
              ))}
            </div>
          )}

          {/* URL: feature importance */}
          {detector === 'url' && data.feature_importance?.length > 0 && (
            <div style={{ marginBottom:14 }}>
              <div style={{ fontSize:11, fontWeight:600, color:'#6B7280',
                            letterSpacing:'0.06em', marginBottom:8 }}>
                TOP FEATURES (SHAP-STYLE IMPORTANCE)
              </div>
              {data.feature_importance.map((f, i) => (
                <div key={i} style={{
                  display:'flex', alignItems:'center', gap:10,
                  marginBottom:6, fontSize:12
                }}>
                  <span style={{ width:180, color:'#374151' }}>{f.feature}</span>
                  <div style={{ flex:1, height:5, background:'#E5E7EB', borderRadius:2 }}>
                    <div style={{
                      width:`${Math.min(f.value * 100, 100)}%`,
                      height:'100%',
                      background: f.impact === 'high' ? '#F04438' : '#F79009',
                      borderRadius:2
                    }}/>
                  </div>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:11,
                                 color:'#6B7280', width:40, textAlign:'right' }}>
                    {f.value.toFixed(2)}
                  </span>
                </div>
              ))}
              {data.registrable_domain && (
                <div style={{ marginTop:8, fontSize:12, color:'#6B7280' }}>
                  Real domain: <code style={{ fontFamily:'var(--font-mono)',
                    background:'#F1F3F5', padding:'2px 6px', borderRadius:4 }}>
                    {data.registrable_domain}
                  </code>
                </div>
              )}
            </div>
          )}

          {/* NLP: top tokens */}
          {detector === 'nlp' && data.top_tokens?.length > 0 && (
            <div style={{ marginBottom:14 }}>
              <div style={{ fontSize:11, fontWeight:600, color:'#6B7280',
                            letterSpacing:'0.06em', marginBottom:8 }}>
                TRIGGER TOKENS
              </div>
              <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
                {data.top_tokens.map((tok, i) => (
                  <span key={i} style={{
                    background:'#FEF3F2', border:'1px solid #FECDCA',
                    borderRadius:6, padding:'3px 10px',
                    fontSize:12, fontFamily:'var(--font-mono)', color:'#B42318'
                  }}>
                    {tok}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Deepfake: signals breakdown */}
          {detector === 'deepfake' && data.signals && (
            <div>
              <div style={{ fontSize:11, fontWeight:600, color:'#6B7280',
                            letterSpacing:'0.06em', marginBottom:8 }}>
                SIGNAL BREAKDOWN
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                {Object.entries(data.signals)
                  .filter(([, v]) => v !== null)
                  .map(([key, val]) => (
                  <div key={key} style={{
                    background:'#F8F9FA', borderRadius:8, padding:'10px 12px'
                  }}>
                    <div style={{ fontSize:11, color:'#6B7280', marginBottom:4 }}>
                      {key.replace(/_/g, ' ').toUpperCase()}
                    </div>
                    <div style={{ fontSize:16, fontWeight:700,
                                  fontFamily:'var(--font-mono)',
                                  color: val > 0.5 ? '#F04438' :
                                         val > 0.3 ? '#F79009' : '#12B76A' }}>
                      {Math.round(val * 100)}%
                    </div>
                    <div style={{ width:'100%', height:4, background:'#E5E7EB',
                                  borderRadius:2, marginTop:4 }}>
                      <div style={{
                        width:`${Math.round(val * 100)}%`, height:'100%',
                        background: val > 0.5 ? '#F04438' :
                                    val > 0.3 ? '#F79009' : '#12B76A',
                        borderRadius:2, transition:'width 0.8s ease-out'
                      }}/>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function EvidenceCardsWrapper({ evidence = {}, detectors_triggered = [] }) {
  if (!Object.keys(evidence).length) {
    return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No detector evidence available.</p>
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Object.entries(evidence).map(([det, data]) => (
        <EvidenceCard key={det} detector={det} data={data} />
      ))}
    </div>
  )
}
