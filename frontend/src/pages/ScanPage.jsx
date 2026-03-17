import React, { useState, useRef, useContext } from 'react'
import { ThemeContext } from '../App'
import { api } from '../api/spectraApi'
import SentinelGauge from '../components/SentinelGauge'
import EvidenceCard from '../components/EvidenceCard'
import ThreatBrief from '../components/ThreatBrief'
import ActionPanel from '../components/ActionPanel'
import { SectionHeader } from '../components/SectionHeader'

const TABS = ['URL', 'Text / Email', 'File Upload', 'Log Paste']

export default function ScanPage() {
  const { addIncident } = useContext(ThemeContext)
  const [tab, setTab] = useState(0)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const fileRef = useRef(null)

  const handleAnalyse = async () => {
    if (tab !== 2 && !input.trim()) return
    setError(''); setResult(null); setLoading(true)
    try {
      if (tab === 2) {
        if (!selectedFile && !fileRef.current?.files[0]) { setLoading(false); return }
        const formData = new FormData()
        formData.append('file', selectedFile || fileRef.current.files[0])
        formData.append('source', 'manual')
        const data = await api.analyseFile(formData)
        if (data.error) throw new Error(data.error)
        setResult(data)
        if (data.incident_id) addIncident(data)
      } else {
        const type_map = ['url', 'text', 'file', 'log']
        const data = await api.analyse(input.trim(), type_map[tab])
        if (data.error) throw new Error(data.error)
        setResult(data)
        if (data.incident_id) addIncident(data)
      }
    } catch (e) {
      setError(e.message || 'Analysis failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-enter" style={{ maxWidth: 1000, margin: '0 auto' }}>
      <div style={{ marginBottom: 40 }}>
        <SectionHeader number="02" title="Manual Analysis" subtitle="Submit isolated artifacts for full ensemble processing." />
      </div>

      {/* Input panel */}
      <div className="card" style={{ padding: '0 0 20px', marginBottom: 40, overflow: 'hidden' }}>
        {/* Tabs */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
          {TABS.map((t, i) => {
            const active = tab === i
            return (
              <button key={t} onClick={() => { setTab(i); setInput(''); setResult(null); setError('') }} style={{
                flex: 1, padding: '16px', border: 'none', cursor: 'pointer',
                background: active ? 'var(--bg-primary)' : 'transparent',
                borderBottom: active ? '2px solid var(--text-primary)' : '2px solid transparent',
                color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                fontSize: 14, fontFamily: 'var(--font-body)', fontWeight: active ? 600 : 500,
                transition: 'all 0.15s',
              }}>{t}</button>
            )
          })}
        </div>

        {/* Input area */}
        <div style={{ padding: '24px 32px' }}>
          {tab === 2 ? (
            <div style={{
              border: '2px dashed var(--border-strong)', borderRadius: 12, padding: '48px 32px',
              textAlign: 'center', color: 'var(--text-secondary)', cursor: 'pointer',
              background: selectedFile ? 'rgba(16, 185, 129, 0.05)' : 'var(--bg-sunken)', transition: 'border 0.2s',
              borderColor: selectedFile ? 'var(--emerald)' : 'var(--border-strong)',
            }} 
            onMouseOver={e => e.currentTarget.style.borderColor = 'var(--accent)'}
            onMouseOut={e => e.currentTarget.style.borderColor = selectedFile ? 'var(--emerald)' : 'var(--border-strong)'}
            onClick={() => fileRef.current?.click()}>
              <input ref={fileRef} type="file" style={{ display: 'none' }} accept=".jpg,.jpeg,.png,.mp4,.avi,.mov,.txt,.log,.webp" 
                onChange={(e) => {
                  const file = e.target.files[0]
                  if (file) {
                    setSelectedFile(file)
                    setResult(null)
                    setError('')
                  }
                }}
              />
              {selectedFile ? (
                <div>
                  <div style={{ fontSize: 32, marginBottom: 12 }}>📄</div>
                  <div style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-primary)' }}>{selectedFile.name}</div>
                  <div style={{ fontSize: 13, marginTop: 4, fontFamily: 'var(--font-mono)' }}>{(selectedFile.size / 1024).toFixed(1)} KB · Click to change</div>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 32, marginBottom: 12 }}>📁</div>
                  <div style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-primary)' }}>Select file to upload</div>
                  <div style={{ fontSize: 13, marginTop: 4, fontFamily: 'var(--font-mono)' }}>JPG, PNG, MP4, AVI, TXT, LOG</div>
                </div>
              )}
            </div>
          ) : (
            <textarea
              rows={tab === 0 ? 2 : 8}
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={
                tab === 0 ? 'https://suspicious-site.xyz/login?verify=account' :
                tab === 1 ? 'Paste suspicious email, SMS, or Slack message here…' :
                'Paste raw syslog or application log lines here…'
              }
              style={{
                width: '100%', padding: '16px 20px', border: '1px solid var(--border)',
                borderRadius: 8, resize: 'vertical', fontSize: 15,
                fontFamily: tab === 0 ? 'var(--font-mono)' : 'var(--font-body)',
                lineHeight: 1.6, outline: 'none', background: 'var(--bg-sunken)', color: 'var(--text-primary)',
                transition: 'border 0.2s, box-shadow 0.2s',
              }}
            />
          )}

          <div style={{ marginTop: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: 13, color: 'var(--critical)', fontWeight: 500 }}>{error}</div>
            
            <button className="btn-primary" onClick={handleAnalyse} disabled={loading || (tab !== 2 && !input.trim())}>
              {loading ? (
                <>
                  <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ animation: 'spin 1s linear infinite' }}><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>
                  Analysing…
                </>
              ) : (
                <>
                  <span>Run Analysis</span>
                  <svg className="btn-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {result && (
        <div style={{ animation: 'pageIn 0.4s cubic-bezier(0.16, 1, 0.3, 1)' }}>
          <div style={{ borderTop: '1px solid var(--border)', margin: '40px 0', position: 'relative' }}>
            <span style={{ position: 'absolute', top: -12, left: '50%', transform: 'translateX(-50%)', background: 'var(--bg-primary)', padding: '0 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>ANALYSIS COMPLETE</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 32, marginBottom: 32 }}>
            <div className="card" style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.04em', fontWeight: 600, marginBottom: 24 }}>SENTINEL SCORE</div>
              <SentinelGauge score={result.sentinel_score} severity={result.severity} />
            </div>
            <ThreatBrief incident={result} />
          </div>

          <div style={{ marginBottom: 32 }}>
            <ActionPanel 
              recommended_action={result.recommended_action} 
              severity={result.severity} 
              result={result}
            />
          </div>

          {result.evidence && Object.keys(result.evidence).length > 0 && (
             <div style={{ marginBottom: 60 }}>
                <SectionHeader number="04" title="Detector Evidence" subtitle="Telemetry from the internal ensemble" />
                <EvidenceCard evidence={result.evidence} detectors_triggered={result.detectors_triggered} />
             </div>
          )}
        </div>
      )}
    </div>
  )
}
