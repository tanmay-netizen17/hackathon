import React, { useState, useContext } from 'react'
import { ThemeContext } from '../App'
import { api } from '../api/spectraApi'
import { SectionHeader } from '../components/SectionHeader'
import { useMode } from '../context/ModeContext'
import { useAgentStatus } from '../hooks/useAgentStatus'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function FormRow({ label, sublabel, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '20px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 400 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>{label}</div>
        {sublabel && <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.5 }}>{sublabel}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

function OperationalModeSection() {
  const { mode, localServerOnline, checking, enableLocalMode, enableCloudMode } = useMode()
  const [error, setError] = useState(null)
  const isLocal = mode === 'local'

  async function handleToggle() {
    setError(null)
    if (isLocal) {
      enableCloudMode()
    } else {
      const result = await enableLocalMode()
      if (!result.success) setError(result.error)
    }
  }

  return (
    <div style={{
      background: '#fff', border: '1px solid var(--border)',
      borderRadius: 12, padding: 24, marginBottom: 40
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 16, color: 'var(--text-primary)' }}>
            Local / Air-gapped Mode
          </div>
          <div style={{
            fontSize: 14, color: 'var(--text-secondary)', marginTop: 4,
            maxWidth: 460, lineHeight: 1.5
          }}>
            All inference runs entirely on your local machine using ONNX quantised models.
            Zero data leaves your network. Disables GPT-4o-mini explanations.
          </div>

          {/* Local server status */}
          {isLocal && (
            <div style={{
              marginTop: 10, display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 12, color: localServerOnline ? '#12B76A' : '#F04438'
            }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%',
                background: localServerOnline ? '#12B76A' : '#F04438',
                display: 'inline-block'
              }} />
              {checking ? 'Checking local server…'
                : localServerOnline ? 'Local server running on localhost:8001'
                  : 'Local server offline — run: python local_server.py'}
            </div>
          )}
        </div>

        {/* Toggle switch */}
        <button
          onClick={handleToggle}
          style={{
            width: 52, height: 28, borderRadius: 14,
            background: isLocal ? '#12B76A' : '#E5E7EB',
            border: 'none', cursor: 'pointer', position: 'relative',
            transition: 'background 0.2s', flexShrink: 0
          }}
          aria-label="Toggle local mode"
        >
          <span style={{
            position: 'absolute',
            top: 3, left: isLocal ? 26 : 3,
            width: 22, height: 22, borderRadius: '50%',
            background: '#fff',
            boxShadow: '0 1px 4px rgba(0,0,0,0.2)',
            transition: 'left 0.2s',
            display: 'block'
          }} />
        </button>
      </div>

      {/* Error message */}
      {error && (
        <div style={{
          marginTop: 12, padding: '10px 14px',
          background: '#FEF3F2', border: '1px solid #FECDCA',
          borderRadius: 8, fontSize: 13, color: '#B42318'
        }}>
          {error}
          <div style={{ marginTop: 4, fontFamily: 'var(--font-mono)', fontSize: 12 }}>
            cd backend && python local_server.py
          </div>
        </div>
      )}

      {/* Instructions for local mode when offline */}
      {isLocal && !localServerOnline && !checking && (
        <div style={{
          marginTop: 12, padding: '12px 16px',
          background: '#FFFAEB', border: '1px solid #FEF0C7',
          borderRadius: 8, fontSize: 13, color: '#B54708'
        }}>
          <strong>To start local server:</strong>
          <pre style={{
            margin: '6px 0 0', fontFamily: 'var(--font-mono)', fontSize: 12,
            background: '#FEF9EE', padding: 8, borderRadius: 6
          }}>
            {`cd backend
pip install onnxruntime -q
python local_server.py`}
          </pre>
        </div>
      )}
    </div>
  )
}

function AgentCard({ name, description, status, actionLabel, onAction }) {
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState(false)

  async function handleAction() {
    setLoading(true)
    if (onAction) await onAction()
    else {
      // expand if no direct action
      setExpanded(true)
    }
    setLoading(false)
  }

  const dotColour = status === 'online' ? '#10B981' // Vibrant Emerald
    : status === 'offline' ? '#9CA3AF' // Neutral Grey
    : '#F59E0B'  // Vibrant Amber for starting

  return (
    <div style={{
      background: '#fff', border: '1px solid var(--border)',
      borderRadius: 10, overflow: 'hidden', marginBottom: 16
    }}>
      <div style={{
        padding: '16px 20px', display: 'flex',
        alignItems: 'center', justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{
            width: 9, height: 9, borderRadius: '50%',
            background: dotColour, display: 'inline-block',
            boxShadow: status === 'online'
              ? `0 0 0 3px ${dotColour}33` : 'none' }}/>
          <div>
            <div style={{ fontWeight:600, fontSize:15, color:'var(--text-primary)' }}>
              {name}
            </div>
            <div style={{ fontSize:12, color:'var(--text-muted)',
                          fontFamily:'var(--font-mono)', marginTop:2 }}>
              {description}
            </div>
          </div>
        </div>

        <div style={{ display:'flex', gap:8 }}>
          <button
            onClick={handleAction}
            disabled={loading}
            style={{
              border:'1px solid var(--border-strong)',
              background:'#fff', borderRadius:8,
              padding:'6px 16px', fontSize:13, fontWeight:500,
              cursor: loading ? 'not-allowed' : 'pointer',
              color:'var(--text-primary)',
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? 'Working…' : actionLabel}
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{ border:'1px solid var(--border)', background:'#fff',
                     borderRadius:8, padding:'6px 10px',
                     cursor:'pointer', fontSize:13, color:'var(--text-muted)' }}
          >
            {expanded ? '▲' : '▼'}
          </button>
        </div>
      </div>

      {/* Expanded config panel */}
      {expanded && (
        <AgentConfigPanel name={name} />
      )}
    </div>
  )
}

function AgentConfigPanel({ name }) {
  if (name === 'Browser Extension') {
    return (
      <div style={{ padding:'0 20px 20px', borderTop:'1px solid var(--border)',
                    paddingTop:16, fontSize:13, color:'var(--text-secondary)' }}>
        <strong style={{ display:'block', marginBottom:8, color:'var(--text-primary)' }}>
          Installation steps
        </strong>
        <ol style={{ margin:0, paddingLeft:20, lineHeight:2 }}>
          <li>Open Chrome → <code style={{ fontFamily:'var(--font-mono)', fontSize:12,
              background:'var(--bg-sunken)', padding:'1px 6px', borderRadius:4 }}>
              chrome://extensions/</code></li>
          <li>Enable <strong>Developer Mode</strong> (top right toggle)</li>
          <li>Click <strong>Load unpacked</strong> → select <code style={{ fontFamily:'var(--font-mono)',
              fontSize:12, background:'var(--bg-sunken)', padding:'1px 6px', borderRadius:4 }}>
              browser-extension/</code> folder</li>
          <li>SentinelAI Shield icon will appear in your toolbar</li>
        </ol>
        <div style={{ marginTop:12, padding:'8px 12px', background:'var(--bg-sunken)',
                      borderRadius:8, fontFamily:'var(--font-mono)', fontSize:12 }}>
          Relay URL: {import.meta.env.VITE_API_URL || 'http://localhost:8000'}/ingest/url
        </div>
      </div>
    )
  }

  if (name === 'Email Daemon') {
    return <EmailDaemonConfig />
  }

  if (name === 'Log Collector') {
    return <LogCollectorConfig />
  }
  return null
}

function TrustedDomainsEditor() {
  const [domains, setDomains] = useState([])
  const [newDomain, setNewDomain] = useState('')
  const [loading, setLoading] = useState(false)
  
  // Load initially
  React.useEffect(() => {
    fetch(`${API}/settings/trusted-domains`)
      .then(r => r.json())
      .then(data => {
        const d = data.domains || []
        // Merge with local storage if desired, but let's trust server state
        setDomains(d)
        localStorage.setItem('sentinel_trusted_domains', JSON.stringify(d))
      })
      .catch(console.error)
  }, [])

  async function saveToServer(list) {
    setLoading(true)
    try {
      await fetch(`${API}/settings/trusted-domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: list })
      })
      localStorage.setItem('sentinel_trusted_domains', JSON.stringify(list))
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  function add() {
    const d = newDomain.trim().toLowerCase()
    if (!d || domains.includes(d)) return
    const list = [...domains, d]
    setDomains(list)
    setNewDomain('')
    saveToServer(list)
  }

  function remove(d) {
    const list = domains.filter(x => x !== d)
    setDomains(list)
    saveToServer(list)
  }

  return (
    <div style={{ marginTop: 24 }}>
      <label style={{ fontSize:14, fontWeight:600, color:'var(--text-primary)', display:'block', marginBottom:8 }}>
        Trusted Senders (Whitelist)
      </label>
      <div style={{ fontSize:12, color:'var(--text-secondary)', marginBottom:12, lineHeight:1.4 }}>
        Emails from these domains will be completely skipped by the Daemon to prevent false positives.
      </div>

      <div style={{ display:'flex', gap:8, marginBottom:16 }}>
        <input 
          placeholder="e.g. google.com"
          value={newDomain} onChange={e => setNewDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && add()}
          style={{
            flex: 1, padding:'8px 12px', fontSize:13,
            border:'1px solid var(--border)', borderRadius:8,
            background:'var(--bg-sunken)', fontFamily:'var(--font-mono)',
            color:'var(--text-primary)', outline:'none',
          }}
        />
        <button onClick={add} disabled={!newDomain.trim() || loading} style={{
          background: 'var(--text-primary)', color: '#fff',
          border: 'none', borderRadius: 8, padding: '0 16px', fontSize: 13,
          fontWeight: 500, cursor: newDomain.trim() ? 'pointer' : 'not-allowed',
          opacity: newDomain.trim() && !loading ? 1 : 0.5
        }}>
          Add
        </button>
      </div>

      {domains.length > 0 && (
        <div style={{ display:'flex', flexWrap:'wrap', gap:8 }}>
          {domains.map(d => (
            <div key={d} style={{
              display:'flex', alignItems:'center', gap:6,
              background:'var(--bg-sunken)', border:'1px solid var(--border)',
              padding:'4px 10px', borderRadius:16, fontSize:12, fontFamily:'var(--font-mono)',
              color:'var(--text-secondary)'
            }}>
              {d}
              <button onClick={() => remove(d)} style={{
                background:'none', border:'none', padding:0, margin:0,
                color:'var(--text-muted)', cursor:'pointer', fontSize:14, lineHeight:1
              }} title="Remove">×</button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function EmailDaemonConfig() {
  const [host,  setHost]  = useState('imap.gmail.com')
  const [user,  setUser]  = useState('')
  const [pass,  setPass]  = useState('')
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function save() {
    setLoading(true)
    setError(null)
    try {
      await api.startAgent('email_daemon', { host, user, password: pass })
      localStorage.setItem('email_daemon_config', JSON.stringify({ host, user }))
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setError('Failed to start daemon')
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    width:'100%', padding:'8px 12px', fontSize:13,
    border:'1px solid var(--border)', borderRadius:8,
    background:'var(--bg-sunken)', fontFamily:'var(--font-body)',
    color:'var(--text-primary)', boxSizing:'border-box',
    outline:'none',
  }

  return (
    <div style={{ padding:'0 20px 20px', borderTop:'1px solid var(--border)', paddingTop:16 }}>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:12 }}>
        <div>
          <label style={{ fontSize:12, fontWeight:500, color:'var(--text-secondary)',
                          display:'block', marginBottom:4 }}>IMAP Host</label>
          <input style={inputStyle} value={host} onChange={e => setHost(e.target.value)}
            placeholder="imap.gmail.com" />
        </div>
        <div>
          <label style={{ fontSize:12, fontWeight:500, color:'var(--text-secondary)',
                          display:'block', marginBottom:4 }}>Email Address</label>
          <input style={inputStyle} value={user} onChange={e => setUser(e.target.value)}
            placeholder="you@gmail.com" />
        </div>
      </div>
      <div style={{ marginBottom:12 }}>
        <label style={{ fontSize:12, fontWeight:500, color:'var(--text-secondary)',
                        display:'block', marginBottom:4 }}>App Password</label>
        <input type="password" style={inputStyle} value={pass}
          onChange={e => setPass(e.target.value)}
          placeholder="Gmail app password (not your main password)" />
        <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:4 }}>
          Generate at myaccount.google.com → Security → App passwords
        </div>
      </div>
      {error && <div style={{ marginBottom:12, fontSize:12, color:'#B42318' }}>{error}</div>}
      <button onClick={save} disabled={loading} style={{
        background: saved ? '#ECFDF5' : 'var(--text-primary)',
        color: saved ? '#12B76A' : '#fff',
        border: saved ? '1px solid #86EFAC' : 'none',
        borderRadius:8, padding:'8px 18px', fontSize:13,
        fontWeight:500, cursor: loading ? 'not-allowed' : 'pointer',
        opacity: loading ? 0.7 : 1
      }}>
        {loading ? 'Starting…' : saved ? 'Started ✓' : 'Save & start daemon'}
      </button>

      <TrustedDomainsEditor />
    </div>
  )
}

function LogCollectorConfig() {
  const [logType, setLogType] = useState('auth')
  const [saved,   setSaved]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleStart() {
    setLoading(true)
    setError(null)
    try {
      await api.startAgent('log_collector', { type: logType })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError('Failed to start collector')
    } finally {
      setLoading(false)
    }
  }

  const LOG_TYPES = [
    { value:'auth',    label:'auth.log (Linux)',             path:'/var/log/auth.log'     },
    { value:'syslog',  label:'syslog (Linux)',               path:'/var/log/syslog'       },
    { value:'winevent',label:'Windows Event Log',            path:'Event Viewer'          },
    { value:'custom',  label:'Custom path',                  path:''                      },
  ]

  return (
    <div style={{ padding:'0 20px 20px', borderTop:'1px solid var(--border)', paddingTop:16 }}>
      <label style={{ fontSize:12, fontWeight:500, color:'var(--text-secondary)',
                      display:'block', marginBottom:8 }}>Log source</label>
      <div style={{ display:'flex', flexDirection:'column', gap:8, marginBottom:16 }}>
        {LOG_TYPES.map(lt => (
          <label key={lt.value} style={{ display:'flex', alignItems:'center', gap:10,
                                         fontSize:13, cursor:'pointer' }}>
            <input type="radio" name="logtype" value={lt.value}
              checked={logType === lt.value}
              onChange={() => setLogType(lt.value)} />
            <span style={{ color:'var(--text-primary)', fontWeight:500 }}>{lt.label}</span>
            {lt.path && (
              <code style={{ fontSize:11, color:'var(--text-muted)',
                             fontFamily:'var(--font-mono)',
                             background:'var(--bg-sunken)',
                             padding:'1px 6px', borderRadius:4 }}>
                {lt.path}
              </code>
            )}
          </label>
        ))}
      </div>
      <div style={{ padding:'10px 14px', background:'#FFFAEB',
                    border:'1px solid #FEF0C7', borderRadius:8,
                    fontSize:12, color:'#B54708', marginBottom:12 }}>
        <strong>Start the log collector agent:</strong>
        <pre style={{ margin:'6px 0 0', fontFamily:'var(--font-mono)',
                      background:'#FEF9EE', padding:8, borderRadius:6 }}>
{`cd backend\npython agents/log_collector.py --type ${logType}`}
        </pre>
      </div>
      {error && <div style={{ marginBottom:12, fontSize:12, color:'#B42318' }}>{error}</div>}
      <button onClick={handleStart} disabled={loading} style={{
        background: saved ? '#ECFDF5' : 'var(--text-primary)',
        color: saved ? '#12B76A' : '#fff',
        border: saved ? '1px solid #86EFAC' : 'none',
        borderRadius:8, padding:'8px 18px', fontSize:13,
        fontWeight:500, cursor: loading ? 'not-allowed' : 'pointer',
        opacity: loading ? 0.7 : 1
      }}>
        {loading ? 'Starting…' : saved ? 'Started ✓' : 'Start collector'}
      </button>
    </div>
  )
}

export default function Settings() {
  const [apiKeys, setApiKeys] = useState({ openai: '', virustotal: '', emailPassword: '' })
  const agentStatus = useAgentStatus()

  const inputStyle = {
    padding: '10px 14px', border: '1px solid var(--border-strong)', borderRadius: 8,
    fontSize: 14, fontFamily: 'var(--font-mono)', width: 320, outline: 'none',
    background: 'var(--bg-sunken)', color: 'var(--text-primary)',
    transition: 'all 0.2s',
  }

  return (
    <div className="page-enter" style={{ maxWidth: 860, margin: '0 auto' }}>
      <div style={{ marginBottom: 40 }}>
        <SectionHeader number="05" title="Platform Settings" subtitle="Configure integration agents, API credentials, and network modes." />
      </div>

      {/* Mode Settings */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>1. Operational Mode</h3>
      <OperationalModeSection />

      {/* Integrations */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>2. Passive Integrations</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24, marginBottom: 40 }}>
        <div>
          <AgentCard 
            name="Browser Extension" 
            description="Chrome MV3 • v1.0.4" 
            status={agentStatus.browser_extension || 'offline'} 
            actionLabel="Configure" 
          />
          <AgentCard 
            name="Email Daemon" 
            description="IMAP IDLE stream" 
            status={agentStatus.email_daemon || 'offline'} 
            actionLabel="Start" 
          />
          <AgentCard 
            name="Log Collector" 
            description="syslog forwarder" 
            status={agentStatus.log_collector || 'offline'} 
            actionLabel="Setup" 
          />
        </div>

        <div className="card" style={{ padding: 24, background: 'var(--bg-primary)', height: 'fit-content' }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, margin: '0 0 16px 0', color: 'var(--text-primary)' }}>Security Posture</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              "WebSocket WSS encrypted",
              "Role-based API limits active",
              "Input payload sanitisation ON",
              "Audit logging enabled",
              "OWASP headers enforced",
            ].map((text, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--clean)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                {text}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* API Keys */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>3. External Providers</h3>
      <div className="card" style={{ padding: '0 24px', marginBottom: 60 }}>
        <FormRow label="OpenAI API Key" sublabel="Required for GPT-4o-mini Threat Breifs (if Local Mode is off).">
          <input type="password" placeholder="sk-proj-..." value={apiKeys.openai} onChange={e => setApiKeys(p => ({ ...p, openai: e.target.value }))} style={inputStyle} />
        </FormRow>
        <FormRow label="VirusTotal API Key" sublabel="Used by URL Detector to enrich domain intelligence and previous block markers.">
          <input type="password" placeholder="vt-key-..." value={apiKeys.virustotal} onChange={e => setApiKeys(p => ({ ...p, virustotal: e.target.value }))} style={inputStyle} />
        </FormRow>
        <div style={{ borderBottom: 'none' }}>
        <FormRow label="Email App Password" sublabel="For the Email Daemon to tail the IMAP IDLE connection securely.">
          <input type="password" placeholder="16-char app password" value={apiKeys.emailPassword} onChange={e => setApiKeys(p => ({ ...p, emailPassword: e.target.value }))} style={inputStyle} />
        </FormRow>
        </div>
      </div>
    </div>
  )
}
