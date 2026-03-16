import React, { useState, useContext } from 'react'
import { ThemeContext } from '../App'
import { setMode } from '../api/sentinelApi'

function SettingRow({ label, sublabel, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 0', borderBottom: '1px solid #F3F4F6' }}>
      <div>
        <div style={{ fontSize: 14, fontWeight: 500, color: '#0F172A' }}>{label}</div>
        {sublabel && <div style={{ fontSize: 12, color: '#9CA3AF', marginTop: 2 }}>{sublabel}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

export default function Settings() {
  const { localMode, setLocalMode } = useContext(ThemeContext)
  const [apiKeys, setApiKeys] = useState({ openai: '', virustotal: '', emailPassword: '' })

  const inputStyle = {
    padding: '8px 12px', border: '1px solid #E5E7EB', borderRadius: 6,
    fontSize: 13, fontFamily: 'IBM Plex Mono', width: 280, outline: 'none',
    background: '#FAFAFA', color: '#0F172A',
  }

  return (
    <div>
      <h1 style={{ fontFamily: 'DM Sans', fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Settings</h1>
      <p style={{ color: '#6B7280', fontSize: 14, marginBottom: 24 }}>Configure agents, API keys, and integration.</p>

      {/* Local / Air-gapped Mode */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <p style={{ fontSize: 15, fontWeight: 600, color: '#0F172A', margin: 0 }}>Local / Air-gapped Mode</p>
            <p style={{ fontSize: 13, color: '#6B7280', marginTop: 4, marginBottom: 0 }}>
              All inference runs on your machine via ONNX models. Zero data leaves your network.
            </p>
          </div>
          <button
            onClick={async () => {
              const newMode = !localMode;
              try {
                await setMode(newMode);
                setLocalMode(newMode);
              } catch (e) {
                console.error("Failed to set local mode", e);
              }
            }}
            style={{
              width: 48, height: 24, borderRadius: 12, border: 'none', cursor: 'pointer',
              background: localMode ? '#6366F1' : '#E5E7EB',
              position: 'relative', transition: 'background-color 0.2s', padding: 0
            }}
          >
            <span style={{
              display: 'block', width: 20, height: 20, background: '#fff', borderRadius: '50%',
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
              position: 'absolute', top: 2, left: localMode ? 26 : 2,
              transition: 'left 0.2s'
            }} />
          </button>
        </div>
      </div>

      {/* API Keys */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 2 }}>API Keys</h3>
        <p style={{ color: '#9CA3AF', fontSize: 12, marginBottom: 12 }}>Keys are stored in your .env file, never in the browser.</p>
        <SettingRow label="OpenAI API Key" sublabel="Required for GPT-4o-mini XAI briefs">
          <input
            type="password" placeholder="sk-…"
            value={apiKeys.openai}
            onChange={e => setApiKeys(p => ({ ...p, openai: e.target.value }))}
            style={inputStyle}
          />
        </SettingRow>
        <SettingRow label="VirusTotal API Key" sublabel="Optional — URL enrichment">
          <input
            type="password" placeholder="vt-key-…"
            value={apiKeys.virustotal}
            onChange={e => setApiKeys(p => ({ ...p, virustotal: e.target.value }))}
            style={inputStyle}
          />
        </SettingRow>
        <SettingRow label="Email App Password" sublabel="Gmail/Outlook for email daemon">
          <input
            type="password" placeholder="App password"
            value={apiKeys.emailPassword}
            onChange={e => setApiKeys(p => ({ ...p, emailPassword: e.target.value }))}
            style={inputStyle}
          />
        </SettingRow>
      </div>

      {/* Browser extension */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>Chrome Extension — SentinelAI Shield</h3>
        <div style={{ background: '#F8FAFC', borderRadius: 8, padding: 14, fontSize: 13, color: '#374151', lineHeight: 1.7 }}>
          <strong>Installation:</strong><br />
          1. Open Chrome → <code>chrome://extensions</code><br />
          2. Enable <em>Developer Mode</em> (top right)<br />
          3. Click <em>Load Unpacked</em> → select <code>sentinelai/browser-extension/</code><br />
          4. The SentinelAI Shield icon will appear in your toolbar.<br />
          <br />
          <strong>What it does:</strong> Intercepts every navigation, checks the URL against SentinelAI,
          and displays a warning overlay for any score ≥ 61 (Likely Malicious or Critical).
        </div>
      </div>

      {/* Desktop agent */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>Desktop Agent</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
          {['Windows', 'macOS', 'Linux'].map(os => (
            <button key={os} style={{
              padding: '12px', border: '1px solid #E5E7EB', borderRadius: 8,
              background: '#FAFAFA', cursor: 'pointer', textAlign: 'center',
              transition: 'border-color 0.15s',
            }}
              onMouseOver={e => e.target.style.borderColor = '#6366F1'}
              onMouseOut={e => e.target.style.borderColor = '#E5E7EB'}
            >
              <div style={{ fontSize: 22 }}>{os === 'Windows' ? '🪟' : os === 'macOS' ? '🍎' : '🐧'}</div>
              <div style={{ fontSize: 13, fontWeight: 500, marginTop: 4 }}>{os}</div>
              <div style={{ fontSize: 11, color: '#9CA3AF' }}>Download Agent</div>
            </button>
          ))}
        </div>
        <p style={{ fontSize: 12, color: '#9CA3AF', marginTop: 10 }}>
          The desktop agent runs <code>python agents/log_collector.py</code> in the background,
          monitoring auth logs and forwarding alerts to this dashboard in real time.
        </p>
      </div>

      {/* Email daemon */}
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>Email Daemon</h3>
        <p style={{ fontSize: 13, color: '#374151', marginBottom: 10 }}>
          Run the email daemon to monitor your inbox passively (IMAP IDLE):
        </p>
        <div style={{
          background: '#0F172A', color: '#A5F3FC', padding: 14, borderRadius: 8,
          fontFamily: 'IBM Plex Mono', fontSize: 12, lineHeight: 1.8,
        }}>
          EMAIL_USER=you@gmail.com \<br />
          EMAIL_APP_PASSWORD=yourapppassword \<br />
          python backend/agents/email_daemon.py
        </div>
      </div>
    </div>
  )
}
