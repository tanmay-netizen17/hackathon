const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS   = import.meta.env.VITE_WS_URL  || 'ws://localhost:8000'

async function call(endpoint, options = {}) {
  const url = `${BASE}${endpoint}`
  try {
    const { headers, ...rest } = options
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...headers },
      ...rest,
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`Server ${res.status}: ${text.slice(0, 200)}`)
    }
    return await res.json()
  } catch (err) {
    if (err.message === 'Failed to fetch') {
      throw new Error(`Cannot reach SpectraGuard backend at ${BASE}. Is it running?`)
    }
    throw err
  }
}

export const api = {
  // Analysis
  analyse:      (input, type)        => call('/analyse',       { method:'POST', body: JSON.stringify({ input, type }) }),
  analyseFile:  (formData)           => fetch(`${BASE}/analyse/file`, { method:'POST', body: formData }).then(r => r.json()),
  analyseUrl:   (url)                => call('/analyse',       { method:'POST', body: JSON.stringify({ input: url,   type: 'url'  }) }),
  analyseText:  (text)               => call('/analyse',       { method:'POST', body: JSON.stringify({ input: text,  type: 'text' }) }),
  analyseLog:   (text)               => call('/analyse',       { method:'POST', body: JSON.stringify({ input: text,  type: 'log'  }) }),

  // Incidents
  getIncidents: (params = {})        => call('/incidents?' + new URLSearchParams(params)),
  getIncident:  (id)                 => call(`/incidents/${id}`),
  feedback:     (id, verdict, score) => call(`/feedback/${id}`, { method:'POST', body: JSON.stringify({ verdict, score }) }),

  // Red Team
  redTeam:      (type, value)        => call('/red-team/run',  { method:'POST', body: JSON.stringify({ input_type: type, input_value: value }) }),
  modelHealth:  ()                   => call('/model-health'),

  // Agents
  agentStatus:  ()                   => call('/agents/status'),
  startAgent:   (name, config)       => call(`/agents/start/${name}`, { method:'POST', body: JSON.stringify(config) }),

  // Settings
  blocklist:      (payload)          => call('/blocklist/add', { method:'POST', body: JSON.stringify(payload) }),
  trustedDomains: (domains)          => call('/settings/trusted-domains', { method:'POST', body: JSON.stringify({ domains }) }),
  setThreshold:   (threshold)        => call('/settings/threshold', { method:'POST', body: JSON.stringify({ threshold }) }),

  // Health
  health:       ()                   => call('/health'),

  // WebSocket URL
  wsUrl: () => `${WS}/ws/live`,
}
