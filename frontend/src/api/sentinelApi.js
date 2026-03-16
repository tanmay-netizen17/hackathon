import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || '/api'

const api = axios.create({ baseURL: BASE, timeout: 30000 })

export const analyseInput = (payload) => api.post('/analyse', payload).then(r => r.data)
export const getIncidents = (page = 1, severity) =>
  api.get('/incidents', { params: { page, limit: 20, severity } }).then(r => r.data)
export const getIncident  = (id) => api.get(`/incidents/${id}`).then(r => r.data)
export const submitFeedback = (id, verdict, notes) =>
  api.post(`/feedback/${id}?verdict=${verdict}&note=${notes}`).then(r => r.data)
export const getHealth = () => api.get('/health').then(r => r.data)
export const getModelHealth = () => api.get('/model-health').then(r => r.data)
export const setMode = (local_mode) => api.post('/settings/mode', { local_mode }).then(r => r.data)
export const setThreshold = (threshold) => api.post('/settings/threshold', { threshold }).then(r => r.data)
export const ingestFile = (file) => {
  const fd = new FormData()
  fd.append('file', file)
  return api.post('/ingest/file', fd, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
}

export const createWebSocket = (onMessage, onClose) => {
  // In dev mode: use relative path so it routes through the Vite proxy (127.0.0.1).
  // In production: use VITE_WS_URL env variable.
  const envWs = import.meta.env.VITE_WS_URL
  let wsUrl
  if (envWs) {
    wsUrl = `${envWs.replace(/\/+$/, '')}/ws/live`
  } else {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    wsUrl = `${proto}//${window.location.host}/ws/live`
  }
  const ws = new WebSocket(wsUrl)
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onclose   = () => onClose && onClose()
  ws.onerror   = () => ws.close()
  return ws
}
