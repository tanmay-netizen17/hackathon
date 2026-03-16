import axios from 'axios'

const CLOUD = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const LOCAL  = 'http://localhost:8001'

function getBase() {
  return localStorage.getItem('sentinel_mode') === 'local' ? LOCAL : CLOUD
}

// Main analyse call — routes to local or cloud automatically
export async function analyseInput(payload) {
  const mode = localStorage.getItem('sentinel_mode') || 'cloud'
  const inputType = payload.type
  const inputValue = payload.content

  if (mode === 'local') {
    const endpoint = inputType === 'url'
      ? '/local/analyse/url'
      : '/local/analyse/text'
    const reqPayload = inputType === 'url'
      ? { url: inputValue }
      : { text: inputValue }
    const res = await axios.post(`${LOCAL}${endpoint}`, reqPayload)
    // Local server returns simpler response — wrap it to match cloud format
    return normaliseLocalResponse(res.data, inputType, inputValue)
  } else {
    // Cloud expects the new schema: url, text, or log_data
    const reqPayload = {}
    if (inputType === 'url') reqPayload.url = inputValue
    else if (inputType === 'log') reqPayload.log_data = inputValue
    else reqPayload.text = inputValue

    const res = await axios.post(`${CLOUD}/analyse`, reqPayload)
    return res.data
  }
}

// Local server returns minimal response — expand it to match cloud schema
function normaliseLocalResponse(data, inputType, inputValue) {
  const score    = Math.round(data.score * 100)
  const severity = score <= 30 ? 'Clean'
                 : score <= 60 ? 'Suspicious'
                 : score <= 80 ? 'Likely Malicious'
                 :               'Critical'
  return {
    incident_id:          `INC-LOCAL-${Date.now()}`,
    sentinel_score:       score,
    severity,
    detectors_triggered:  [inputType === 'url' ? 'url' : 'nlp'],
    threat_brief:         `[Local Mode] ${severity} detected with ${score}% confidence. GPT-4o-mini explanations are disabled in air-gapped mode.`,
    evidence:             { [inputType === 'url' ? 'url' : 'nlp']: { score: data.score, mode: 'local' } },
    mitre_tactic:         score > 60 ? 'T1566' : null,
    mitre_label:          score > 60 ? 'Phishing' : null,
    recommended_action:   score > 80 ? 'Block and investigate immediately.'
                        : score > 60 ? 'Quarantine and review.'
                        : score > 30 ? 'Monitor closely.'
                        : 'No action required.',
    auto_detected:        false,
    ingestion_source:     'manual',
    mode:                 'local',
    data_left_device:     false,
    timestamp:            new Date().toISOString(),
  }
}

export async function getIncidents(params = {}) {
  const res = await axios.get(`${CLOUD}/incidents`, { params })
  return res.data
}

export async function submitFeedback(incidentId, verdict, score) {
  const res = await axios.post(`${CLOUD}/feedback/${incidentId}`, { verdict, score })
  return res.data
}

export async function runRedTeam(inputType, inputValue, incidentId) {
  const res = await axios.post(`${CLOUD}/red-team/run`, {
    input_type:  inputType,
    input_value: inputValue,
    incident_id: incidentId,
  })
  return res.data
}

export async function getModelHealth() {
  const res = await axios.get(`${CLOUD}/model-health`)
  return res.data
}

export const getHealth = () => axios.get(`${CLOUD}/health`).then(r => r.data)
export const getIncident = (id) => axios.get(`${CLOUD}/incidents/${id}`).then(r => r.data)
export const setMode = (local_mode) => axios.post(`${CLOUD}/settings/mode`, { local_mode }).then(r => r.data)
export const setThreshold = (threshold) => axios.post(`${CLOUD}/settings/threshold`, { threshold }).then(r => r.data)
export const startAgent = (agentName, config) => axios.post(`${CLOUD}/agents/start/${agentName}`, { config }).then(r => r.data)

export const ingestFile = (file) => {
  const fd = new FormData()
  fd.append('file', file)
  return axios.post(`${CLOUD}/ingest/file`, fd, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
}
