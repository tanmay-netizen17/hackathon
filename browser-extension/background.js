// SpectraGuard Shield — background.js v4
// KEY FIX: Use onBeforeNavigate (fires BEFORE Chrome's Safe Browsing intercepts)
// so we always get the real URL even when Chrome blocks the page.

const BACKEND      = 'http://localhost:8000'
const DASHBOARD    = 'http://localhost:5173'
const WARN_SCORE   = 65
const NOTIFY_SCORE = 50
const COOLDOWN_MS  = 20000

const checkedUrls  = new Map()   // url → { score, ts }
const pendingUrls  = new Map()   // tabId → url (for overlay re-attempt)

// ─── Trusted domains — NEVER scan ────────────────────────────────────────────
const TRUSTED = new Set([
  'google.com','mail.google.com','accounts.google.com','drive.google.com',
  'docs.google.com','calendar.google.com','meet.google.com','maps.google.com',
  'youtube.com','googleapis.com','gstatic.com',
  'microsoft.com','outlook.com','outlook.live.com','office.com',
  'live.com','bing.com','linkedin.com','teams.microsoft.com',
  'apple.com','icloud.com',
  'amazon.com','amazon.in','amazon.co.uk','aws.amazon.com',
  'facebook.com','instagram.com','twitter.com','x.com','reddit.com',
  'github.com','gitlab.com','stackoverflow.com',
  'netflix.com','spotify.com','twitch.tv',
  'paypal.com','stripe.com',
  'wikipedia.org','wikimedia.org',
  'gnims.com',
])

function isTrusted(url) {
  try {
    const host = new URL(url).hostname.toLowerCase().replace(/^www\./, '')
    if (TRUSTED.has(host)) return true
    for (const t of TRUSTED) {
      if (host.endsWith('.' + t)) return true
    }
    const tld = host.split('.').pop()
    if (['edu','gov','mil','ac'].includes(tld)) return true
    return false
  } catch { return false }
}

// ─── CORE ANALYSIS ───────────────────────────────────────────────────────────
async function analyseUrl(url, tabId) {
  const now    = Date.now()
  const cached = checkedUrls.get(url)

  if (cached && now - cached.ts < COOLDOWN_MS) {
    // Already analysed — re-show badge and maybe overlay
    setBadge(tabId, cached.score)
    if (cached.score >= WARN_SCORE) {
      setTimeout(() => injectOverlay(tabId, cached.score, cached.severity, new URL(url).hostname, cached.brief), 1200)
    }
    return
  }

  try {
    const res = await fetch(`${BACKEND}/analyse`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ input: url, type: 'url' }),
    })
    if (!res.ok) return
    const data = await res.json()

    const score    = data.sentinel_score || 0
    const severity = data.severity       || 'Clean'
    const brief    = (data.threat_brief  || '').slice(0, 200)
    const host     = new URL(url).hostname

    checkedUrls.set(url, { score, severity, brief, ts: now })
    saveRecent({ url, score, severity, ts: now })
    setBadge(tabId, score)

    if (score < NOTIFY_SCORE) return  // Clean — silent

    // ── Chrome OS notification (works even on chrome:// pages) ────────────
    showNotification(score, severity, host, brief, tabId, url)

    // ── Page overlay injection ─────────────────────────────────────────────
    if (score >= WARN_SCORE) {
      // Tab might still be on the phishing URL — try immediately, then retry once
      setTimeout(() => injectOverlay(tabId, score, severity, host, brief), 600)
      setTimeout(() => injectOverlay(tabId, score, severity, host, brief), 2500)
    }

  } catch {
    // Backend offline
  }
}

// ─── LISTENER 1: onBeforeNavigate — fires BEFORE Chrome's Safe Browsing ──────
// This is the critical hook that captures the real URL before it gets intercepted
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return
  const url = details.url
  if (!url || !url.startsWith('http')) return
  if (url.includes('localhost') || url.includes('127.0.0.1')) return
  if (isTrusted(url)) return

  // Store it so onCompleted can attempt overlay injection
  pendingUrls.set(details.tabId, url)

  // Start analysis NOW — don't wait for page to load
  analyseUrl(url, details.tabId)
})

// ─── LISTENER 2: onCompleted — try overlay once page is fully loaded ──────────
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return
  const url = details.url
  if (!url || !url.startsWith('http')) return

  // Get the original URL (in case it was replaced by chrome-error page)
  const original = pendingUrls.get(details.tabId) || url
  const cached   = checkedUrls.get(original)

  if (cached && cached.score >= WARN_SCORE) {
    // Page loaded — try overlay injection with the actual loaded tab
    injectOverlay(details.tabId, cached.score, cached.severity,
                  new URL(original).hostname, cached.brief)
  }
})

// ─── BADGE ────────────────────────────────────────────────────────────────────
function setBadge(tabId, score) {
  const color = score >= 81 ? '#DC2626'
              : score >= 65 ? '#EA580C'
              : score >= 50 ? '#D97706'
              : '#059669'
  const label = score >= 50 ? String(score) : ''
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {})
  chrome.action.setBadgeText({ text: label, tabId }).catch(() => {})
}

// ─── CHROME NOTIFICATION ──────────────────────────────────────────────────────
function showNotification(score, severity, host, brief, tabId, originalUrl) {
  const id = `sg_${Date.now()}`

  const label = score >= 81 ? 'CRITICAL THREAT BLOCKED'
              : score >= 65 ? 'HIGH-RISK SITE FLAGGED'
              : 'SUSPICIOUS ACTIVITY DETECTED'

  chrome.notifications.create(id, {
    type:               'basic',
    iconUrl:            chrome.runtime.getURL('icons/icon128.png'),
    title:              `🛡 SpectraGuard  ·  ${label}`,
    message:            `${host}   ·   Threat Index: ${score}/100\n${brief.slice(0, 130)}`,
    priority:           score >= 81 ? 2 : 1,
    requireInteraction: score >= 81,
    buttons: score >= 65
      ? [{ title: '↩ Go Back to Safety' }, { title: 'Ignore Risk' }]
      : [{ title: '→ View Threat Report' }, { title: 'Ignore' }],
  })

  const handler = (nId, btnIdx) => {
    if (nId !== id) return
    chrome.notifications.onButtonClicked.removeListener(handler)
    chrome.notifications.clear(id)
    if (score >= 65 && btnIdx === 0) {
      chrome.tabs.goBack(tabId).catch(() => {})
    } else if (btnIdx === 0) {
      chrome.tabs.create({ url: `${DASHBOARD}/incidents` })
    }
  }
  chrome.notifications.onButtonClicked.addListener(handler)
}

// ─── PAGE OVERLAY (injected into the real page) ───────────────────────────────
function injectOverlay(tabId, score, severity, host, brief) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (_score, _severity, _host, _brief) => {
      if (document.getElementById('sg-shield-bar')) return

      const isCrit = _score >= 81
      const isHigh = _score >= 65

      const pal = isCrit
        ? { bg: 'rgba(15,10,30,0.97)', border: '#F04438', text: '#FF6B6B', sub: '#FDA4AF', btn: '#F04438', label: 'CRITICAL THREAT' }
        : isHigh
        ? { bg: 'rgba(20,14,10,0.96)', border: '#F97316', text: '#FDBA74', sub: '#FED7AA', btn: '#F97316', label: 'HIGH-RISK SITE' }
        : { bg: 'rgba(10,15,25,0.95)', border: '#FBBF24', text: '#FDE68A', sub: '#FEF3C7', btn: '#FBBF24', label: 'SUSPICIOUS SITE' }

      const bar     = document.createElement('div')
      bar.id        = 'sg-shield-bar'
      bar.style.cssText = [
        'all:initial!important',
        'position:fixed!important',
        'top:0!important','left:0!important','right:0!important',
        `z-index:2147483647!important`,
        `background:${pal.bg}!important`,
        `border-bottom:2px solid ${pal.border}!important`,
        'padding:0 20px!important',
        'display:flex!important',
        'align-items:center!important',
        'justify-content:space-between!important',
        'height:56px!important',
        'box-sizing:border-box!important',
        `box-shadow:0 4px 32px rgba(0,0,0,.6)!important`,
        `font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif!important`,
      ].join(';')

      bar.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px">
          <svg width="26" height="26" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L4 7v9c0 8.4 5.2 13.8 12 15 6.8-1.2 12-6.6 12-15V7z"
                  fill="${pal.border}" fill-opacity=".25" stroke="${pal.border}" stroke-width="1.5"/>
            <text x="16" y="21" text-anchor="middle" fill="white" font-size="10"
                  font-weight="800" font-family="system-ui">SG</text>
          </svg>
          <div>
            <div style="font-size:10px;font-weight:800;letter-spacing:.1em;color:${pal.text};text-transform:uppercase">
              ${pal.label} &nbsp;<span style="background:${pal.border};color:#fff;font-size:9px;padding:2px 7px;border-radius:20px">${_score}/100</span>
            </div>
            <div style="font-size:11px;color:#94A3B8;margin-top:1px;max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              <span style="color:${pal.sub};font-weight:600">${_host}</span> &nbsp;·&nbsp; ${_brief.slice(0, 90)}
            </div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${_score >= 65 ? `<button id="sg-back" style="background:${pal.btn};color:#fff;border:none;padding:7px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700;font-family:inherit">↩ Go Back</button>` : ''}
          <a href="http://localhost:5173/incidents" target="_blank" style="color:${pal.sub};font-size:11px;text-decoration:none;padding:6px 12px;border:1px solid rgba(255,255,255,.12);border-radius:7px;font-family:inherit">View Report ↗</a>
          <button id="sg-close" style="background:rgba(255,255,255,.06);color:#94A3B8;border:1px solid rgba(255,255,255,.1);padding:6px 12px;border-radius:7px;cursor:pointer;font-size:11px;font-family:inherit">✕</button>
        </div>
      `

      // Prepend to body or html
      const root = document.body || document.documentElement
      root.insertBefore(bar, root.firstChild)
      if (document.body) document.body.style.marginTop = '56px'

      document.getElementById('sg-back')?.addEventListener('click', () => { history.back(); bar.remove(); if(document.body) document.body.style.marginTop='' })
      document.getElementById('sg-close')?.addEventListener('click', () => { bar.remove(); if(document.body) document.body.style.marginTop='' })

      if (!isCrit) setTimeout(() => { bar.remove(); if(document.body) document.body.style.marginTop='' }, 12000)
    },
    args: [score, severity, host, brief],
  }).catch(() => {
    // Can't inject into chrome:// pages — notification already shown
  })
}

// ─── STORAGE ──────────────────────────────────────────────────────────────────
async function saveRecent(item) {
  try {
    const { recent = [] } = await chrome.storage.local.get('recent')
    recent.unshift(item)
    await chrome.storage.local.set({ recent: recent.slice(0, 50) })
  } catch {}
}

// ─── MESSAGE BRIDGE (content.js ↔ background) ────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {

  if (msg.type === 'GET_RECENT') {
    chrome.storage.local.get('recent', ({ recent = [] }) => reply({ recent }))
    return true
  }

  // content.js detected a specific email was opened — analyse body text
  if (msg.type === 'ANALYSE_EMAIL_CONTENT') {
    const tabId   = sender.tab?.id
    const text    = msg.text    || ''
    const subject = msg.subject || ''
    const from    = msg.sender  || ''

    if (!text || text.length < 80) { reply({ ok: true }); return true }

    fetch(`${BACKEND}/analyse`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ input: text, type: 'text' }),
    })
    .then(r => r.ok ? r.json() : null)
    .then(data => {
      if (!data) return
      const score  = data.sentinel_score || 0
      const brief  = (data.threat_brief  || '').slice(0, 200)

      if (tabId) setBadge(tabId, score)

      if (score < NOTIFY_SCORE) return  // Legitimate email — silent

      const id = `sg_email_${Date.now()}`
      const notifLabel = score >= 81 ? 'PHISHING EMAIL DETECTED' : 'SUSPICIOUS EMAIL CONTENT'

      chrome.notifications.create(id, {
        type:               'basic',
        iconUrl:            chrome.runtime.getURL('icons/icon128.png'),
        title:              `🛡 SpectraGuard  ·  ${notifLabel}`,
        message:            `"${subject.slice(0, 60)}"\nFrom: ${from.slice(0, 50)}\nThreat Index: ${score}/100\n${brief.slice(0, 80)}`,
        priority:           score >= 81 ? 2 : 1,
        requireInteraction: score >= 81,
        buttons:            [{ title: '→ View Threat Report' }, { title: 'Ignore' }],
      })

      const handler = (nId, btnIdx) => {
        if (nId !== id) return
        chrome.notifications.onButtonClicked.removeListener(handler)
        chrome.notifications.clear(id)
        if (btnIdx === 0) chrome.tabs.create({ url: `${DASHBOARD}/incidents` })
      }
      chrome.notifications.onButtonClicked.addListener(handler)

      // Critical phishing → inject fullscreen warning into Gmail
      if (score >= 81 && tabId) {
        chrome.tabs.sendMessage(tabId, {
          action: 'show_blocking_overlay',
          result: { score, explanation: brief },
        }).catch(() => {})
      }
    })
    .catch(() => {})

    reply({ ok: true })
    return true
  }
})
