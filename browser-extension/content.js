/**
 * SpectraGuard Shield — Content Script v4
 *
 * Gmail:   Detects when user OPENS a specific email (hash change with thread ID).
 *          Extracts body text and sends to background for analysis.
 * Outlook: Same via MutationObserver on reading pane.
 * Others:  Receives overlay injection commands from background.js.
 */

const pageHost = window.location.hostname

// ─── Gmail email monitoring ───────────────────────────────────────────────────
if (pageHost === 'mail.google.com') {

  let lastThreadId  = null   // last gmail thread ID we analysed
  let analysing     = false
  let debounceTimer = null

  // Gmail hash format: #inbox/THREADID or #all/THREADID
  // Thread IDs are base62 (letters + digits) — NOT hex
  function getThreadId() {
    const hash = window.location.hash
    // Match the last path segment after # (the actual thread ID)
    const parts = hash.replace('#', '').split('/')
    // e.g. ['inbox', 'KlbxLxGIIkfqqHLCvDqSOdCmnfHgnxOCpg']
    const id = parts[parts.length - 1]
    // Must have a thread ID (alphanumeric, > 8 chars), not just a folder name
    return (id && id.length > 8 && /[A-Za-z0-9]{8,}/.test(id) && parts.length >= 2) ? id : null
  }

  async function checkAndAnalyse() {
    if (analysing) return

    const threadId = getThreadId()
    if (!threadId || threadId === lastThreadId) return

    // Wait for email body DOM to render
    await new Promise(r => setTimeout(r, 1600))

    // Double-check user is still on the same email
    if (getThreadId() !== threadId) return

    // Extract email content from Gmail's reading pane
    const emailBody  = document.querySelector('.a3s.aiL')           // main email body
                    || document.querySelector('[data-message-id]')   // fallback
                    || document.querySelector('.gs')                  // quoted text container

    const bodyText   = emailBody?.innerText || ''
    if (bodyText.length < 60) return  // Not enough content yet

    // Extract metadata
    const senderEl  = document.querySelector('.gD')
    const subjectEl = document.querySelector('.hP')
    const sender    = senderEl?.getAttribute('email') || senderEl?.textContent || ''
    const subject   = subjectEl?.textContent || ''

    // Mark as analysing to prevent duplicates
    lastThreadId = threadId
    analysing    = true

    const fullText = [
      subject ? `Subject: ${subject}` : '',
      sender  ? `From: ${sender}`     : '',
      '',
      bodyText.slice(0, 3000),
    ].filter(Boolean).join('\n')

    console.log('[SpectraGuard] Analysing email:', subject.slice(0, 40))

    try {
      chrome.runtime.sendMessage({
        type:    'ANALYSE_EMAIL_CONTENT',
        text:    fullText,
        subject: subject,
        sender:  sender,
        msgId:   threadId,
      }, () => { /* ignore response */ })
    } catch (e) {
      console.warn('[SpectraGuard] sendMessage error:', e)
    } finally {
      // Allow re-analysis after 30s (in case user comes back)
      setTimeout(() => { analysing = false }, 30000)
    }
  }

  // ── Watch for URL hash changes (fired when opening/closing emails) ──────────
  let lastHash = window.location.hash
  const hashWatcher = setInterval(() => {
    const currentHash = window.location.hash
    if (currentHash !== lastHash) {
      lastHash = currentHash
      clearTimeout(debounceTimer)
      debounceTimer = setTimeout(checkAndAnalyse, 400)
    }
  }, 500)

  // ── Also fire if an email is ALREADY open when the script loads ─────────────
  setTimeout(checkAndAnalyse, 2500)
}

// ─── Outlook email monitoring ─────────────────────────────────────────────────
if (pageHost === 'outlook.live.com' || pageHost === 'outlook.office.com') {
  let lastSubject = ''
  let analysing   = false

  const observer = new MutationObserver(() => {
    if (analysing) return
    clearTimeout(window._sg_ol_timer)
    window._sg_ol_timer = setTimeout(async () => {
      const pane    = document.querySelector('[aria-label*="Reading"]') || document.querySelector('[role="main"]')
      const subject = document.querySelector('[data-testid*="subject"]')?.textContent
                   || document.querySelector('[aria-label*="Subject"]')?.textContent || ''
      const text    = pane?.innerText || ''

      if (!text || text.length < 80 || subject === lastSubject) return
      lastSubject = subject
      analysing   = true
      setTimeout(() => { analysing = false }, 30000)

      chrome.runtime.sendMessage({
        type:    'ANALYSE_EMAIL_CONTENT',
        text:    `Subject: ${subject}\n\n${text.slice(0, 3000)}`,
        subject: subject,
        sender:  '',
      }, () => {})
    }, 1200)
  })

  observer.observe(document.body, { childList: true, subtree: true })
}

// ─── Receive overlay commands from background.js ──────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.action === 'show_blocking_overlay') {
    showFullOverlay(msg.result)
    if (reply) reply({ status: 'ok' })
  }
})

// ─── Full-screen overlay for critical phishing emails ────────────────────────
function showFullOverlay(result) {
  if (document.getElementById('sg-fullscreen-overlay')) return

  const score   = result.score || 0
  const explain = (result.explanation || 'Malicious content patterns detected').slice(0, 150)

  const overlay = document.createElement('div')
  overlay.id    = 'sg-fullscreen-overlay'
  overlay.style.cssText = `
    position:fixed;top:0;left:0;width:100vw;height:100vh;
    background:rgba(10,8,20,0.97);z-index:2147483647;
    display:flex;align-items:center;justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    opacity:0;transition:opacity 0.3s ease;
  `

  overlay.innerHTML = `
    <div style="max-width:520px;width:90%;background:rgba(20,14,35,0.98);
      border:1.5px solid #F04438;border-radius:20px;padding:40px 36px;
      box-shadow:0 40px 80px rgba(0,0,0,.8),0 0 80px rgba(240,68,56,.15);
      text-align:center">

      <svg width="52" height="52" viewBox="0 0 32 32" fill="none" style="margin:0 auto 18px;display:block">
        <path d="M16 2L4 7v9c0 8.4 5.2 13.8 12 15 6.8-1.2 12-6.6 12-15V7z"
              fill="#F04438" fill-opacity=".2" stroke="#F04438" stroke-width="1.5"/>
        <path d="M16 6L7 10v6c0 5.6 3.6 9.6 9 10.5 5.4-.9 9-4.9 9-10.5v-6z"
              fill="#F04438" fill-opacity=".4"/>
        <text x="16" y="20" text-anchor="middle" fill="white" font-size="9"
              font-weight="800" font-family="system-ui">SG</text>
      </svg>

      <div style="font-size:10px;font-weight:800;letter-spacing:.15em;color:#F04438;
                  text-transform:uppercase;margin-bottom:10px">
        Phishing Email Intercepted
      </div>
      <h2 style="font-size:22px;font-weight:800;color:#F8FAFC;margin:0 0 12px;letter-spacing:-.02em">
        This Email Is Not Safe
      </h2>
      <p style="color:#94A3B8;font-size:13px;line-height:1.6;margin:0 0 22px">
        SpectraGuard's AI detected malicious content in this email.<br>
        It may be attempting to steal credentials or compromise your device.
      </p>

      <div style="background:rgba(240,68,56,.08);border:1px solid rgba(240,68,56,.2);
                  border-radius:10px;padding:12px 14px;margin-bottom:22px;text-align:left">
        <div style="font-size:9px;color:#F04438;font-weight:700;letter-spacing:.08em;margin-bottom:5px">
          THREAT ANALYSIS
        </div>
        <div style="font-size:12px;color:#CBD5E1;line-height:1.5">
          Threat Index: <strong style="color:#FF6B6B">${score}/100</strong>
          &nbsp;·&nbsp;${explain}
        </div>
      </div>

      <div style="display:flex;gap:10px">
        <button id="sg-ov-back" style="flex:1;padding:13px;background:#F04438;color:#fff;
          border:none;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;
          font-family:inherit">
          ← Go Back to Inbox
        </button>
        <button id="sg-ov-ignore" style="padding:13px 18px;background:transparent;color:#475569;
          border:1px solid rgba(255,255,255,.1);border-radius:10px;font-size:13px;
          cursor:pointer;font-family:inherit">
          Ignore
        </button>
      </div>

      <div style="margin-top:18px;font-size:10px;color:#334155">
        Protected by SpectraGuard · AI Threat Intelligence
      </div>
    </div>
  `

  document.documentElement.appendChild(overlay)
  setTimeout(() => overlay.style.opacity = '1', 20)

  document.getElementById('sg-ov-back')?.addEventListener('click', () => window.history.back())
  document.getElementById('sg-ov-ignore')?.addEventListener('click', () => {
    overlay.style.opacity = '0'
    setTimeout(() => overlay.remove(), 300)
  })
}
