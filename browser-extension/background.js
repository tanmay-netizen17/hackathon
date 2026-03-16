/**
 * SentinelAI Shield — Background Service Worker (V2)
 * Advanced real-time threat detection and response.
 */

const SENTINEL_API = "http://localhost:8000";
const ALERT_THRESHOLD = 70;   // Show browser notification
const BLOCK_THRESHOLD = 85;   // Show full-screen blocking overlay
const MAX_HISTORY = 20;

// Scanned URL cache to prevent redundant API calls
const scanCache = new Map();

// ── Navigation listener ──────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame

  const url = details.url;
  if (shouldSkip(url)) return;

  // Debounce/Cache check (5 min TTL)
  if (scanCache.has(url) && (Date.now() - scanCache.get(url).time < 300000)) {
    handleResult(url, scanCache.get(url).result, details.tabId);
    return;
  }

  try {
    const response = await fetch(`${SENTINEL_API}/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error("API Offline");
    const result = await response.json();
    
    scanCache.set(url, { result, time: Date.now() });
    handleResult(url, result, details.tabId);
    
    // Log threat to dashboard if suspicious/critical
    if (result.score >= ALERT_THRESHOLD) {
        logToDashboard(url, result);
    }

  } catch (e) {
    console.warn("[SentinelAI] Analysis failed:", e.message);
  }
});

// ── Response Logic ────────────────────────────────────────────────────────────
function handleResult(url, result, tabId) {
  storeResult(url, result);

  if (result.score >= BLOCK_THRESHOLD) {
    // Critical Threat: Inject Blocking Overlay
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ["content.js"]
    }).then(() => {
      chrome.tabs.sendMessage(tabId, { action: "show_blocking_overlay", result });
    });
  } else if (result.score >= ALERT_THRESHOLD) {
    // High Threat: Show Browser Notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "⚠ SentinelAI Security Warning",
      message: `Suspicious activity detected at ${new URL(url).hostname}. Score: ${result.score}/100`,
      priority: 2
    });
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function shouldSkip(url) {
  const skipProtocols = ["chrome:", "chrome-extension:", "about:", "data:", "file:"];
  if (skipProtocols.some(p => url.startsWith(p))) return true;
  
  const hostname = new URL(url).hostname;
  return hostname === "localhost" || hostname === "127.0.0.1";
}

async function logToDashboard(url, result) {
    try {
        await fetch(`${SENTINEL_API}/log/threat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url,
                sentinel_score: result.score,
                severity: result.severity,
                threat_brief: result.explanation,
                timestamp: new Date().toISOString(),
                source: "browser_agent_realtime"
            })
        });
    } catch (e) {}
}

async function storeResult(url, result) {
  const { history = [] } = await chrome.storage.local.get("history");
  const newEntry = {
    url: url.substring(0, 100),
    score: result.score,
    severity: result.severity,
    timestamp: new Date().toISOString(),
  };
  await chrome.storage.local.set({ 
      history: [newEntry, ...history].slice(0, MAX_HISTORY) 
  });
}

// ── Message Listener (Text Extraction) ───────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_text") {
    fetch(`${SENTINEL_API}/analyze/text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: request.text })
    })
    .then(r => r.json())
    .then(result => {
      handleResult(sender.tab.url, result, sender.tab.id);
      sendResponse({ status: "processed" });
    })
    .catch(() => sendResponse({ status: "error" }));
    return true; // async
  }
});
