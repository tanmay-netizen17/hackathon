/**
 * SentinelAI Shield — Content Script (V2)
 * Handles UI injection for threat warnings and email text extraction.
 */

// ── Email Content Extraction ─────────────────────────────────────────────────
const EMAIL_DOMAINS = ["mail.google.com", "outlook.live.com", "outlook.office.com"];
let lastText = "";
let debounceTimer = null;

if (EMAIL_DOMAINS.includes(window.location.hostname)) {
    console.log("[SentinelAI] Email monitoring active.");
    
    const observer = new MutationObserver(() => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(extractAndAnalyse, 2000); // 2s debounce
    });

    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
}

function extractAndAnalyse() {
    const visibleText = document.body.innerText.substring(0, 5000); // Limit to 5k chars
    if (visibleText === lastText || visibleText.length < 50) return;
    
    lastText = visibleText;
    chrome.runtime.sendMessage({ action: "analyze_text", text: visibleText });
}

// ── Message Listener ─────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "show_blocking_overlay") {
    injectBlockingOverlay(request.result);
    sendResponse({ status: "overlay_injected" });
  }
});

// ── UI Injection: Security Alert Overlay ──────────────────────────────────────
function injectBlockingOverlay(result) {
  if (document.getElementById("sentinel-blocking-overlay")) return;

  const overlay = document.createElement("div");
  overlay.id = "sentinel-blocking-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left:0; width: 100vw; height: 100vh;
    background: #0F172A; z-index: 2147483647; display: flex;
    align-items: center; justify-content: center; color: white;
    font-family: 'Inter', system-ui, sans-serif; opacity: 0;
    transition: opacity 0.4s ease;
  `;

  overlay.innerHTML = `
    <div style="max-width: 540px; width: 90%; background: #1E293B; border: 2px solid #EF4444; border-radius: 24px; padding: 48px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7); text-align: center;">
      <div style="width: 80px; height: 80px; background: rgba(239, 68, 68, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px;">
        <svg depth="1.5" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      </div>
      
      <h1 style="font-size: 32px; font-weight: 800; letter-spacing: -0.025em; margin-bottom: 12px; color: #F8FAFC;">SentinelAI Security Alert</h1>
      <p style="font-size: 16px; line-height: 1.6; color: #94A3B8; margin-bottom: 32px;">
        This page has been flagged as high-risk. Proceeding may compromise your data.<br>
        <span style="display:inline-block; margin-top:12px; font-weight: 600; color: #EF4444; background: rgba(239, 68, 68, 0.1); padding: 4px 12px; border-radius: 99px;">
          Sentinel Score: ${result.score}/100
        </span>
      </p>

      <div style="background: rgba(15, 23, 42, 0.5); border-radius: 12px; padding: 20px; text-align: left; margin-bottom: 32px;">
        <div style="font-size: 12px; font-weight: 700; color: #6366F1; text-transform: uppercase; margin-bottom: 8px;">AI Evidence Analysis:</div>
        <div style="font-size: 14px; color: #CBD5E1; line-height: 1.5;">${result.explanation || "Detection based on multiple suspicious lexical and behavioral patterns."}</div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 12px;">
        <button id="sen-btn-back" style="width: 100%; padding: 16px; background: #EF4444; color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 700; cursor: pointer; transition: transform 0.2s;">
          Get me to safety
        </button>
        <button id="sen-btn-ignore" style="width: 100%; padding: 16px; background: transparent; color: #64748B; border: 1px solid #334155; border-radius: 12px; font-size: 14px; font-weight: 500; cursor: pointer;">
          I understand the risks, proceed anyway
        </button>
      </div>
      
      <div style="margin-top: 24px; font-size: 12px; color: #475569; display: flex; align-items: center; justify-content: center; gap: 6px;">
        <span style="width:6px; height:6px; background:#10B981; border-radius:50%;"></span>
        Protected by SentinelAI Defense Platform
      </div>
    </div>
  `;

  document.documentElement.appendChild(overlay);
  setTimeout(() => overlay.style.opacity = "1", 10);

  document.getElementById("sen-btn-back").addEventListener("click", () => {
    window.history.back();
    setTimeout(() => { if (window.location.href === window.location.href) window.close(); }, 500);
  });

  document.getElementById("sen-btn-ignore").addEventListener("click", () => {
    overlay.style.opacity = "0";
    setTimeout(() => overlay.remove(), 400);
  });
}
