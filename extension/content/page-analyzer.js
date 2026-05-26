/**
 * TraceZ — Content Script: Page Analyzer
 * Analyzes page DOM for phishing indicators
 */

(() => {
  let analyzed = false;

  // Listen for analysis request from service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'analyzeDOM' && !analyzed) {
      analyzed = true;
      const result = analyzeDOM();
      sendResponse(result);
      // Also send to background
      chrome.runtime.sendMessage({
        type: 'domAnalysisResult',
        data: { ...result, domain: window.location.hostname },
      });
    }

    if (message.type === 'showWarning') {
      showWarningOverlay(message.data);
    }
  });

  // Auto-analyze after page loads if score was medium+
  function analyzeDOM() {
    const result = {
      passwordFields: 0,
      crossDomainForm: false,
      hiddenIframes: 0,
      obfuscatedJS: false,
      externalScripts: 0,
      autoDownload: false,
    };

    try {
      // 1. Count password fields
      result.passwordFields = document.querySelectorAll('input[type="password"]').length;

      // 2. Check for cross-domain form actions
      const forms = document.querySelectorAll('form');
      const currentHost = window.location.hostname;
      for (const form of forms) {
        const action = form.getAttribute('action') || '';
        if (action.startsWith('http')) {
          try {
            const actionUrl = new URL(action);
            if (actionUrl.hostname !== currentHost) {
              result.crossDomainForm = true;
            }
          } catch (e) { /* invalid URL */ }
        }
      }

      // 3. Detect hidden iframes
      const iframes = document.querySelectorAll('iframe');
      for (const iframe of iframes) {
        const style = window.getComputedStyle(iframe);
        const isHidden = style.display === 'none' || style.visibility === 'hidden' ||
                         parseInt(style.width) <= 1 || parseInt(style.height) <= 1 ||
                         style.opacity === '0';
        const src = iframe.getAttribute('src') || '';
        if (isHidden && src.startsWith('http')) {
          try {
            const iframeUrl = new URL(src);
            if (iframeUrl.hostname !== currentHost) {
              result.hiddenIframes++;
            }
          } catch (e) { /* invalid */ }
        }
      }

      // 4. Check for obfuscated JavaScript patterns
      const scripts = document.querySelectorAll('script:not([src])');
      for (const script of scripts) {
        const content = script.textContent || '';
        const obfuscationPatterns = [
          /eval\s*\(/,
          /document\.write\s*\(/,
          /atob\s*\([^)]*atob/,
          /String\.fromCharCode\s*\(\s*\d+/,
          /\\x[0-9a-f]{2}/i,
          /unescape\s*\(/,
        ];
        for (const pattern of obfuscationPatterns) {
          if (pattern.test(content)) {
            result.obfuscatedJS = true;
            break;
          }
        }
      }

      // 5. Count external scripts
      const extScripts = document.querySelectorAll('script[src]');
      for (const s of extScripts) {
        const src = s.getAttribute('src') || '';
        if (src.startsWith('http')) {
          try {
            const scriptUrl = new URL(src);
            if (scriptUrl.hostname !== currentHost) {
              result.externalScripts++;
            }
          } catch (e) { /* invalid */ }
        }
      }

      // 6. Auto-download detection
      const downloadLinks = document.querySelectorAll('a[download], a[href$=".exe"], a[href$=".msi"], a[href$=".bat"]');
      if (downloadLinks.length > 0) {
        result.autoDownload = true;
      }

    } catch (e) {
      // DOM analysis failed silently
    }

    return result;
  }

  // ─── Warning Overlay ──────────────────────────────────────
  function showWarningOverlay(data) {
    // Check if already showing
    if (document.getElementById('tracez-warning-host')) return;

    const host = document.createElement('div');
    host.id = 'tracez-warning-host';
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      * { margin: 0; padding: 0; box-sizing: border-box; }
      @keyframes slideDown {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; transform: translateY(-20px); }
      }
      .banner {
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: slideDown 0.4s ease-out;
        padding: 0;
      }
      .banner.closing { animation: fadeOut 0.3s ease-in forwards; }
      .banner-inner {
        margin: 12px; padding: 16px 20px;
        background: #FFFFFF; border-radius: 12px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.12), 0 0 0 1px rgba(0,0,0,0.04);
        border-left: 4px solid ${data.verdict === 'WARNING' ? '#F97316' : '#F59E0B'};
      }
      .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
      .title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #1A1A2E; }
      .title svg { width: 18px; height: 18px; flex-shrink: 0; }
      .close { background: none; border: none; cursor: pointer; color: #9CA3AF; padding: 4px; border-radius: 4px; }
      .close:hover { background: #F3F4F6; color: #6B7280; }
      .score-badge {
        display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600;
        background: ${data.verdict === 'WARNING' ? '#FFF7ED' : '#FFFBEB'};
        color: ${data.verdict === 'WARNING' ? '#9A3412' : '#92400E'};
      }
      .body { font-size: 13px; color: #4B5563; line-height: 1.5; margin-bottom: 12px; }
      .signals { margin: 8px 0; }
      .signal { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #6B7280; padding: 2px 0; }
      .signal-icon { width: 14px; text-align: center; }
      .actions { display: flex; gap: 8px; flex-wrap: wrap; }
      .btn {
        padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 500;
        border: none; cursor: pointer; transition: all 0.15s;
      }
      .btn-back { background: #1A1A2E; color: white; }
      .btn-back:hover { background: #2D2D4E; }
      .btn-trust { background: #F3F4F6; color: #4B5563; }
      .btn-trust:hover { background: #E5E7EB; }
    `;

    const banner = document.createElement('div');
    banner.className = 'banner';

    const inner = document.createElement('div');
    inner.className = 'banner-inner';

    // Header
    const header = document.createElement('div');
    header.className = 'header';

    const titleDiv = document.createElement('div');
    titleDiv.className = 'title';
    titleDiv.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.3 14.17A2 2 0 003.72 21h16.56a2 2 0 001.73-2.97l-8.3-14.17a2 2 0 00-3.42 0z"/></svg>`;
    const titleText = document.createElement('span');
    titleText.textContent = 'TraceZ Security Warning';
    titleDiv.appendChild(titleText);

    const scoreBadge = document.createElement('span');
    scoreBadge.className = 'score-badge';
    scoreBadge.textContent = `Risk: ${data.score}/100`;

    const closeBtn = document.createElement('button');
    closeBtn.className = 'close';
    closeBtn.textContent = '✕';
    closeBtn.addEventListener('click', () => {
      banner.classList.add('closing');
      setTimeout(() => host.remove(), 300);
    });

    header.appendChild(titleDiv);
    header.appendChild(scoreBadge);
    header.appendChild(closeBtn);

    // Body
    const body = document.createElement('div');
    body.className = 'body';
    body.textContent = data.summary || `This page may not be safe. Risk score: ${data.score}/100`;

    // Signals
    const signalsDiv = document.createElement('div');
    signalsDiv.className = 'signals';
    if (data.signals) {
      for (const sig of data.signals.slice(0, 3)) {
        const sigEl = document.createElement('div');
        sigEl.className = 'signal';
        const icon = document.createElement('span');
        icon.className = 'signal-icon';
        icon.textContent = sig.icon || '⚠';
        const text = document.createElement('span');
        text.textContent = sig.text;
        sigEl.appendChild(icon);
        sigEl.appendChild(text);
        signalsDiv.appendChild(sigEl);
      }
    }

    // Actions
    const actions = document.createElement('div');
    actions.className = 'actions';

    const backBtn = document.createElement('button');
    backBtn.className = 'btn btn-back';
    backBtn.textContent = 'Go Back';
    backBtn.addEventListener('click', () => history.back());

    const trustBtn = document.createElement('button');
    trustBtn.className = 'btn btn-trust';
    trustBtn.textContent = 'I Trust This Site';
    trustBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'trustSite', domain: data.domain });
      banner.classList.add('closing');
      setTimeout(() => host.remove(), 300);
    });

    actions.appendChild(backBtn);
    actions.appendChild(trustBtn);

    // Assemble
    inner.appendChild(header);
    inner.appendChild(body);
    inner.appendChild(signalsDiv);
    inner.appendChild(actions);
    banner.appendChild(inner);
    shadow.appendChild(style);
    shadow.appendChild(banner);
    document.body.appendChild(host);

    // Auto-dismiss after 30 seconds
    setTimeout(() => {
      if (document.getElementById('tracez-warning-host')) {
        banner.classList.add('closing');
        setTimeout(() => host.remove(), 300);
      }
    }, 30000);
  }

  // Request DOM analysis after 2 seconds if page has loaded
  setTimeout(() => {
    if (!analyzed) {
      const result = analyzeDOM();
      if (result.passwordFields > 0 || result.hiddenIframes > 0 || result.obfuscatedJS) {
        chrome.runtime.sendMessage({
          type: 'domAnalysisResult',
          data: { ...result, domain: window.location.hostname },
        }).catch(() => {});
      }
    }
  }, 2000);

  // Set attribute on DOM document root and dispatch custom event to indicate extension is active
  try {
    document.documentElement.dataset.tracezInstalled = "true";
    window.dispatchEvent(new CustomEvent('tracezExtensionLoaded', { 
      detail: { version: "1.0.0", active: true } 
    }));
  } catch (e) {
    // Fail silently
  }
})();

