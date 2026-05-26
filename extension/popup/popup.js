/**
 * TraceZ — Popup Controller
 * Renders score, signals, recent scans, and handles user interactions
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scoreValue = document.getElementById('scoreValue');
  const scoreLabel = document.getElementById('scoreLabel');
  const scoreRing = document.getElementById('scoreRing');
  const domainName = document.getElementById('domainName');
  const scanTime = document.getElementById('scanTime');
  const signalList = document.getElementById('signalList');
  const recentList = document.getElementById('recentList');
  const detailsToggle = document.getElementById('detailsToggle');
  const detailsContent = document.getElementById('detailsContent');
  const settingsBtn = document.getElementById('settingsBtn');
  const protectionToggle = document.getElementById('protectionToggle');

  // ─── Get Current Tab ────────────────────────────────
  let currentUrl = '';
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrl = tab.url;
      const domain = extractDomainSimple(currentUrl);
      domainName.textContent = domain || 'Unknown';
    }
  } catch (e) {
    domainName.textContent = 'Unable to detect';
  }

  // ─── Request Score from Background ──────────────────
  if (currentUrl && !currentUrl.startsWith('chrome') && !currentUrl.startsWith('about')) {
    try {
      const result = await chrome.runtime.sendMessage({ type: 'getPageScore', url: currentUrl });
      if (result) {
        renderScore(result.score, result.verdict);
        renderSignals(result.formatted || []);
        if (result.scannedAt) {
          scanTime.textContent = `Scanned ${formatTimeAgo(result.scannedAt)}`;
        }
      }
    } catch (e) {
      scoreValue.textContent = '—';
      scoreLabel.textContent = 'Unavailable';
    }
  } else {
    scoreValue.textContent = '—';
    scoreLabel.textContent = 'Internal page';
    domainName.textContent = 'Browser page';
  }

  // ─── Load Recent Scans ─────────────────────────────
  try {
    const response = await chrome.runtime.sendMessage({ type: 'getRecentScans' });
    if (response && response.scans && response.scans.length > 0) {
      renderRecentScans(response.scans.slice(0, 5));
    }
  } catch (e) { /* keep empty state */ }

  // ─── Load Settings ─────────────────────────────────
  try {
    const response = await chrome.runtime.sendMessage({ type: 'getSettings' });
    if (response && response.settings) {
      protectionToggle.checked = response.settings.enabled !== false;
    }
  } catch (e) { /* keep defaults */ }

  // ─── Event Listeners ───────────────────────────────
  detailsToggle.addEventListener('click', () => {
    detailsToggle.classList.toggle('open');
    detailsContent.classList.toggle('open');
  });

  settingsBtn.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  protectionToggle.addEventListener('change', async () => {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'getSettings' });
      const settings = resp?.settings || {};
      settings.enabled = protectionToggle.checked;
      await chrome.runtime.sendMessage({ type: 'updateSettings', settings });
    } catch (e) { /* silent */ }
  });

  // ─── Render Functions ──────────────────────────────
  function renderScore(score, verdict) {
    // Animate count-up
    let current = 0;
    const target = score;
    const step = Math.max(1, Math.ceil(target / 30));
    const interval = setInterval(() => {
      current = Math.min(current + step, target);
      scoreValue.textContent = current;

      const degree = (current / 100) * 360;
      const color = getScoreColor(current);
      scoreRing.style.background = `conic-gradient(${color} ${degree}deg, #F3F4F6 ${degree}deg)`;

      if (current >= target) {
        clearInterval(interval);
        scoreLabel.textContent = getVerdictLabel(verdict || 'SAFE');
        scoreLabel.style.color = color;
      }
    }, 20);
  }

  function renderSignals(signals) {
    signalList.textContent = ''; // Clear

    if (signals.length === 0) {
      const item = document.createElement('div');
      item.className = 'signal-item safe';
      const icon = document.createElement('span');
      icon.className = 'signal-icon';
      icon.textContent = '✓';
      const text = document.createElement('span');
      text.className = 'signal-text';
      text.textContent = 'No threats detected';
      item.appendChild(icon);
      item.appendChild(text);
      signalList.appendChild(item);
      return;
    }

    for (const sig of signals.slice(0, 6)) {
      const item = document.createElement('div');
      item.className = `signal-item ${sig.severity || 'safe'}`;
      const icon = document.createElement('span');
      icon.className = 'signal-icon';
      icon.textContent = sig.icon || '✓';
      const text = document.createElement('span');
      text.className = 'signal-text';
      text.textContent = sig.text || sig.description || 'Unknown signal';
      item.appendChild(icon);
      item.appendChild(text);
      signalList.appendChild(item);
    }
  }

  function renderRecentScans(scans) {
    recentList.textContent = ''; // Clear

    for (const scan of scans) {
      const item = document.createElement('div');
      item.className = 'recent-item';

      const domain = document.createElement('span');
      domain.className = 'recent-domain';
      domain.textContent = scan.domain;

      const badge = document.createElement('span');
      const verdictClass = (scan.verdict || 'SAFE').toLowerCase();
      badge.className = `verdict-badge ${verdictClass}`;
      badge.textContent = getVerdictLabel(scan.verdict);

      item.appendChild(domain);
      item.appendChild(badge);
      recentList.appendChild(item);
    }
  }

  // ─── Utilities ─────────────────────────────────────
  function getScoreColor(score) {
    if (score <= 25) return '#10B981';
    if (score <= 55) return '#F59E0B';
    if (score <= 80) return '#F97316';
    return '#EF4444';
  }

  function getVerdictLabel(verdict) {
    const labels = { SAFE: 'Safe', CAUTION: 'Caution', WARNING: 'Warning', DANGEROUS: 'Dangerous' };
    return labels[verdict] || verdict || 'Unknown';
  }

  function extractDomainSimple(url) {
    try {
      return new URL(url).hostname;
    } catch { return ''; }
  }

  function formatTimeAgo(timestamp) {
    const diff = Date.now() - timestamp;
    const seconds = Math.floor(diff / 1000);
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
  }
});
