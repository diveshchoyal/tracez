/**
 * TraceZ — Background Service Worker
 * Main brain: intercepts navigation, runs scans, coordinates everything
 */

import { extractDomain } from '../lib/utils.js';
import { BlocklistManager } from '../lib/blocklist.js';
import { detectHomoglyphAttack, findBrandMimic } from '../lib/homoglyph.js';
import { analyzeDomain, analyzeURL } from '../lib/detector.js';
import { calculateScore, getVerdict, formatSignals, generateSummary } from '../lib/scorer.js';

// ─── State ─────────────────────────────────────────────────
const scanCache = new Map();       // url -> { result, timestamp }
const CACHE_TTL = 5 * 60 * 1000;  // 5 minutes
const blocklist = new BlocklistManager();
let protectionEnabled = true;
let apiUrl = 'http://localhost:8000';

// ─── Initialization ────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  await blocklist.load();
  await loadSettings();
  console.log('[TraceZ] Extension installed. Blocklist loaded:', blocklist.getStats());
});

chrome.runtime.onStartup.addListener(async () => {
  await blocklist.load();
  await loadSettings();
});

async function loadSettings() {
  try {
    const data = await chrome.storage.local.get(['tracez_settings']);
    if (data.tracez_settings) {
      const s = JSON.parse(data.tracez_settings);
      protectionEnabled = s.enabled !== false;
      apiUrl = s.apiUrl || 'http://localhost:8000';
    }
  } catch (e) { /* use defaults */ }
}

// ─── Navigation Interception ───────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigations
  if (details.frameId !== 0 || !protectionEnabled) return;

  const url = details.url;

  // Skip internal URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:') || url.startsWith('edge://') ||
      url.startsWith('brave://') || url.startsWith('devtools://')) {
    return;
  }

  const domain = extractDomain(url);
  if (!domain) return;

  // Skip safe domains (fast path)
  if (blocklist.isSafe(domain)) {
    updateBadge(details.tabId, 0);
    saveScanResult(url, domain, 0, [], 'SAFE');
    return;
  }

  // Check cache
  const cached = scanCache.get(domain);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    handleScanResult(details.tabId, url, cached.result);
    return;
  }

  // Run local scan pipeline
  const result = await runLocalScan(url, domain);

  // Cache it
  scanCache.set(domain, { result, timestamp: Date.now() });

  // Handle result
  handleScanResult(details.tabId, url, result);

  // Async API enrichment for medium-risk URLs
  if (result.score >= 30 && result.score <= 80) {
    enrichWithAPI(url, domain, details.tabId).catch(() => {});
  }
});

// ─── Local Scan Pipeline ───────────────────────────────────
async function runLocalScan(url, domain) {
  const allSignals = [];

  // Layer 1: Blocklist check
  const blockResult = blocklist.checkDomain(domain);
  if (blockResult.blocked) {
    allSignals.push({
      layer: 'blocklist', name: 'blocklist_hit',
      description: blockResult.reason || 'Domain is on the blocklist',
      score: 90, confidence: 1.0,
    });
  }

  // Layer 2: Homoglyph detection
  const homoResult = detectHomoglyphAttack(domain);
  if (homoResult.hasHomoglyphs) {
    allSignals.push({
      layer: 'homoglyph', name: 'homoglyph_chars',
      description: `Domain uses confusable Unicode characters`,
      score: 40, confidence: 0.95,
    });
  }

  // Layer 3: Brand impersonation
  const brandResult = findBrandMimic(domain);
  if (brandResult.isMimic) {
    const method = brandResult.method === 'homoglyph' ? 'Unicode characters' :
                   brandResult.method === 'typosquat' ? 'typosquatting' : 'subdomain abuse';
    allSignals.push({
      layer: 'homoglyph', name: 'brand_mimic',
      description: `Domain mimics "${brandResult.brand}" via ${method}`,
      score: brandResult.method === 'homoglyph' ? 45 : 25, confidence: 0.9,
    });
  }

  // Layer 4: Domain heuristics
  const domainSignals = analyzeDomain(domain);
  allSignals.push(...domainSignals);

  // Layer 5: URL pattern analysis
  const urlSignals = analyzeURL(url);
  allSignals.push(...urlSignals);

  const score = calculateScore(allSignals);
  const verdict = getVerdict(score);

  return {
    url, domain, score,
    verdict: verdict.level,
    signals: allSignals,
    formatted: formatSignals(allSignals),
    summary: generateSummary(score, allSignals, domain),
    scannedAt: Date.now(),
    enriched: false,
  };
}

// ─── Handle Scan Results ───────────────────────────────────
function handleScanResult(tabId, url, result) {
  updateBadge(tabId, result.score);
  saveScanResult(url, result.domain, result.score, result.signals, result.verdict);

  if (result.score > 80) {
    // Block: redirect to blocked page
    const params = new URLSearchParams({
      url: url,
      score: result.score.toString(),
      domain: result.domain,
      reason: result.summary,
    });
    chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL(`assets/blocked-page.html?${params.toString()}`)
    });
  } else if (result.score >= 30) {
    // Warning: send message to content script to show banner
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, {
        type: 'showWarning',
        data: {
          score: result.score,
          verdict: result.verdict,
          domain: result.domain,
          signals: result.formatted.slice(0, 4),
          summary: result.summary,
        },
      }).catch(() => {}); // Tab might not have content script yet
    }, 1000);
  }
}

// ─── API Enrichment ────────────────────────────────────────
async function enrichWithAPI(url, domain, tabId) {
  try {
    const resp = await fetch(`${apiUrl}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(5000),
    });

    if (!resp.ok) return;

    const data = await resp.json();
    if (data.risk_score !== undefined) {
      // Merge API results with local scan
      const cached = scanCache.get(domain);
      if (cached) {
        cached.result.score = Math.max(cached.result.score, data.risk_score);
        cached.result.verdict = data.verdict || cached.result.verdict;
        cached.result.enriched = true;
        if (data.signals) {
          cached.result.signals.push(...data.signals.map(s => ({
            layer: 'reputation', name: s.layer || 'api',
            description: s.signal || s.description,
            score: s.score, confidence: s.confidence || 0.8,
          })));
        }
        cached.result.formatted = formatSignals(cached.result.signals);
        // Re-evaluate
        handleScanResult(tabId, url, cached.result);
      }
    }
  } catch (e) {
    // API unavailable — local results stand
  }
}

// ─── Badge Update ──────────────────────────────────────────
function updateBadge(tabId, score) {
  const verdict = getVerdict(score);
  const text = score === 0 ? '✓' : score.toString();

  chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color: verdict.color, tabId }).catch(() => {});
  chrome.action.setBadgeTextColor({ color: '#FFFFFF', tabId }).catch(() => {});
}

// ─── Scan History ──────────────────────────────────────────
async function saveScanResult(url, domain, score, signals, verdict) {
  try {
    const data = await chrome.storage.local.get(['tracez_recent_scans']);
    let scans = [];
    if (data.tracez_recent_scans) {
      scans = JSON.parse(data.tracez_recent_scans);
    }

    // Deduplicate by domain (keep latest)
    scans = scans.filter(s => s.domain !== domain);
    scans.unshift({
      url, domain, score, verdict,
      signalCount: signals.length,
      timestamp: Date.now(),
    });

    // Keep last 20
    if (scans.length > 20) scans = scans.slice(0, 20);

    await chrome.storage.local.set({
      tracez_recent_scans: JSON.stringify(scans),
    });

    // Report scan to the server central DB for real-time dashboard log sync
    fetch(`${apiUrl}/api/scan/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        verdict: verdict,
        risk_score: score,
        signals: signals.map(s => ({ layer: s.layer || 'local', signal: s.description || s.name || s.signal, score: s.score || 0 })),
        reputation: {}
      })
    }).catch(e => { /* server offline, ignore */ });

  } catch (e) { /* non-critical */ }
}

// ─── Message Handler ───────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getPageScore') {
    handleGetPageScore(message.url).then(sendResponse);
    return true; // async response
  }

  if (message.type === 'getRecentScans') {
    chrome.storage.local.get(['tracez_recent_scans']).then(data => {
      const scans = data.tracez_recent_scans ? JSON.parse(data.tracez_recent_scans) : [];
      sendResponse({ scans });
    });
    return true;
  }

  if (message.type === 'trustSite') {
    blocklist.addTrust(message.domain).then(() => {
      scanCache.delete(message.domain);
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'getSettings') {
    chrome.storage.local.get(['tracez_settings']).then(data => {
      const settings = data.tracez_settings ? JSON.parse(data.tracez_settings) : {
        enabled: true, apiUrl: 'http://localhost:8000',
        level: 'balanced', notifications: true,
      };
      sendResponse({ settings });
    });
    return true;
  }

  if (message.type === 'updateSettings') {
    const newSettings = message.settings;
    protectionEnabled = newSettings.enabled !== false;
    apiUrl = newSettings.apiUrl || apiUrl;
    chrome.storage.local.set({
      tracez_settings: JSON.stringify(newSettings),
    }).then(() => sendResponse({ success: true }));
    return true;
  }

  if (message.type === 'forceSyncBlocklist') {
    blocklist.syncFromServer(apiUrl).then(success => {
      sendResponse({ success, stats: blocklist.getStats() });
    });
    return true;
  }

  if (message.type === 'domAnalysisResult') {
    handleDOMAnalysis(sender.tab?.id, message.data);
  }
});

async function handleGetPageScore(url) {
  if (!url) return { score: 0, verdict: 'SAFE', signals: [], summary: 'No URL to scan' };

  const domain = extractDomain(url);
  if (!domain) return { score: 0, verdict: 'SAFE', signals: [], summary: 'Invalid URL' };

  // Check cache
  const cached = scanCache.get(domain);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  // Run fresh scan
  const result = await runLocalScan(url, domain);
  scanCache.set(domain, { result, timestamp: Date.now() });
  return result;
}

function handleDOMAnalysis(tabId, data) {
  if (!data || !tabId) return;
  // DOM signals from content script
  const domain = data.domain;
  const cached = scanCache.get(domain);
  if (!cached) return;

  const domSignals = [];
  if (data.passwordFields > 0 && data.crossDomainForm) {
    domSignals.push({
      layer: 'dom', name: 'cross_domain_login',
      description: 'Login form submits to a different domain',
      score: 40, confidence: 0.9,
    });
  }
  if (data.hiddenIframes > 0) {
    domSignals.push({
      layer: 'dom', name: 'hidden_iframes',
      description: `Page contains ${data.hiddenIframes} hidden iframe(s)`,
      score: 20, confidence: 0.7,
    });
  }
  if (data.obfuscatedJS) {
    domSignals.push({
      layer: 'dom', name: 'obfuscated_js',
      description: 'Page contains obfuscated JavaScript',
      score: 15, confidence: 0.6,
    });
  }

  if (domSignals.length > 0) {
    cached.result.signals.push(...domSignals);
    cached.result.score = calculateScore(cached.result.signals);
    cached.result.formatted = formatSignals(cached.result.signals);
    cached.result.summary = generateSummary(cached.result.score, cached.result.signals, domain);
    handleScanResult(tabId, cached.result.url, cached.result);
  }
}

// ─── Blocklist Sync Alarm ──────────────────────────────────
chrome.alarms.create('blocklist-sync', { periodInMinutes: 360 }); // Every 6 hours

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'blocklist-sync') {
    const success = await blocklist.syncFromServer(apiUrl);
    if (success) {
      console.log('[TraceZ] Blocklist synced successfully:', blocklist.getStats());
    }
  }

  if (alarm.name === 'cache-cleanup') {
    const now = Date.now();
    for (const [key, val] of scanCache.entries()) {
      if (now - val.timestamp > CACHE_TTL) scanCache.delete(key);
    }
  }
});

chrome.alarms.create('cache-cleanup', { periodInMinutes: 10 });
