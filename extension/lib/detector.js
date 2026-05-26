/**
 * TraceZ — Local URL Detection Engine
 * Offline-capable heuristic analysis for URLs and domains
 */

import { isIPAddress, extractDomain, extractTLD } from './utils.js';

const HIGH_RISK_TLDS = new Set(['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.buzz','.club','.work','.click','.link','.info','.pw','.cc','.ws']);
const SUSPICIOUS_KEYWORDS = ['login','signin','sign-in','verify','secure','account','update','confirm','bank','password','credential','suspend','locked','alert','billing','refund','prize','winner','claim','urgent','expire','unauthorized'];
const URL_SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','shorturl.at','tiny.cc','lnkd.in','db.tt','qr.ae','adf.ly']);
const DANGEROUS_EXTENSIONS = ['.exe','.scr','.bat','.cmd','.com','.pif','.msi','.js','.vbs','.ps1'];

/**
 * Analyze a domain for suspicious characteristics
 * Returns array of signal objects
 */
export function analyzeDomain(domain) {
  const signals = [];
  const clean = domain.toLowerCase().replace(/^www\./, '');
  const tld = extractTLD(clean);
  const parts = clean.split('.');

  // 1. High-risk free TLD
  if (HIGH_RISK_TLDS.has(tld)) {
    signals.push({
      layer: 'domain', name: 'high_risk_tld',
      description: `Uses high-risk free TLD "${tld}"`,
      score: 12, confidence: 0.8,
    });
  }

  // 2. IP address as domain
  if (isIPAddress(clean)) {
    signals.push({
      layer: 'domain', name: 'ip_domain',
      description: 'Uses raw IP address instead of domain name',
      score: 20, confidence: 0.9,
    });
  }

  // 3. Excessive subdomain depth
  if (parts.length > 4) {
    signals.push({
      layer: 'domain', name: 'deep_subdomains',
      description: `Unusually deep subdomain structure (${parts.length} levels)`,
      score: 10, confidence: 0.7,
    });
  }

  // 4. Very long domain
  if (clean.length > 35) {
    signals.push({
      layer: 'domain', name: 'long_domain',
      description: `Unusually long domain name (${clean.length} characters)`,
      score: 8, confidence: 0.6,
    });
  }

  // 5. Contains suspicious keywords
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => clean.includes(kw));
  if (foundKeywords.length > 0) {
    const severity = foundKeywords.length >= 2 ? 15 : 8;
    signals.push({
      layer: 'domain', name: 'suspicious_keywords',
      description: `Domain contains suspicious keywords: ${foundKeywords.join(', ')}`,
      score: severity, confidence: 0.65,
    });
  }

  // 6. Hyphen abuse (more than 2 hyphens)
  const hyphenCount = (clean.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    signals.push({
      layer: 'domain', name: 'hyphen_abuse',
      description: `Excessive hyphens in domain (${hyphenCount})`,
      score: 8, confidence: 0.6,
    });
  }

  // 7. Numeric-heavy domain
  const numCount = (clean.match(/\d/g) || []).length;
  if (numCount > 5 && numCount / clean.length > 0.3) {
    signals.push({
      layer: 'domain', name: 'numeric_heavy',
      description: 'Domain contains excessive numbers',
      score: 10, confidence: 0.6,
    });
  }

  return signals;
}

/**
 * Analyze a URL for suspicious patterns
 * Returns array of signal objects
 */
export function analyzeURL(url) {
  const signals = [];

  try {
    const parsed = new URL(url);

    // 1. Dangerous schemes
    if (['javascript:', 'data:', 'vbscript:'].includes(parsed.protocol)) {
      signals.push({
        layer: 'url_pattern', name: 'dangerous_scheme',
        description: `Uses dangerous URL scheme "${parsed.protocol}"`,
        score: 35, confidence: 1.0,
      });
      return signals; // No further analysis needed
    }

    // 2. Non-HTTPS
    if (parsed.protocol === 'http:' && !parsed.hostname.includes('localhost')) {
      signals.push({
        layer: 'url_pattern', name: 'no_https',
        description: 'Connection is not encrypted (HTTP)',
        score: 5, confidence: 0.9,
      });
    }

    // 3. Excessive URL length
    if (url.length > 200) {
      signals.push({
        layer: 'url_pattern', name: 'long_url',
        description: `Unusually long URL (${url.length} characters)`,
        score: 8, confidence: 0.6,
      });
    }

    // 4. @ symbol in URL (redirect trick)
    if (url.includes('@') && !parsed.username) {
      signals.push({
        layer: 'url_pattern', name: 'at_symbol',
        description: 'URL contains @ symbol (possible redirect trick)',
        score: 20, confidence: 0.85,
      });
    }

    // 5. Base64-encoded segments
    const b64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
    if (b64Pattern.test(parsed.pathname + parsed.search)) {
      signals.push({
        layer: 'url_pattern', name: 'base64_payload',
        description: 'URL contains possible Base64-encoded payload',
        score: 12, confidence: 0.7,
      });
    }

    // 6. Suspicious path keywords on non-safe domains
    const pathLower = parsed.pathname.toLowerCase();
    const suspiciousPaths = ['/login', '/signin', '/verify', '/confirm', '/secure', '/account', '/password', '/auth'];
    const hasPath = suspiciousPaths.some(p => pathLower.includes(p));
    if (hasPath) {
      signals.push({
        layer: 'url_pattern', name: 'suspicious_path',
        description: 'URL path contains authentication-related keywords',
        score: 5, confidence: 0.5,
      });
    }

    // 7. Excessive query parameters
    const paramCount = parsed.searchParams.size;
    if (paramCount > 6) {
      signals.push({
        layer: 'url_pattern', name: 'many_params',
        description: `Excessive query parameters (${paramCount})`,
        score: 6, confidence: 0.5,
      });
    }

    // 8. URL shortener
    if (URL_SHORTENERS.has(parsed.hostname)) {
      signals.push({
        layer: 'url_pattern', name: 'url_shortener',
        description: 'URL uses a shortener service (destination unknown)',
        score: 8, confidence: 0.7,
      });
    }

    // 9. Double extension (e.g., .pdf.exe)
    const pathParts = parsed.pathname.split('/').pop() || '';
    const dotParts = pathParts.split('.');
    if (dotParts.length > 2) {
      const lastExt = '.' + dotParts[dotParts.length - 1].toLowerCase();
      if (DANGEROUS_EXTENSIONS.includes(lastExt)) {
        signals.push({
          layer: 'url_pattern', name: 'double_extension',
          description: `File uses double extension trick (ends with ${lastExt})`,
          score: 25, confidence: 0.9,
        });
      }
    }

    // 10. Port number in URL (non-standard)
    if (parsed.port && !['80', '443', '8080', '8443'].includes(parsed.port)) {
      signals.push({
        layer: 'url_pattern', name: 'unusual_port',
        description: `Uses non-standard port ${parsed.port}`,
        score: 5, confidence: 0.5,
      });
    }

  } catch (e) {
    signals.push({
      layer: 'url_pattern', name: 'invalid_url',
      description: 'URL could not be parsed',
      score: 15, confidence: 0.8,
    });
  }

  return signals;
}
