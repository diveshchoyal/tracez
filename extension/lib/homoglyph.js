/**
 * TraceZ — Homoglyph / IDN Attack Detector
 * Detects Unicode confusable characters and brand impersonation
 */

// Cyrillic → Latin and Greek → Latin confusable character mappings
const CONFUSABLES = new Map([
  // Cyrillic
  ['а', 'a'], ['с', 'c'], ['е', 'e'], ['о', 'o'], ['р', 'p'],
  ['х', 'x'], ['у', 'y'], ['А', 'A'], ['В', 'B'], ['С', 'C'],
  ['Е', 'E'], ['Н', 'H'], ['К', 'K'], ['М', 'M'], ['О', 'O'],
  ['Р', 'P'], ['Т', 'T'], ['Х', 'X'], ['і', 'i'], ['ј', 'j'],
  ['ѕ', 's'], ['ԁ', 'd'], ['ԛ', 'q'], ['ԝ', 'w'], ['ɡ', 'g'],
  // Greek
  ['α', 'a'], ['β', 'b'], ['γ', 'y'], ['ε', 'e'], ['η', 'n'],
  ['ι', 'i'], ['κ', 'k'], ['ν', 'v'], ['ο', 'o'], ['ρ', 'p'],
  ['τ', 't'], ['υ', 'u'], ['χ', 'x'], ['ω', 'w'],
  // Common substitutions
  ['ɑ', 'a'], ['ℓ', 'l'], ['ꞁ', 'l'], ['ɩ', 'i'], ['ŋ', 'n'],
  ['ɴ', 'n'], ['ʀ', 'r'], ['ꜱ', 's'], ['ʙ', 'b'],
  // Numeric look-alikes
  ['０', '0'], ['１', '1'], ['２', '2'], ['３', '3'],
]);

const TOP_BRANDS = [
  'google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple',
  'netflix', 'github', 'instagram', 'twitter', 'linkedin', 'chase',
  'bankofamerica', 'wellsfargo', 'dropbox', 'zoom', 'spotify',
  'coinbase', 'binance', 'steam', 'discord', 'whatsapp', 'telegram',
  'yahoo', 'outlook', 'icloud', 'ebay', 'walmart', 'target',
];

/**
 * Replace confusable Unicode characters with their ASCII equivalents
 */
export function normalizeHomoglyphs(str) {
  let normalized = '';
  for (const char of str) {
    normalized += CONFUSABLES.get(char) || char;
  }
  return normalized;
}

/**
 * Detect if a domain uses homoglyph characters
 * Returns { hasHomoglyphs, original, normalized, confusedChars }
 */
export function detectHomoglyphAttack(domain) {
  const normalized = normalizeHomoglyphs(domain);
  const confusedChars = [];

  for (let i = 0; i < domain.length; i++) {
    if (CONFUSABLES.has(domain[i])) {
      confusedChars.push({ position: i, original: domain[i], replacement: CONFUSABLES.get(domain[i]) });
    }
  }

  return {
    hasHomoglyphs: confusedChars.length > 0,
    original: domain,
    normalized,
    confusedChars,
  };
}

/**
 * Check if domain uses Punycode (internationalized domain name)
 */
export function checkPunycode(domain) {
  const parts = domain.split('.');
  const punycoded = parts.filter(p => p.startsWith('xn--'));
  return {
    isPunycode: punycoded.length > 0,
    punycodeParts: punycoded,
  };
}

/**
 * Compute Levenshtein edit distance between two strings
 */
export function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Check if a domain mimics a known brand
 * Returns { isMimic, brand, method, distance } or { isMimic: false }
 */
export function findBrandMimic(domain) {
  // Strip TLD and www
  let clean = domain.toLowerCase();
  if (clean.startsWith('www.')) clean = clean.slice(4);
  const dotIndex = clean.lastIndexOf('.');
  const domainBase = dotIndex > 0 ? clean.slice(0, dotIndex) : clean;
  // Also remove subdomains — take last part before TLD
  const parts = domainBase.split('.');
  const mainPart = parts[parts.length - 1];

  // Normalize homoglyphs first
  const normalizedMain = normalizeHomoglyphs(mainPart);
  const normalizedFull = normalizeHomoglyphs(domainBase);

  for (const brand of TOP_BRANDS) {
    // Exact match after normalization (homoglyph attack)
    if (normalizedMain === brand && mainPart !== brand) {
      return { isMimic: true, brand, method: 'homoglyph', distance: 0 };
    }

    // Levenshtein distance check (typosquat)
    const dist = levenshteinDistance(normalizedMain, brand);
    if (dist > 0 && dist <= 2 && normalizedMain !== brand) {
      return { isMimic: true, brand, method: 'typosquat', distance: dist };
    }

    // Brand name embedded in subdomain
    if (normalizedFull.includes(brand) && normalizedMain !== brand) {
      return { isMimic: true, brand, method: 'subdomain_abuse', distance: 0 };
    }
  }

  return { isMimic: false };
}
