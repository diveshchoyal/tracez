/**
 * TraceZ — Multi-Signal Risk Scorer
 * Weighted scoring engine with verdict classification
 */

const LAYER_WEIGHTS = {
  blocklist: 10,
  homoglyph: 5,
  domain: 3,
  url_pattern: 2,
  reputation: 4,
  dom: 3,
};

const VERDICTS = [
  { min: 0,  max: 25,  level: 'SAFE',      label: 'Safe',      color: '#10B981', bgColor: '#ECFDF5', action: 'allow' },
  { min: 26, max: 55,  level: 'CAUTION',    label: 'Caution',   color: '#F59E0B', bgColor: '#FFFBEB', action: 'warn' },
  { min: 56, max: 80,  level: 'WARNING',    label: 'Warning',   color: '#F97316', bgColor: '#FFF7ED', action: 'banner' },
  { min: 81, max: 100, level: 'DANGEROUS',  label: 'Dangerous', color: '#EF4444', bgColor: '#FEF2F2', action: 'block' },
];

/**
 * Calculate weighted risk score from an array of signals
 * Each signal: { layer, name, description, score, confidence }
 * Returns 0-100
 */
export function calculateScore(signals) {
  if (!signals || signals.length === 0) return 0;

  let totalWeightedScore = 0;
  let totalWeight = 0;

  // Group signals by layer
  const layerSignals = {};
  for (const s of signals) {
    const layer = s.layer || 'unknown';
    if (!layerSignals[layer]) layerSignals[layer] = [];
    layerSignals[layer].push(s);
  }

  // Calculate weighted sum
  for (const [layer, sigs] of Object.entries(layerSignals)) {
    const weight = LAYER_WEIGHTS[layer] || 1;
    // Sum scores within this layer, applying confidence
    let layerScore = 0;
    for (const s of sigs) {
      layerScore += s.score * (s.confidence || 1.0);
    }
    totalWeightedScore += layerScore * weight;
    totalWeight += weight;
  }

  // Normalize: divide by total weight, but cap at 100
  const raw = totalWeight > 0 ? totalWeightedScore / totalWeight : 0;
  return Math.min(100, Math.round(raw));
}

/**
 * Get verdict classification for a score
 * Returns { level, label, color, bgColor, action }
 */
export function getVerdict(score) {
  for (const v of VERDICTS) {
    if (score >= v.min && score <= v.max) {
      return { ...v, score };
    }
  }
  return { ...VERDICTS[VERDICTS.length - 1], score };
}

/**
 * Format signals into human-readable descriptions
 * Returns array of { icon, text, severity }
 */
export function formatSignals(signals) {
  if (!signals || signals.length === 0) {
    return [{ icon: '✓', text: 'No threats detected', severity: 'safe' }];
  }

  return signals.map(s => {
    let icon = '✓';
    let severity = 'safe';

    if (s.score >= 20) {
      icon = '✗';
      severity = 'danger';
    } else if (s.score >= 8) {
      icon = '⚠';
      severity = 'warning';
    }

    return { icon, text: s.description, severity, layer: s.layer, score: s.score };
  }).sort((a, b) => b.score - a.score);
}

/**
 * Generate a summary recommendation string
 */
export function generateSummary(score, signals, domain) {
  const verdict = getVerdict(score);

  if (verdict.level === 'SAFE') {
    return `${domain} appears safe. No suspicious indicators were detected.`;
  }

  const topSignals = signals
    .sort((a, b) => b.score - a.score)
    .slice(0, 2)
    .map(s => s.description.toLowerCase());

  if (verdict.level === 'DANGEROUS') {
    return `${domain} is likely dangerous: ${topSignals.join(', and ')}. Do not enter any personal information.`;
  }

  return `${domain} shows some concerns: ${topSignals.join(', and ')}. Proceed with caution.`;
}
