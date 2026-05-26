/**
 * TraceZ — Shared Utilities Module
 * Common helper functions used across the extension.
 */

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} str - Raw string to escape.
 * @returns {string} Escaped HTML-safe string.
 */
export function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Extract the domain (hostname) from a URL string.
 * @param {string} url - Full URL string.
 * @returns {string|null} Domain or null if parsing fails.
 */
export function extractDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Extract the top-level domain from a domain string.
 * @param {string} domain - Domain name (e.g. "www.example.com").
 * @returns {string} TLD (e.g. "com").
 */
export function extractTLD(domain) {
  if (!domain || typeof domain !== 'string') return '';
  const parts = domain.split('.');
  return parts.length > 0 ? parts[parts.length - 1] : '';
}

/**
 * Check if a string is an IP address (IPv4 or IPv6).
 * @param {string} str - String to check.
 * @returns {boolean} True if the string is an IP address.
 */
export function isIPAddress(str) {
  if (!str || typeof str !== 'string') return false;

  // IPv4: four decimal octets (0-255) separated by dots
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  if (ipv4Regex.test(str)) return true;

  // IPv6: eight groups of 4 hex digits, or compressed with ::
  // Also match bracket-wrapped IPv6 used in URLs like [::1]
  const bare = str.replace(/^\[|\]$/g, '');
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:$|^(?:[0-9a-fA-F]{1,4}:){1}:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){2}:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){3}:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){4}:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){5}:[0-9a-fA-F]{1,4}$|^::$|^::1$/;
  if (ipv6Regex.test(bare)) return true;

  return false;
}

/**
 * Format a timestamp into a human-readable "time ago" string.
 * @param {number} timestamp - Unix timestamp in milliseconds.
 * @returns {string} Human-readable relative time (e.g., "5 minutes ago").
 */
export function formatTimeAgo(timestamp) {
  const now = Date.now();
  const diffMs = now - timestamp;

  if (diffMs < 0) return 'just now';

  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const weeks = Math.floor(days / 7);
  const months = Math.floor(days / 30);
  const years = Math.floor(days / 365);

  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds} second${seconds !== 1 ? 's' : ''} ago`;
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
  if (days < 7) return `${days} day${days !== 1 ? 's' : ''} ago`;
  if (weeks < 5) return `${weeks} week${weeks !== 1 ? 's' : ''} ago`;
  if (months < 12) return `${months} month${months !== 1 ? 's' : ''} ago`;
  return `${years} year${years !== 1 ? 's' : ''} ago`;
}

/**
 * Generate a simple unique ID using timestamp and random component.
 * @returns {string} Unique identifier string.
 */
export function generateId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `${timestamp}-${random}`;
}

/**
 * Create a debounced version of a function that delays invocation.
 * @param {Function} fn - Function to debounce.
 * @param {number} ms - Debounce delay in milliseconds.
 * @returns {Function} Debounced function with a .cancel() method.
 */
export function debounce(fn, ms) {
  let timerId = null;

  const debounced = function (...args) {
    if (timerId !== null) {
      clearTimeout(timerId);
    }
    timerId = setTimeout(() => {
      timerId = null;
      fn.apply(this, args);
    }, ms);
  };

  debounced.cancel = function () {
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
  };

  return debounced;
}
