/**
 * TraceZ — Local Blocklist Manager
 * Manages phishing blocklists and safe domain allowlists with chrome.storage sync
 */

const BUILTIN_PHISHING = new Set([
  'login-microsoftonline.tk','secure-paypal-verify.ml','apple-id-confirm.ga',
  'netflix-billing-update.cf','amazon-prime-refund.gq','facebook-security-alert.xyz',
  'google-account-verify.tk','chase-bank-alert.ml','wellsfargo-secure.ga',
  'bankofamerica-login.cf','instagram-verify-account.gq','twitter-suspend-appeal.xyz',
  'linkedin-job-offer.tk','dropbox-shared-file.ml','zoom-meeting-invite.ga',
  'outlook-password-reset.cf','icloud-unlock-device.gq','whatsapp-verify-number.xyz',
  'steam-trade-offer.tk','discord-nitro-gift.ml','paypal-resolution-center.ga',
  'ebay-item-dispute.cf','usps-package-tracking.gq','fedex-delivery-failed.xyz',
  'dhl-customs-payment.tk','irs-tax-refund.ml','coinbase-verify-identity.gq',
  'binance-withdraw-confirm.xyz','crypto-airdrop-claim.tk','metamask-security-update.ga',
  'docusign-document-review.cf','microsoft365-license.xyz','office365-password-expire.tk',
  'shopify-store-suspended.xyz','stripe-payout-failed.tk','venmo-payment-pending.ga',
  'cashapp-money-received.cf','robinhood-account-locked.xyz','spotify-payment-failed.gq',
  'hulu-subscription-expired.cf','tiktok-creator-fund.ga','snapchat-account-unlock.cf',
  'youtube-copyright-strike.tk','craigslist-posting-flagged.tk',
  'social-security-alert.ga','medicare-benefits-update.cf',
  'att-billing-overdue.xyz','verizon-account-suspended.tk',
  'tmobile-free-upgrade.ml','comcast-service-interrupt.ga',
]);

const SAFE_DOMAINS = new Set([
  'google.com','youtube.com','facebook.com','amazon.com','wikipedia.org',
  'twitter.com','instagram.com','linkedin.com','reddit.com','netflix.com',
  'microsoft.com','apple.com','github.com','stackoverflow.com','medium.com',
  'wordpress.com','pinterest.com','paypal.com','ebay.com','spotify.com',
  'twitch.tv','discord.com','zoom.us','dropbox.com','slack.com',
  'notion.so','figma.com','canva.com','adobe.com','cloudflare.com',
  'chase.com','bankofamerica.com','wellsfargo.com','citi.com',
  'capitalone.com','americanexpress.com','discover.com',
  'nytimes.com','washingtonpost.com','bbc.com','cnn.com','reuters.com',
  'gmail.com','outlook.com','yahoo.com','protonmail.com',
  'office.com','live.com','icloud.com',
  'accounts.google.com','myaccount.google.com','mail.google.com',
  'drive.google.com','docs.google.com','maps.google.com',
  'play.google.com','whatsapp.com','web.whatsapp.com','signal.org',
  'telegram.org','messenger.com','skype.com','teams.microsoft.com',
  'shopify.com','squarespace.com','wix.com','godaddy.com',
  'stripe.com','square.com','venmo.com','cashapp.com',
  'coinbase.com','binance.com','kraken.com','robinhood.com',
  'fidelity.com','schwab.com','vanguard.com',
  'hulu.com','disneyplus.com','hbomax.com',
  'tiktok.com','snapchat.com','indeed.com','glassdoor.com',
  'coursera.org','udemy.com','edx.org','khanacademy.org',
  'usps.com','ups.com','fedex.com','dhl.com',
  'walmart.com','target.com','bestbuy.com','costco.com',
  'homedepot.com','lowes.com','att.com','verizon.com','t-mobile.com',
  'irs.gov','ssa.gov','usa.gov','cdc.gov','nih.gov',
  'archive.org','mozilla.org','npmjs.com','pypi.org',
  'gitlab.com','bitbucket.org','codepen.io','replit.com',
]);

export class BlocklistManager {
  constructor() {
    this.phishingDomains = new Set(BUILTIN_PHISHING);
    this.safeDomains = new Set(SAFE_DOMAINS);
    this.customBlocked = new Map(); // domain -> reason
    this.trustedDomains = new Set();
    this.version = '1.0.0';
    this.lastSynced = null;
  }

  async load() {
    try {
      const data = await chrome.storage.local.get([
        'tracez_custom_blocked',
        'tracez_trusted',
        'tracez_extra_phishing',
        'tracez_blocklist_version',
        'tracez_last_synced',
      ]);

      if (data.tracez_custom_blocked) {
        const entries = JSON.parse(data.tracez_custom_blocked);
        for (const [domain, reason] of entries) {
          this.customBlocked.set(domain, reason);
        }
      }
      if (data.tracez_trusted) {
        for (const d of JSON.parse(data.tracez_trusted)) {
          this.trustedDomains.add(d);
        }
      }
      if (data.tracez_extra_phishing) {
        for (const d of JSON.parse(data.tracez_extra_phishing)) {
          this.phishingDomains.add(d);
        }
      }
      if (data.tracez_blocklist_version) {
        this.version = data.tracez_blocklist_version;
      }
      if (data.tracez_last_synced) {
        this.lastSynced = data.tracez_last_synced;
      }
    } catch (e) {
      console.warn('[TraceZ] Failed to load blocklist from storage:', e.message);
    }
  }

  async save() {
    try {
      await chrome.storage.local.set({
        tracez_custom_blocked: JSON.stringify([...this.customBlocked.entries()]),
        tracez_trusted: JSON.stringify([...this.trustedDomains]),
        tracez_blocklist_version: this.version,
        tracez_last_synced: this.lastSynced,
      });
    } catch (e) {
      console.warn('[TraceZ] Failed to save blocklist:', e.message);
    }
  }

  checkDomain(domain) {
    const clean = domain.toLowerCase().replace(/^www\./, '');

    if (this.trustedDomains.has(clean)) {
      return { blocked: false, reason: 'User trusted' };
    }
    if (this.customBlocked.has(clean)) {
      return { blocked: true, reason: this.customBlocked.get(clean) };
    }
    if (this.phishingDomains.has(clean)) {
      return { blocked: true, reason: 'Known phishing domain' };
    }
    return { blocked: false, reason: null };
  }

  isSafe(domain) {
    const clean = domain.toLowerCase().replace(/^www\./, '');
    // Check exact match and parent domain
    if (this.safeDomains.has(clean)) return true;
    const parts = clean.split('.');
    if (parts.length > 2) {
      const parent = parts.slice(-2).join('.');
      if (this.safeDomains.has(parent)) return true;
    }
    return false;
  }

  async addCustomBlock(domain, reason = 'User reported') {
    const clean = domain.toLowerCase().replace(/^www\./, '');
    this.customBlocked.set(clean, reason);
    this.trustedDomains.delete(clean);
    await this.save();
  }

  async addTrust(domain) {
    const clean = domain.toLowerCase().replace(/^www\./, '');
    this.trustedDomains.add(clean);
    this.customBlocked.delete(clean);
    await this.save();
  }

  async syncFromServer(apiUrl) {
    try {
      const resp = await fetch(`${apiUrl}/api/blocklist/download`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      if (!resp.ok) return false;

      const data = await resp.json();
      if (data.domains && Array.isArray(data.domains)) {
        const extra = [];
        for (const d of data.domains) {
          if (!this.phishingDomains.has(d)) {
            this.phishingDomains.add(d);
            extra.push(d);
          }
        }
        if (extra.length > 0) {
          await chrome.storage.local.set({
            tracez_extra_phishing: JSON.stringify(extra),
          });
        }
        this.version = data.version || this.version;
        this.lastSynced = new Date().toISOString();
        await this.save();
        return true;
      }
    } catch (e) {
      console.warn('[TraceZ] Blocklist sync failed:', e.message);
    }
    return false;
  }

  getVersion() {
    return this.version;
  }

  getStats() {
    return {
      phishing: this.phishingDomains.size,
      safe: this.safeDomains.size,
      customBlocked: this.customBlocked.size,
      trusted: this.trustedDomains.size,
      lastSynced: this.lastSynced,
    };
  }
}
