/**
 * SENTINEL APEX — Trial Conversion Engine
 * Tracks trial lifecycle events, computes upgrade readiness score,
 * and triggers conversion actions via revenue-engine Worker API.
 * Version: v175.1.0 | June 2026
 */

const REVENUE_API = 'https://revenue.intel.cyberdudebivash.com';

const TRIAL_EVENT_WEIGHTS = {
  trial_started:          5,
  first_login:            5,
  first_api_call:         20,
  first_report_download:  15,
  siem_connected:         30,
  detection_rule_deployed:25,
  ioc_export:             10,
  stix_bundle_access:     15,
  upgrade_page_visited:   20,
  pricing_page_visited:   15,
  api_100_calls:          25,
  api_500_calls:          35,
};

const TIER_CONVERSION_CTAS = {
  low:    { threshold: 0,  message: 'Explore APEX capabilities →',          url: '/platform-capabilities.html' },
  medium: { threshold: 40, message: 'Your trial is working — upgrade now →', url: '/PAYMENT-GATEWAY.html' },
  high:   { threshold: 70, message: 'You\'ve seen the value. Lock in PRO →', url: '/PAYMENT-GATEWAY.html?urgency=high' },
  urgent: { threshold: 90, message: '🔥 Trial expires soon — upgrade now →', url: '/PAYMENT-GATEWAY.html?urgency=expiring' },
};

class TrialConversionEngine {
  constructor(email, tier = 'PRO') {
    this.email = email;
    this.tier = tier;
    this.events = [];
    this.score = 0;
    this.trialStarted = null;
    this.daysRemaining = 0;
  }

  async init() {
    try {
      const res = await fetch(`${REVENUE_API}/api/customer/portal?email=${encodeURIComponent(this.email)}`);
      if (res.ok) {
        const data = await res.json();
        this.tier = data.customer?.tier || 'PRO';
        if (data.subscription?.trial_ends_at) {
          const end = new Date(data.subscription.trial_ends_at);
          this.daysRemaining = Math.max(0, Math.ceil((end - Date.now()) / 86400000));
        }
      }
    } catch (e) { /* offline — continue */ }
  }

  async trackEvent(eventType, meta = {}) {
    const weight = TRIAL_EVENT_WEIGHTS[eventType] || 5;
    this.score = Math.min(100, this.score + weight);
    this.events.push({ type: eventType, ts: new Date().toISOString(), weight, meta });

    // Persist to revenue engine
    try {
      await fetch(`${REVENUE_API}/api/leads/trial`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: this.email, event: eventType, score: this.score, meta })
      });
    } catch (e) { /* non-blocking */ }

    this._updateInAppCTA();
    this._checkConversionTriggers();
    return this.score;
  }

  async trackAPICall(count = 1) {
    if (count >= 500) await this.trackEvent('api_500_calls');
    else if (count >= 100) await this.trackEvent('api_100_calls');
    else await this.trackEvent('first_api_call');
  }

  getUpgradeReadiness() {
    const urgency = this.daysRemaining <= 2 ? 'urgent' : this.daysRemaining <= 5 ? 'high' : this.score >= 70 ? 'high' : this.score >= 40 ? 'medium' : 'low';
    const cta = TIER_CONVERSION_CTAS[urgency];
    return { score: this.score, urgency, cta, days_remaining: this.daysRemaining, events_count: this.events.length };
  }

  _updateInAppCTA() {
    const readiness = this.getUpgradeReadiness();
    const ctaEls = document.querySelectorAll('[data-apex-upgrade-cta]');
    ctaEls.forEach(el => {
      el.textContent = readiness.cta.message;
      el.href = readiness.cta.url;
      if (readiness.urgency === 'urgent') el.style.background = '#ef4444';
      else if (readiness.urgency === 'high') el.style.background = 'var(--accent,#00ffc6)';
    });
    const scoreEls = document.querySelectorAll('[data-apex-trial-score]');
    scoreEls.forEach(el => el.textContent = this.score);
  }

  _checkConversionTriggers() {
    // Show upgrade modal if score crosses threshold
    if (this.score >= 80 && !sessionStorage.getItem('apex_upgrade_modal_shown')) {
      sessionStorage.setItem('apex_upgrade_modal_shown', '1');
      this._showUpgradeModal();
    }
    // Show expiry banner if 3 days or less
    if (this.daysRemaining <= 3 && this.daysRemaining > 0 && !sessionStorage.getItem('apex_expiry_banner_shown')) {
      sessionStorage.setItem('apex_expiry_banner_shown', '1');
      this._showExpiryBanner();
    }
  }

  _showUpgradeModal() {
    if (document.getElementById('apex-upgrade-modal')) return;
    const modal = document.createElement('div');
    modal.id = 'apex-upgrade-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:#0b1422;border:1px solid rgba(0,255,198,0.3);border-radius:16px;padding:32px;max-width:440px;width:90%;text-align:center;">
        <div style="font-size:36px;margin-bottom:12px;">⬆</div>
        <h3 style="font-size:18px;font-weight:800;color:#e2e8f0;margin-bottom:8px;">You're getting value from SENTINEL APEX</h3>
        <p style="font-size:13px;color:#64748b;margin-bottom:20px;">Your trial score: <strong style="color:#00ffc6;">${this.score}/100</strong>. You've used detection rules, IOC feeds, and API access. Lock in full access before your trial ends.</p>
        <div style="display:flex;gap:10px;justify-content:center;">
          <a href="/PAYMENT-GATEWAY.html?source=upgrade_modal" style="padding:12px 22px;background:#00ffc6;color:#000;font-weight:800;border-radius:8px;text-decoration:none;font-size:13px;">Upgrade Now →</a>
          <button onclick="document.getElementById('apex-upgrade-modal').remove()" style="padding:12px 22px;background:none;border:1px solid rgba(100,116,139,0.3);color:#64748b;border-radius:8px;cursor:pointer;font-size:13px;">Maybe Later</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  }

  _showExpiryBanner() {
    if (document.getElementById('apex-expiry-banner')) return;
    const banner = document.createElement('div');
    banner.id = 'apex-expiry-banner';
    banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:linear-gradient(90deg,#450a0a,#7f1d1d);border-top:1px solid rgba(239,68,68,0.5);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;z-index:9998;flex-wrap:wrap;gap:10px;';
    banner.innerHTML = `
      <span style="color:#fca5a5;font-size:13px;font-weight:700;">⚠ Your trial expires in <strong>${this.daysRemaining} day${this.daysRemaining !== 1 ? 's' : ''}</strong> — your API key will stop working</span>
      <div style="display:flex;gap:8px;align-items:center;">
        <a href="/PAYMENT-GATEWAY.html?source=expiry_banner" style="padding:8px 18px;background:#ef4444;color:#fff;font-weight:800;border-radius:7px;text-decoration:none;font-size:12px;">Renew Now</a>
        <button onclick="document.getElementById('apex-expiry-banner').remove()" style="background:none;border:none;color:#fca5a5;cursor:pointer;font-size:18px;">×</button>
      </div>`;
    document.body.appendChild(banner);
  }
}

// Auto-init on pages with data-apex-trial attribute
if (document.currentScript) {
  document.addEventListener('DOMContentLoaded', () => {
    const trialMeta = document.querySelector('[data-apex-trial-email]');
    if (trialMeta) {
      const engine = new TrialConversionEngine(trialMeta.dataset.apexTrialEmail);
      engine.init().then(() => {
        engine.trackEvent('first_login');
        window.APEX_TRIAL = engine;
      });
    }
  });
}

export { TrialConversionEngine, TRIAL_EVENT_WEIGHTS, TIER_CONVERSION_CTAS };
