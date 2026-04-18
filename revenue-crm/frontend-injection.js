// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Frontend Revenue System v123.0.0
// Inject this as a <script> block in index.html AFTER the auth engine.
// Handles: lead capture gate · trial modal · IOC upgrade CTA · usage alerts
// =============================================================================

(function CDB_REVENUE_SYSTEM() {
  "use strict";

  const REVENUE_API = "https://revenue.intel.cyberdudebivash.com";
  const INTEL_API   = "https://intel.cyberdudebivash.com";

  // ─── Lead Capture Gate ─────────────────────────────────────────────────────
  // Intercepts: full report access, IOC export, STIX download
  // Captures email BEFORE showing locked content
  window.cdbLeadGate = async function(context, onSuccess) {
    // If already logged in — skip gate
    if (window.cdbAuth?.isLoggedIn()) { onSuccess && onSuccess(); return; }

    // If already captured this session — skip gate
    const captured = sessionStorage.getItem("cdb_lead_captured");
    if (captured) { onSuccess && onSuccess(); return; }

    // Show lead capture modal
    window.cdbOpenLeadModal(context, async function(email, company, role) {
      try {
        await fetch(REVENUE_API + "/api/leads/capture", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, company, role, context, source: "web_gate" }),
        });
        sessionStorage.setItem("cdb_lead_captured", "1");
        sessionStorage.setItem("cdb_lead_email", email);
        onSuccess && onSuccess();
      } catch {
        // On network failure — let them through (don't block)
        onSuccess && onSuccess();
      }
    });
  };

  // ─── Lead Capture Modal ────────────────────────────────────────────────────
  window.cdbOpenLeadModal = function(context, onCapture) {
    const modal = document.getElementById("cdb-lead-modal");
    if (!modal) { _injectLeadModal(); }
    const m = document.getElementById("cdb-lead-modal");
    if (!m) return;

    // Set context-specific messaging
    const ctxMsg = {
      ioc_access:    { title: "Unlock IOC Intelligence",      sub: "Enter your details to access full indicator arrays." },
      stix_request:  { title: "Access STIX Bundle",           sub: "STIX export requires a free account." },
      report_full:   { title: "Read Full Intel Report",       sub: "Enter your work email to continue reading." },
      generic:       { title: "Access Full Intel",            sub: "Enter your details to unlock this content." },
    };
    const ctx = ctxMsg[context] || ctxMsg.generic;
    const titleEl = document.getElementById("cdb-lead-title");
    const subEl   = document.getElementById("cdb-lead-sub");
    if (titleEl) titleEl.textContent = ctx.title;
    if (subEl)   subEl.textContent   = ctx.sub;

    m.style.display = "flex";
    setTimeout(() => m.classList.add("open"), 10);
    m._onCapture = onCapture;
    document.getElementById("cdb-lead-email-input")?.focus();
  };

  window.cdbCloseLeadModal = function() {
    const m = document.getElementById("cdb-lead-modal");
    if (!m) return;
    m.classList.remove("open");
    setTimeout(() => { m.style.display = "none"; }, 300);
  };

  window.cdbSubmitLead = async function() {
    const emailEl   = document.getElementById("cdb-lead-email-input");
    const companyEl = document.getElementById("cdb-lead-company-input");
    const roleEl    = document.getElementById("cdb-lead-role-input");
    const btnEl     = document.getElementById("cdb-lead-submit-btn");
    const errEl     = document.getElementById("cdb-lead-error");
    const m         = document.getElementById("cdb-lead-modal");

    const email   = emailEl?.value?.trim() || "";
    const company = companyEl?.value?.trim() || "";
    const role    = roleEl?.value?.trim() || "";

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (errEl) errEl.textContent = "Valid work email required.";
      return;
    }

    if (btnEl) { btnEl.disabled = true; btnEl.textContent = "UNLOCKING..."; }
    if (errEl) errEl.textContent = "";

    if (m?._onCapture) await m._onCapture(email, company, role);

    window.cdbCloseLeadModal();
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = "UNLOCK ACCESS →"; }
  };

  // ─── Trial Activation Modal ────────────────────────────────────────────────
  window.cdbOpenTrialModal = function() {
    const m = document.getElementById("cdb-trial-modal");
    if (!m) { _injectTrialModal(); }
    const modal = document.getElementById("cdb-trial-modal");
    if (!modal) return;
    modal.style.display = "flex";
    setTimeout(() => modal.classList.add("open"), 10);
    document.getElementById("cdb-trial-email")?.focus();
  };

  window.cdbCloseTrialModal = function() {
    const m = document.getElementById("cdb-trial-modal");
    if (!m) return;
    m.classList.remove("open");
    setTimeout(() => { m.style.display = "none"; }, 300);
  };

  window.cdbActivateTrial = async function() {
    const email   = document.getElementById("cdb-trial-email")?.value?.trim() || "";
    const name    = document.getElementById("cdb-trial-name")?.value?.trim() || "";
    const company = document.getElementById("cdb-trial-company")?.value?.trim() || "";
    const btnEl   = document.getElementById("cdb-trial-btn");
    const errEl   = document.getElementById("cdb-trial-error");
    const resEl   = document.getElementById("cdb-trial-result");

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (errEl) errEl.textContent = "Valid email required.";
      return;
    }

    if (btnEl) { btnEl.disabled = true; btnEl.textContent = "ACTIVATING..."; }
    if (errEl) errEl.textContent = "";

    try {
      const res = await fetch(REVENUE_API + "/api/leads/trial", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, name, company }),
      });
      const data = await res.json();

      if (res.ok && data.api_key) {
        if (resEl) resEl.innerHTML = `
          <div style="background:rgba(0,212,170,0.08);border:1px solid rgba(0,212,170,0.3);border-radius:8px;padding:16px;margin-top:16px;">
            <div style="color:#00d4aa;font-weight:900;font-size:13px;margin-bottom:8px;">✅ TRIAL ACTIVATED — 7 DAYS PRO ACCESS</div>
            <div style="font-size:11px;color:#4a6a8a;margin-bottom:6px;">API KEY (save this — shown only once):</div>
            <code style="display:block;background:rgba(0,0,0,0.4);padding:10px;border-radius:5px;font-size:11px;word-break:break-all;color:#e0f0ff;">${data.api_key}</code>
            <div style="font-size:11px;color:#4a6a8a;margin-top:8px;">Expires: ${data.expires_at?.slice(0,10) || "7 days"}</div>
          </div>
          <a href="https://intel.cyberdudebivash.com/docs" target="_blank"
             style="display:block;margin-top:12px;text-align:center;font-size:12px;color:#00d4aa;">View API Docs →</a>`;
        sessionStorage.setItem("cdb_trial_active", "1");
      } else {
        if (errEl) errEl.textContent = data.message || data.error || "Activation failed. Try again.";
        if (data.upgrade) {
          if (errEl) errEl.innerHTML += `&nbsp;<a href="${data.upgrade}" style="color:#00d4aa;">Upgrade →</a>`;
        }
      }
    } catch {
      if (errEl) errEl.textContent = "Network error. Please try again.";
    }

    if (btnEl) { btnEl.disabled = false; btnEl.textContent = "ACTIVATE TRIAL"; }
  };

  // ─── IOC Upgrade CTA (injected on blocked IOC access) ─────────────────────
  window.cdbShowIOCUpgrade = function(iocCount, tier) {
    const modal = document.getElementById("upgrade-modal-overlay");
    if (modal && window.openUpgradeModal) {
      window.openUpgradeModal("pro");
    }
    // Also track the event for automation
    _trackUpgradeTrigger("ioc_access", tier);
  };

  // ─── STIX Upgrade CTA ──────────────────────────────────────────────────────
  window.cdbShowSTIXUpgrade = function(tier) {
    const targetPlan = (tier || "free") === "free" ? "pro" : "enterprise";
    if (window.openUpgradeModal) window.openUpgradeModal(targetPlan);
    _trackUpgradeTrigger("stix_request", tier);
  };

  // ─── Usage Alert Banner ────────────────────────────────────────────────────
  window.cdbShowUsageAlert = function(used, limit, tier) {
    const banner = document.getElementById("cdb-usage-banner");
    if (banner) {
      banner.style.display = "block";
      banner.innerHTML = `
        <span style="color:#ff8c00;font-weight:700;">⚡ API USAGE: ${used}/${limit} calls used today</span>
        <a href="https://intel.cyberdudebivash.com/upgrade?plan=pro" target="_blank"
           style="margin-left:16px;color:#00d4aa;font-weight:700;text-decoration:none;">
           Upgrade for 5,000/day →</a>`;
    }
    _trackUpgradeTrigger("approaching_limit", tier);
  };

  // ─── Demo Request Form Handler ────────────────────────────────────────────
  window.cdbRequestDemo = async function(company, email, useCase, teamSize) {
    try {
      const res = await fetch(REVENUE_API + "/api/demo/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company, email, use_case: useCase, team_size: teamSize, name: email }),
      });
      const data = await res.json();
      return data;
    } catch {
      return { error: "network_error" };
    }
  };

  // ─── Automation trigger (called by backend events mirrored to frontend) ────
  window.cdbFireAutomation = async function(trigger, context) {
    const email = sessionStorage.getItem("cdb_lead_email")
                || window.cdbAuth?.getUser()?.email
                || "";
    if (!email) return;
    try {
      await fetch(REVENUE_API + "/api/automation/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trigger, email, context }),
      });
    } catch {}
  };

  // ─── Revenue Event Tracker ─────────────────────────────────────────────────
  async function _trackUpgradeTrigger(context, tier) {
    try {
      await fetch(INTEL_API + "/api/revenue/event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: `upgrade_trigger:${context}`, tier, ts: new Date().toISOString() }),
      });
    } catch {}
  }

  // ─────────────────────────────────────────────────────────────────────────
  // MODAL INJECTION (no external dependencies)
  // ─────────────────────────────────────────────────────────────────────────

  function _injectLeadModal() {
    if (document.getElementById("cdb-lead-modal")) return;
    const el = document.createElement("div");
    el.id = "cdb-lead-modal";
    el.onclick = function(e) { if (e.target === el) window.cdbCloseLeadModal(); };
    el.style.cssText = "display:none;position:fixed;inset:0;background:rgba(0,0,0,0.87);z-index:10001;align-items:center;justify-content:center;transition:opacity .3s;opacity:0;";
    el.innerHTML = `
      <style>
        #cdb-lead-modal.open { opacity:1!important; }
        #cdb-lead-box { transform:translateY(20px);transition:transform .3s; }
        #cdb-lead-modal.open #cdb-lead-box { transform:translateY(0); }
        #cdb-lead-box input { width:100%;padding:10px 14px;background:rgba(0,0,0,0.45);border:1px solid rgba(0,212,170,0.2);
          border-radius:7px;color:#e0f0ff;font-size:13px;outline:none;font-family:inherit;margin-bottom:12px; }
        #cdb-lead-box input:focus { border-color:rgba(0,212,170,0.5); }
      </style>
      <div id="cdb-lead-box" style="background:#071428;border:1px solid rgba(0,212,170,0.3);border-radius:14px;
        width:100%;max-width:400px;padding:28px;position:relative;box-shadow:0 0 60px rgba(0,212,170,0.12);">
        <button onclick="cdbCloseLeadModal()"
          style="position:absolute;top:12px;right:14px;background:none;border:none;color:#4a6a8a;font-size:18px;cursor:pointer;">✕</button>
        <div style="text-align:center;margin-bottom:20px;">
          <div style="font-family:monospace;font-size:9px;color:#00d4aa;letter-spacing:3px;text-transform:uppercase;margin-bottom:4px;">
            SENTINEL APEX INTELLIGENCE GATE</div>
          <div id="cdb-lead-title" style="font-size:20px;font-weight:900;color:#fff;margin-bottom:4px;">Unlock Full Intel</div>
          <div id="cdb-lead-sub" style="font-size:12px;color:#4a6a8a;">Enter your details to access this content.</div>
        </div>
        <input id="cdb-lead-email-input"   type="email"  placeholder="Work email (required)" />
        <input id="cdb-lead-company-input" type="text"   placeholder="Company name" />
        <input id="cdb-lead-role-input"    type="text"   placeholder="Your role (e.g. CISO, SOC Analyst)" />
        <button id="cdb-lead-submit-btn" onclick="cdbSubmitLead()"
          style="width:100%;padding:12px;background:linear-gradient(135deg,#00d4aa,#0099cc);border:none;border-radius:8px;
          color:#020811;font-family:monospace;font-size:12px;font-weight:900;letter-spacing:2px;cursor:pointer;text-transform:uppercase;">
          UNLOCK ACCESS →</button>
        <div id="cdb-lead-error" style="margin-top:8px;min-height:18px;font-size:11px;color:#ff4466;font-family:monospace;text-align:center;"></div>
        <div style="margin-top:14px;text-align:center;font-size:11px;color:#4a6a8a;">
          Or <a href="#" onclick="event.preventDefault();cdbCloseLeadModal();cdbOpenTrialModal();"
            style="color:#00d4aa;text-decoration:none;font-weight:700;">start a 7-day Pro trial →</a>
        </div>
      </div>`;
    document.body.appendChild(el);
  }

  function _injectTrialModal() {
    if (document.getElementById("cdb-trial-modal")) return;
    const el = document.createElement("div");
    el.id = "cdb-trial-modal";
    el.onclick = function(e) { if (e.target === el) window.cdbCloseTrialModal(); };
    el.style.cssText = "display:none;position:fixed;inset:0;background:rgba(0,0,0,0.87);z-index:10002;align-items:center;justify-content:center;transition:opacity .3s;opacity:0;";
    el.innerHTML = `
      <style>
        #cdb-trial-modal.open { opacity:1!important; }
        #cdb-trial-box { transform:translateY(20px);transition:transform .3s; }
        #cdb-trial-modal.open #cdb-trial-box { transform:translateY(0); }
        #cdb-trial-box input { width:100%;padding:10px 14px;background:rgba(0,0,0,0.45);border:1px solid rgba(0,212,170,0.2);
          border-radius:7px;color:#e0f0ff;font-size:13px;outline:none;font-family:inherit;margin-bottom:12px; }
        #cdb-trial-box input:focus { border-color:rgba(0,212,170,0.5); }
      </style>
      <div id="cdb-trial-box" style="background:#071428;border:1px solid rgba(0,212,170,0.3);border-radius:14px;
        width:100%;max-width:420px;padding:32px;position:relative;box-shadow:0 0 60px rgba(0,212,170,0.15);">
        <button onclick="cdbCloseTrialModal()"
          style="position:absolute;top:12px;right:14px;background:none;border:none;color:#4a6a8a;font-size:18px;cursor:pointer;">✕</button>
        <div style="text-align:center;margin-bottom:24px;">
          <div style="font-family:monospace;font-size:9px;color:#00d4aa;letter-spacing:3px;text-transform:uppercase;margin-bottom:4px;">
            7-DAY FREE TRIAL</div>
          <div style="font-size:22px;font-weight:900;color:#fff;margin-bottom:4px;">Start Pro Access Now</div>
          <div style="font-size:12px;color:#4a6a8a;">Full IOC arrays · AI analysis · 5,000 API calls/day<br>No credit card required.</div>
        </div>
        <input id="cdb-trial-name"    type="text"  placeholder="Your name" />
        <input id="cdb-trial-email"   type="email" placeholder="Work email (required)" />
        <input id="cdb-trial-company" type="text"  placeholder="Company name" />
        <button id="cdb-trial-btn" onclick="cdbActivateTrial()"
          style="width:100%;padding:13px;background:linear-gradient(135deg,#00d4aa,#0099cc);border:none;border-radius:8px;
          color:#020811;font-family:monospace;font-size:12px;font-weight:900;letter-spacing:2px;cursor:pointer;text-transform:uppercase;">
          ACTIVATE TRIAL</button>
        <div id="cdb-trial-error"  style="margin-top:8px;min-height:18px;font-size:11px;color:#ff4466;font-family:monospace;text-align:center;"></div>
        <div id="cdb-trial-result" style=""></div>
        <div style="margin-top:14px;text-align:center;font-size:11px;color:#4a6a8a;">
          After trial: <strong style="color:#00d4aa;">₹2,499/mo</strong> · Cancel anytime</div>
      </div>`;
    document.body.appendChild(el);
    // Trigger open animation
    const box = document.getElementById("cdb-trial-box");
    if (box) setTimeout(() => { box.style.transform = "translateY(0)"; }, 10);
  }

  // ─── Usage Banner HTML ─────────────────────────────────────────────────────
  function _injectUsageBanner() {
    if (document.getElementById("cdb-usage-banner")) return;
    const el = document.createElement("div");
    el.id = "cdb-usage-banner";
    el.style.cssText = "display:none;position:fixed;bottom:0;left:0;right:0;background:rgba(7,14,28,0.97);"+
      "border-top:1px solid rgba(255,140,0,0.3);padding:10px 20px;font-family:monospace;font-size:12px;"+
      "z-index:9990;text-align:center;";
    document.body.appendChild(el);
  }

  // ─── Trial CTA Navbar Button ───────────────────────────────────────────────
  function _injectTrialNavBtn() {
    const navRow = document.querySelector(".nav-chip-row, nav");
    if (!navRow || document.getElementById("cdb-trial-nav-btn")) return;
    const btn = document.createElement("button");
    btn.id = "cdb-trial-nav-btn";
    btn.onclick = function() { window.cdbOpenTrialModal(); };
    btn.title = "Start 7-day Pro trial — no credit card";
    btn.className = "nav-chip";
    btn.style.cssText = "background:linear-gradient(135deg,#00d4aa20,#00d4aa08);border:1px solid rgba(0,212,170,0.5);"+
      "cursor:pointer;font-family:inherit;font-size:inherit;color:#00d4aa;font-weight:700;";
    btn.textContent = "🚀 FREE TRIAL";
    navRow.appendChild(btn);
  }

  // ─── Init ──────────────────────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", function() {
    _injectLeadModal();
    _injectTrialModal();
    _injectUsageBanner();
    _injectTrialNavBtn();

    // Intercept any "View Full Report" / "Export IOC" buttons that are locked
    document.body.addEventListener("click", function(e) {
      const el = e.target.closest("[data-cdb-gate]");
      if (!el) return;
      const gateType = el.getAttribute("data-cdb-gate");
      e.preventDefault();
      e.stopPropagation();
      window.cdbLeadGate(gateType, function() {
        // After capture — show relevant modal
        if (gateType === "ioc_access" || gateType === "stix_request") {
          if (window.openUpgradeModal) window.openUpgradeModal("pro");
        }
      });
    });

    // Check trial status — show banner if trial active
    if (sessionStorage.getItem("cdb_trial_active")) {
      const banner = document.getElementById("cdb-usage-banner");
      if (banner) {
        banner.style.display = "block";
        banner.style.borderTopColor = "rgba(0,212,170,0.3)";
        banner.innerHTML = `<span style="color:#00d4aa;font-weight:700;">✅ PRO TRIAL ACTIVE</span>
          &nbsp;— Full IOC access enabled. &nbsp;
          <a href="https://intel.cyberdudebivash.com/upgrade?plan=pro" target="_blank"
             style="color:#ffd700;font-weight:700;text-decoration:none;">Lock in Pro access →</a>`;
      }
    }
  });

})();
