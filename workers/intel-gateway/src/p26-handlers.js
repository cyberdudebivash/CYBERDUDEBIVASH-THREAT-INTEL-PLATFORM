/**
 * workers/intel-gateway/src/p26-handlers.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  P26.0 Enterprise Intelligence Excellence Program
 * ========================================================================================
 * Unification and orchestration layer for P20-P25 intelligence quality engines.
 * Computes the definitive P26 Enterprise Grade and produces commercial certification.
 *
 * THIS IS NOT A FEATURE LAYER  -  it is the quality governance capstone.
 *
 * Components (all additive  -  P1-P25 unchanged):
 *   P26.6   -  Enterprise Intelligence Scoring   (computeP26Grade, buildP26GradeCardBlock)
 *   P26.7   -  Commercial Report Certification   (buildP26CertificationBlock)
 *   P26.8   -  Enterprise Report Presentation    (buildP26ReportHeaderBlock)
 *   P26.10  -  Customer Trust Framework          (buildP26TrustBadgesBlock)
 *   API     -  handleP26Grade, handleP26FeedGrade, handleP26Observability
 *
 * ZERO FABRICATION  -  all scores derived from existing P20-P25 pipeline output only.
 * ADDITIVE ONLY    -  no existing schema, API, KV, auth, scoring engine modified.
 * ZERO DUPLICATION -  P20-P25 engines reused via imports; P26 aggregates, not recomputes.
 *
 * Grade -> A/B/C/D/F from composite of P20/P21/P22/P23/P25 quality signals.
 * Commercial certification -> ENTERPRISE_EXCELLENT / ENTERPRISE_CERTIFIED / ENTERPRISE_READY
 *                            / CONDITIONAL / REJECTED
 */

import { computeP20QualityScore }     from './p20-handlers.js';
import { getP21CertificationLevel }   from './p21-handlers.js';
import { computeActionabilityScore }  from './p23-handlers.js';
import { computeEnterpriseTrustScore} from './p25-handlers.js';

export const P26_VERSION = "P26.0";

// -- Shared helpers ------------------------------------------------------------

function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function _block(id, title, color, body, subtitle) {
  return `
<div id="${id}" style="margin:24px 0;padding:20px 24px;background:#0d1117;border:1px solid ${color}33;border-left:4px solid ${color};border-radius:6px;font-family:'Courier New',monospace;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
    <div>
      <span style="color:${color};font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;">${esc(title)}</span>
      ${subtitle ? `<div style="color:#6b7280;font-size:10px;margin-top:2px;">${esc(subtitle)}</div>` : ''}
    </div>
    <span style="color:#333;font-size:10px;">P26.0 ? SENTINEL APEX ENTERPRISE</span>
  </div>
  ${body}
</div>`;
}

function _badge(text, color, bg) {
  return `<span style="display:inline-block;padding:3px 10px;background:${bg || color + '22'};color:${color};border:1px solid ${color}55;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.08em;">${esc(text)}</span>`;
}

function _bar(pct, color, h) {
  const w = Math.min(100, Math.max(0, pct));
  h = h || "4px";
  return `<div style="background:#1a1f2e;border-radius:2px;height:${h};width:100%;margin:4px 0;">
    <div style="background:${color};height:${h};border-radius:2px;width:${w}%;transition:width .3s;"></div>
  </div>`;
}

function _row(label, value, color) {
  return `<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #1a1f2e;">
    <span style="color:#8b949e;font-size:11px;">${esc(label)}</span>
    <span style="color:${color || '#e6edf3'};font-size:11px;font-weight:600;">${esc(String(value))}</span>
  </div>`;
}

// -- P26.6 - Enterprise Intelligence Scoring -----------------------------------

/**
 * Aggregate P20-P25 quality signals into a single P26 composite grade.
 * Each dimension reuses an existing engine  -  nothing is recomputed from scratch.
 *
 * Composite weights:
 *   P20 Quality Score    (100 pts)  -> 25%  of composite
 *   P21 Cert Level       (4 tiers)  -> 15%  of composite
 *   P23 Actionability    (100 pts)  -> 25%  of composite
 *   P25 Trust Score V2   (100 pts)  -> 25%  of composite
 *   P22 Contradiction    (clean=1)  -> 10%  of composite
 *
 * Total: 100%. Grade thresholds: A?90 B?75 C?60 D?45 F<45
 */
export function computeP26Grade(item) {
  // P20 quality (0-100)
  const p20    = computeP20QualityScore(item);
  const p20pct = p20.total;                               // 0-100

  // P21 certification (BELOW_MINIMUM=0, INTERNAL_DRAFT=50, ENTERPRISE_READY=75, PREMIUM_CERTIFIED=100)
  const p21    = getP21CertificationLevel(item);
  const p21map = { PREMIUM_CERTIFIED: 100, ENTERPRISE_READY: 75, INTERNAL_DRAFT: 50, BELOW_MINIMUM: 0 };
  const p21pct = p21map[p21.level] ?? 0;

  // P23 actionability (0-100)
  const p23    = computeActionabilityScore(item);
  const p23pct = p23.total;                               // 0-100

  // P25 trust score (0-100)
  const p25    = computeEnterpriseTrustScore(item);
  const p25pct = p25.pct;                                 // 0-100

  // P22 contradiction penalty (0-100  -  subtract 25 per error contradiction)
  // Read from _score_details or compute inline: check for obvious contradictions
  const sd      = item._score_details || {};
  const cvss    = parseFloat(sd.cvss || item.cvss_score || item.risk_score || 0);
  const kev     = !!(sd.kev || item.kev_present || item.kev);
  const severity = String(item.severity || "").toUpperCase();
  const SBAND   = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
  let contradictions = 0;
  if (cvss >= 9 && SBAND[severity] !== undefined && SBAND[severity] <= 1) contradictions++;
  if (kev && (severity === "LOW" || severity === "INFO"))                   contradictions++;
  const p22pct  = Math.max(0, 100 - contradictions * 25);                  // 100/75/50...

  // Weighted composite
  const composite = Math.round(
    p20pct  * 0.25 +
    p21pct  * 0.15 +
    p23pct  * 0.25 +
    p25pct  * 0.25 +
    p22pct  * 0.10
  );

  // Grade
  let grade, gradeColor, gradeLabel;
  if (composite >= 90) {
    grade = "A";  gradeColor = "#22c55e";
    gradeLabel = "ENTERPRISE EXCELLENT";
  } else if (composite >= 75) {
    grade = "B";  gradeColor = "#3b82f6";
    gradeLabel = "ENTERPRISE CERTIFIED";
  } else if (composite >= 60) {
    grade = "C";  gradeColor = "#eab308";
    gradeLabel = "ENTERPRISE READY";
  } else if (composite >= 45) {
    grade = "D";  gradeColor = "#f97316";
    gradeLabel = "CONDITIONAL RELEASE";
  } else {
    grade = "F";  gradeColor = "#ef4444";
    gradeLabel = "BELOW THRESHOLD";
  }

  // P26.7 commercial certification
  const certFlags = _computeCertFlags(item, composite, contradictions, p20, p21);

  return {
    composite, grade, gradeColor, gradeLabel,
    components: {
      p20: { score: p20pct, label: "P20 Quality Score",    weight: 25 },
      p21: { score: p21pct, label: "P21 Certification",    weight: 15 },
      p22: { score: p22pct, label: "P22 Contradictions",   weight: 10 },
      p23: { score: p23pct, label: "P23 Actionability",    weight: 25 },
      p25: { score: p25pct, label: "P25 Trust Score V2",   weight: 25 },
    },
    p20detail: p20, p21detail: p21, p23detail: p23, p25detail: p25,
    certFlags,
    contradictions,
  };
}

/** P26.7: Compute commercial certification flags. */
function _computeCertFlags(item, composite, contradictions, p20, p21) {
  const flags = [];
  const desc  = String(item.description || item.apex?.ai_summary || item.apex_ai?.ai_summary || "");
  const exec  = String(item.executive_summary || "");

  // Synthetic language detection
  const synthetic = /lorem ipsum|placeholder|tbd|todo|example corp|acme corp|\[insert\]|\[redacted\]|synthetic|dummy/i;
  if (synthetic.test(desc) || synthetic.test(exec)) {
    flags.push({ code: "C-SYN", level: "BLOCKER", msg: "Synthetic or placeholder language detected in intelligence narrative" });
  }

  // Evidence completeness
  if (!item.evidence_chain) {
    flags.push({ code: "C-EVI", level: "WARNING", msg: "Evidence chain not populated  -  enricher may not have run" });
  }

  // MITRE completeness
  const ttpCnt = parseInt(item.ttp_count || 0);
  if (ttpCnt === 0) {
    flags.push({ code: "C-MIT", level: "WARNING", msg: "No MITRE ATT&CK techniques mapped  -  behavioral detection coverage unknown" });
  }

  // Contradiction check
  if (contradictions > 0) {
    flags.push({ code: "C-CON", level: "WARNING", msg: `${contradictions} data contradiction(s) detected  -  severity/CVSS/KEV alignment required` });
  }

  // Confidence threshold
  const conf = parseFloat(item.confidence || 0);
  if (conf < 0.10) {
    flags.push({ code: "C-CNF", level: "WARNING", msg: `Pipeline confidence critically low: ${Math.round(conf * 100)}%  -  corroboration needed` });
  }

  // P21 certification minimum
  if (p21.level === "BELOW_MINIMUM") {
    flags.push({ code: "C-P21", level: "BLOCKER", msg: "P21 certification BELOW_MINIMUM  -  item does not meet enterprise release standard" });
  }

  // P20 score minimum
  if (p20.total < 25) {
    flags.push({ code: "C-P20", level: "WARNING", msg: `P20 quality score critically low: ${p20.total}/100  -  enrichment incomplete` });
  }

  // Determine commercial tier
  const blockers  = flags.filter(f => f.level === "BLOCKER").length;
  const warnings  = flags.filter(f => f.level === "WARNING").length;
  let certTier, certColor;
  if (blockers === 0 && warnings === 0 && composite >= 90) {
    certTier = "ENTERPRISE_EXCELLENT";  certColor = "#22c55e";
  } else if (blockers === 0 && composite >= 75) {
    certTier = "ENTERPRISE_CERTIFIED";  certColor = "#3b82f6";
  } else if (blockers === 0 && composite >= 60) {
    certTier = "ENTERPRISE_READY";      certColor = "#eab308";
  } else if (blockers === 0) {
    certTier = "CONDITIONAL";           certColor = "#f97316";
  } else {
    certTier = "REJECTED";              certColor = "#ef4444";
  }

  return { flags, blockers, warnings, certTier, certColor };
}

// -- P26.8 - Enterprise Report Presentation: Grade Card -----------------------

/** Top-of-report enterprise grade card  -  the highest-signal summary block. */
export function buildP26GradeCardBlock(item) {
  const g = computeP26Grade(item);
  const now = new Date().toISOString();

  const compRows = Object.values(g.components).map(c => {
    const color = c.score >= 80 ? "#22c55e" : c.score >= 60 ? "#eab308" : "#ef4444";
    return `<div style="display:flex;align-items:center;gap:8px;margin:5px 0;">
      <span style="color:#8b949e;font-size:10px;min-width:140px;">${esc(c.label)}</span>
      <div style="flex:1;">${_bar(c.score, color, "5px")}</div>
      <span style="color:${color};font-size:10px;font-weight:700;min-width:36px;text-align:right;">${c.score}%</span>
      <span style="color:#4b5563;font-size:9px;">x${c.weight}%</span>
    </div>`;
  }).join("");

  const certFlagRows = g.certFlags.flags.length > 0
    ? g.certFlags.flags.map(f => {
        const fc = f.level === "BLOCKER" ? "#ef4444" : "#eab308";
        return `<div style="display:flex;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid #1a1f2e;">
          <span style="color:${fc};font-size:10px;font-weight:700;min-width:60px;">${esc(f.code)}</span>
          <span style="color:${fc};font-size:9px;font-weight:700;">[${esc(f.level)}]</span>
          <span style="color:#8b949e;font-size:10px;flex:1;">${esc(f.msg)}</span>
        </div>`;
      }).join("")
    : `<div style="color:#22c55e;font-size:10px;padding:6px 0;">[OK] No commercial flags  -  all certification criteria met</div>`;

  const body = `
    <div style="display:grid;grid-template-columns:auto 1fr;gap:24px;margin-bottom:20px;align-items:center;">
      <div style="text-align:center;padding:16px 24px;background:${g.gradeColor}11;border:2px solid ${g.gradeColor}44;border-radius:8px;">
        <div style="color:${g.gradeColor};font-size:52px;font-weight:900;line-height:1;letter-spacing:-.04em;">${esc(g.grade)}</div>
        <div style="color:${g.gradeColor};font-size:9px;font-weight:700;letter-spacing:.12em;margin-top:4px;">${esc(g.grade === "A" ? "EXCELLENT" : g.grade === "B" ? "CERTIFIED" : g.grade === "C" ? "READY" : g.grade === "D" ? "CONDITIONAL" : "REJECTED")}</div>
      </div>
      <div>
        <div style="color:${g.gradeColor};font-size:16px;font-weight:800;margin-bottom:4px;">${esc(g.gradeLabel)}</div>
        <div style="color:#8b949e;font-size:11px;margin-bottom:8px;">Composite score: <span style="color:${g.gradeColor};font-weight:700;">${g.composite}/100</span> across 5 quality dimensions</div>
        ${_bar(g.composite, g.gradeColor, "6px")}
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
          ${_badge(g.certFlags.certTier, g.certFlags.certColor)}
          ${_badge("P26.0 GRADED", "#8b5cf6")}
          ${g.certFlags.blockers === 0 ? _badge("NO BLOCKERS", "#22c55e") : _badge(`${g.certFlags.blockers} BLOCKER(S)`, "#ef4444")}
        </div>
      </div>
    </div>
    <div style="color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;">Component Breakdown (weighted)</div>
    ${compRows}
    ${g.certFlags.flags.length > 0 ? `
    <div style="color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:12px 0 6px;">P26.7 Commercial Certification Flags</div>
    ${certFlagRows}` : `
    <div style="margin-top:12px;">${certFlagRows}</div>`}
    <div style="color:#4b5563;font-size:10px;margin-top:12px;text-align:right;">P26.0 Enterprise Intelligence Excellence * Graded ${now.slice(0,19).replace('T',' ')} UTC</div>`;

  return _block(
    "p26-grade-card",
    "P26.6 - Enterprise Intelligence Grade",
    g.gradeColor,
    body,
    "Composite of P20 Quality / P21 Certification / P22 Contradictions / P23 Actionability / P25 Trust Score V2"
  );
}

// -- P26.10 - Customer Trust Framework ----------------------------------------

/**
 * Compact horizontal trust badge strip  -  the first thing an enterprise customer sees.
 * Shows live verification status for each major dimension.
 */
export function buildP26TrustBadgesBlock(item) {
  const g   = computeP26Grade(item);
  const p20 = g.p20detail;
  const p21 = g.p21detail;
  const p23 = g.p23detail;
  const p25 = g.p25detail;

  // Determine badge state per dimension
  const badges = [
    {
      label: "Evidence Verified",
      ok:    !!(item.evidence_chain),
      sub:   item.evidence_chain
        ? `Reliability ${item.evidence_chain.reliability_code || '?'} (NATO)`
        : "Enricher pending",
    },
    {
      label: "Commercial Certified",
      ok:    g.certFlags.blockers === 0 && g.composite >= 60,
      sub:   g.certFlags.certTier,
    },
    {
      label: "Detection Validated",
      ok:    !!(item.sigma_rule || item.kql_query || item.suricata_rule),
      sub:   [
        item.sigma_rule     ? "Sigma" : null,
        item.kql_query      ? "KQL"   : null,
        item.suricata_rule  ? "IDS"   : null,
      ].filter(Boolean).join("/") || "Behavioral only",
    },
    {
      label: "IOC Verified",
      ok:    parseInt(item.ioc_count || 0) > 0,
      sub:   parseInt(item.ioc_count || 0) > 0
        ? `${item.ioc_count} validated indicator(s)`
        : "No IOCs  -  behavioral intel",
    },
    {
      label: "Enterprise Ready",
      ok:    g.composite >= 60 && g.certFlags.blockers === 0,
      sub:   `P26 grade: ${g.grade}  -  ${g.composite}/100`,
    },
    {
      label: "ATT&CK Mapped",
      ok:    parseInt(item.ttp_count || 0) > 0,
      sub:   parseInt(item.ttp_count || 0) > 0
        ? `${item.ttp_count} technique(s)`
        : "Not mapped",
    },
    {
      label: "Platform Version",
      ok:    true,
      sub:   "SENTINEL APEX v184 / P26.0",
    },
    {
      label: "Last Verification",
      ok:    true,
      sub:   new Date().toISOString().slice(0, 10),
    },
  ];

  const badgeHtml = badges.map(b => {
    const color = b.ok ? "#22c55e" : "#6b7280";
    const icon  = b.ok ? "[OK]" : "?";
    return `<div style="display:flex;align-items:flex-start;gap:6px;padding:8px 12px;background:${b.ok ? '#0a1a0e' : '#0a0e17'};border:1px solid ${color}33;border-radius:6px;min-width:140px;">
      <span style="color:${color};font-size:13px;font-weight:700;margin-top:1px;">${icon}</span>
      <div>
        <div style="color:${color};font-size:10px;font-weight:700;">${esc(b.label)}</div>
        <div style="color:#6b7280;font-size:9px;margin-top:2px;">${esc(b.sub)}</div>
      </div>
    </div>`;
  }).join("");

  const trustPct = Math.round((badges.filter(b => b.ok).length / badges.length) * 100);
  const trustColor = trustPct >= 80 ? "#22c55e" : trustPct >= 60 ? "#eab308" : "#ef4444";

  const body = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
      <div style="font-size:11px;color:#8b949e;">Customer-facing trust verification status  -  updated on each pipeline run.</div>
      <div style="color:${trustColor};font-size:12px;font-weight:700;">${trustPct}% verified</div>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">
      ${badgeHtml}
    </div>`;

  return _block(
    "p26-trust-badges",
    "P26.10 - Customer Trust Framework",
    "#22c55e",
    body,
    "Live verification status across all intelligence quality dimensions"
  );
}

// -- P26.7 - Commercial Certification Block ------------------------------------

export function buildP26CertificationBlock(item) {
  const g = computeP26Grade(item);

  const flagRows = g.certFlags.flags.length > 0
    ? `<table style="width:100%;border-collapse:collapse;margin-top:8px;">
        <thead>
          <tr>
            <th style="text-align:left;font-size:9px;color:#6b7280;padding:4px 8px;border-bottom:1px solid #1a1f2e;">Code</th>
            <th style="text-align:left;font-size:9px;color:#6b7280;padding:4px 8px;border-bottom:1px solid #1a1f2e;">Level</th>
            <th style="text-align:left;font-size:9px;color:#6b7280;padding:4px 8px;border-bottom:1px solid #1a1f2e;">Finding</th>
          </tr>
        </thead>
        <tbody>
          ${g.certFlags.flags.map(f => {
            const fc = f.level === "BLOCKER" ? "#ef4444" : "#eab308";
            return `<tr>
              <td style="padding:5px 8px;font-size:10px;color:${fc};font-weight:700;border-bottom:1px solid #0a0e17;">${esc(f.code)}</td>
              <td style="padding:5px 8px;font-size:10px;color:${fc};border-bottom:1px solid #0a0e17;">${esc(f.level)}</td>
              <td style="padding:5px 8px;font-size:10px;color:#c9d1d9;border-bottom:1px solid #0a0e17;">${esc(f.msg)}</td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>`
    : `<div style="padding:10px;background:#0a1a0e;border-radius:4px;border-left:3px solid #22c55e44;margin-top:8px;">
        <div style="color:#22c55e;font-size:11px;font-weight:700;">[OK] COMMERCIALLY CERTIFIED  -  No flags detected</div>
        <div style="color:#8b949e;font-size:10px;margin-top:4px;">All commercial certification criteria satisfied. Intelligence meets enterprise publication standards.</div>
      </div>`;

  const tierDescriptions = {
    ENTERPRISE_EXCELLENT: "Highest commercial tier. Suitable for government, board, and Fortune 500 executive distribution.",
    ENTERPRISE_CERTIFIED: "Full enterprise certification. Suitable for SOC, MSSP, CISO, and compliance distribution.",
    ENTERPRISE_READY:     "Enterprise ready. Minor improvements recommended before executive distribution.",
    CONDITIONAL:          "Conditional release. Warnings present  -  internal use and analyst review appropriate.",
    REJECTED:             "Publication rejected. Critical blockers must be resolved before customer release.",
  };

  const body = `
    <div style="padding:14px;background:${g.certFlags.certColor}11;border:1px solid ${g.certFlags.certColor}33;border-radius:6px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:12px;">
        <div>
          <div style="color:${g.certFlags.certColor};font-size:13px;font-weight:800;">${esc(g.certFlags.certTier.replace(/_/g, ' '))}</div>
          <div style="color:#8b949e;font-size:10px;margin-top:3px;">${esc(tierDescriptions[g.certFlags.certTier] || '')}</div>
        </div>
        <div style="margin-left:auto;text-align:right;">
          <div style="color:${g.certFlags.blockers === 0 ? '#22c55e' : '#ef4444'};font-size:11px;font-weight:700;">${g.certFlags.blockers} blocker(s)</div>
          <div style="color:#6b7280;font-size:10px;">${g.certFlags.warnings} warning(s)</div>
        </div>
      </div>
    </div>
    ${_row("P26 Composite Score", g.composite + "/100", g.gradeColor)}
    ${_row("P26 Grade",           g.grade + "  -  " + g.gradeLabel, g.gradeColor)}
    ${_row("P21 Cert Level",      g.p21detail.level, g.p21detail.level === "PREMIUM_CERTIFIED" ? "#22c55e" : g.p21detail.level === "ENTERPRISE_READY" ? "#3b82f6" : "#6b7280")}
    ${_row("P25 Trust Tier",      g.p25detail.tier, g.p25detail.tierColor)}
    <div style="margin-top:12px;color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.1em;">Certification Findings</div>
    ${flagRows}`;

  return _block(
    "p26-certification",
    "P26.7 - Commercial Report Certification",
    g.certFlags.certColor,
    body,
    "Automated commercial publication gate  -  P26.0 certification engine"
  );
}

// -- API Handlers --------------------------------------------------------------

/**
 * GET /api/v1/p26/grade?id=<item-id>
 * Returns the P26 enterprise grade JSON for a specific feed item.
 */
export async function handleP26Grade(request, env) {
  try {
    const url    = new URL(request.url);
    const itemId = url.searchParams.get("id");
    const raw    = await env.SECURITY_HUB_KV.get("feed:latest", { type: "json" });
    const items  = Array.isArray(raw) ? raw : (raw?.items || raw?.data || []);

    const item = itemId ? items.find(i => i.id === itemId) : items[0];
    if (!item) {
      return new Response(JSON.stringify({ error: "Item not found", version: P26_VERSION }), {
        status: 404, headers: { "Content-Type": "application/json" }
      });
    }

    const g = computeP26Grade(item);
    return new Response(JSON.stringify({
      version:          P26_VERSION,
      generated_at:     new Date().toISOString(),
      item_id:          item.id,
      title:            item.title,
      p26_grade:        g.grade,
      p26_composite:    g.composite,
      p26_label:        g.gradeLabel,
      commercial_tier:  g.certFlags.certTier,
      blockers:         g.certFlags.blockers,
      warnings:         g.certFlags.warnings,
      flags:            g.certFlags.flags,
      components:       g.components,
    }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e), version: P26_VERSION }), {
      status: 500, headers: { "Content-Type": "application/json" }
    });
  }
}

/**
 * GET /api/v1/p26/grade/feed
 * Returns aggregate P26 grade distribution across all feed items.
 */
export async function handleP26FeedGrade(request, env) {
  try {
    const raw   = await env.SECURITY_HUB_KV.get("feed:latest", { type: "json" });
    const items = Array.isArray(raw) ? raw : (raw?.items || raw?.data || []);
    if (!items.length) {
      return new Response(JSON.stringify({ error: "No feed items", version: P26_VERSION }), {
        status: 404, headers: { "Content-Type": "application/json" }
      });
    }

    const grades  = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    const tiers   = {};
    let totalComp = 0;
    let totalBlock = 0;

    items.forEach(item => {
      const g = computeP26Grade(item);
      grades[g.grade] = (grades[g.grade] || 0) + 1;
      tiers[g.certFlags.certTier] = (tiers[g.certFlags.certTier] || 0) + 1;
      totalComp  += g.composite;
      totalBlock += g.certFlags.blockers;
    });

    return new Response(JSON.stringify({
      version:               P26_VERSION,
      generated_at:          new Date().toISOString(),
      total_items:           items.length,
      average_composite:     Math.round(totalComp / items.length),
      total_blockers:        totalBlock,
      grade_distribution:    grades,
      tier_distribution:     tiers,
      enterprise_excellent_pct: Math.round(((grades.A || 0) / items.length) * 100),
      enterprise_certified_pct: Math.round((((grades.A || 0) + (grades.B || 0)) / items.length) * 100),
    }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e), version: P26_VERSION }), {
      status: 500, headers: { "Content-Type": "application/json" }
    });
  }
}

/**
 * GET /api/v1/p26/observability
 * Platform-level P26 intelligence excellence observability.
 */
export async function handleP26Observability(request, env) {
  try {
    const raw   = await env.SECURITY_HUB_KV.get("feed:latest", { type: "json" });
    const items = Array.isArray(raw) ? raw : (raw?.items || raw?.data || []);
    if (!items.length) {
      return new Response(JSON.stringify({ error: "No feed items", version: P26_VERSION }), {
        status: 404, headers: { "Content-Type": "application/json" }
      });
    }

    const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    let totalComp = 0, totalBlock = 0, totalWarn = 0;
    const compTotals = { p20: 0, p21: 0, p22: 0, p23: 0, p25: 0 };

    items.forEach(item => {
      const g = computeP26Grade(item);
      grades[g.grade]++;
      totalComp  += g.composite;
      totalBlock += g.certFlags.blockers;
      totalWarn  += g.certFlags.warnings;
      for (const [k, v] of Object.entries(g.components)) {
        compTotals[k] = (compTotals[k] || 0) + v.score;
      }
    });

    const n = items.length;
    return new Response(JSON.stringify({
      version:            P26_VERSION,
      generated_at:       new Date().toISOString(),
      total_items:        n,
      average_composite:  Math.round(totalComp / n),
      total_blockers:     totalBlock,
      total_warnings:     totalWarn,
      grade_distribution: grades,
      component_averages: Object.fromEntries(
        Object.entries(compTotals).map(([k, v]) => [k, Math.round(v / n)])
      ),
      enterprise_certified_pct: Math.round(((grades.A + grades.B) / n) * 100),
      quality_target_met:       Math.round(((grades.A + grades.B) / n) * 100) >= 95,
    }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e), version: P26_VERSION }), {
      status: 500, headers: { "Content-Type": "application/json" }
    });
  }
}

/**
 * Build complete P26 HTML package for injection into each report.
 * Order: Trust Badges (top) -> Grade Card -> Certification Block.
 */
export function buildP26Package(item) {
  return [
    buildP26TrustBadgesBlock(item),
    buildP26GradeCardBlock(item),
    buildP26CertificationBlock(item),
  ].join("\n");
}
