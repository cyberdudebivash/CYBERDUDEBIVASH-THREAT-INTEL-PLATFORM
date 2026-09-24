/**
 * CYBERDUDEBIVASH SENTINEL APEX -- customer dashboard derivation contract.
 *
 * Pure functions: canonical feed items in, evidence-derived dashboard blocks
 * out. Used by /api/v1/intel/campaigns, /ransomware, /cybermap and /stats in
 * index.js so the homepage widgets read one set of semantics.
 *
 * Rules (P0 dashboard data-contract recovery, 2026-09-24):
 *   - ATT&CK coverage counts only tactics the item's own ATT&CK evidence
 *     names. Severity and risk score are never used to infer a tactic.
 *   - An advisory is a "campaign" only when the advisory itself says so
 *     (threat_type, a campaign tag, or the title). A critical vulnerability
 *     is not, by itself, a campaign.
 *   - Pipeline attribution labels (campaign_id / campaign / campaign_name,
 *     actor, actor_tag, mitre_group_name) are keyword-inferred by the
 *     pipeline and are supporting evidence only: they are recorded next to
 *     independent evidence but never classify an item or name an active
 *     group on their own (live: CAMP-APT41Healthcare on CRM XSS CVEs, a
 *     LockBit label on Ryuk sentencing news, Cl0p on a Linux kernel CVE).
 *   - Ransomware classification reads threat_type, tags, malware family and
 *     the title, and never the description. A group is "active" only when
 *     one of those fields of a current ransomware-classified item names it.
 *   - Geographic origin comes only from actor_country (threat-actor
 *     attribution). Publisher, vendor, victim and IP geography are not origin.
 */

export const DASHBOARD_CONTRACT_VERSION = "dashboard-contract/1.0";
export const ATTACK_DERIVATION_VERSION = "attack-tactics/1.0";
export const CAMPAIGN_SEMANTICS_VERSION = "campaign-evidence/1.2";
export const RANSOMWARE_CLASSIFIER_VERSION = "ransomware-classifier/1.1";
export const THREAT_LEVEL_FORMULA_VERSION = "threat-level/1.0";
export const THREAT_LEVEL_FORMULA =
  "min(10, min(avg_risk_score,10) + min(kev_confirmed*0.15,1.5) + min(critical*0.05,0.5)); " +
  "bands: >=8.5 CRITICAL, >=7.0 HIGH, >=5.0 ELEVATED, >=3.0 GUARDED, else LOW";

/** MITRE ATT&CK Enterprise tactics, in matrix order. */
export const ATTACK_TACTICS = Object.freeze([
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
]);

const TACTIC_BY_KEY = new Map();
for (const t of ATTACK_TACTICS) {
  TACTIC_BY_KEY.set(_key(t.name), t.name);
  TACTIC_BY_KEY.set(t.id.toLowerCase(), t.name);
}

function _key(s) {
  return String(s || "").toLowerCase().replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim();
}

/** Canonical ATT&CK tactic name for one label, or null when it is not one. */
export function normalizeTactic(label) {
  return TACTIC_BY_KEY.get(_key(label)) || null;
}

/** A tactic field may hold "Defense Evasion / Persistence" for a multi-tactic technique. */
function _tacticsFromLabel(label) {
  const out = [];
  for (const part of String(label || "").split(/\s*[/,;|]\s*/)) {
    const t = normalizeTactic(part);
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

function _techniqueId(v) {
  if (typeof v === "string") return TECHNIQUE_RE.test(v.trim()) ? v.trim() : null;
  if (v && typeof v === "object") {
    const id = v.technique_id || v.id;
    return typeof id === "string" && TECHNIQUE_RE.test(id.trim()) ? id.trim() : null;
  }
  return null;
}

function _baseTechnique(id) {
  return id.split(".")[0];
}

/** Every ATT&CK technique id an item carries, from any structured field or a T-id tag. */
export function techniqueIdsOf(item) {
  const ids = new Set();
  const lists = [item && item.attck_technique_ids, item && item.mitre_techniques,
    item && item.attck_techniques, item && item.mitre_tactics, item && item.tags];
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const v of list) {
      const id = _techniqueId(v);
      if (id) ids.add(id);
    }
  }
  return [...ids];
}

/**
 * technique id -> tactics, built from the pipeline's own technique/tactic
 * pairs (mitre_tactics[], attck_techniques[]) in this same feed generation.
 * No static taxonomy is invented here.
 */
export function buildTechniqueTacticMap(items) {
  const map = new Map();
  for (const item of items || []) {
    for (const list of [item && item.mitre_tactics, item && item.attck_techniques]) {
      if (!Array.isArray(list)) continue;
      for (const entry of list) {
        if (!entry || typeof entry !== "object") continue;
        const id = _techniqueId(entry);
        const tactics = _tacticsFromLabel(entry.tactic);
        if (!id || !tactics.length) continue;
        const base = _baseTechnique(id);
        const set = map.get(base) || new Set();
        tactics.forEach((t) => set.add(t));
        map.set(base, set);
      }
    }
  }
  return map;
}

/**
 * Tactics one item's evidence supports, with the method that produced them.
 * Precedence: mitre_tactics[].tactic > attck_techniques[].tactic >
 * technique ids mapped via the feed's own pairs > legacy kill_chain fields.
 */
export function deriveItemTactics(item, techniqueMap) {
  const collect = (list) => {
    const out = new Set();
    if (Array.isArray(list)) {
      for (const e of list) {
        if (e && typeof e === "object") _tacticsFromLabel(e.tactic).forEach((t) => out.add(t));
      }
    }
    return out;
  };
  let tactics = collect(item && item.mitre_tactics);
  if (tactics.size) return { tactics: [...tactics], method: "mitre_tactics" };
  tactics = collect(item && item.attck_techniques);
  if (tactics.size) return { tactics: [...tactics], method: "attck_techniques" };
  if (techniqueMap) {
    for (const id of techniqueIdsOf(item)) {
      const mapped = techniqueMap.get(_baseTechnique(id));
      if (mapped) mapped.forEach((t) => tactics.add(t));
    }
    if (tactics.size) return { tactics: [...tactics], method: "technique_id_map" };
  }
  const legacy = [];
  if (Array.isArray(item && item.kill_chain_phases)) legacy.push(...item.kill_chain_phases);
  if (item && typeof item.kill_chain_phase === "string") legacy.push(item.kill_chain_phase);
  for (const l of legacy) {
    const name = typeof l === "string" ? l : (l && (l.phase_name || l.tactic));
    _tacticsFromLabel(name).forEach((t) => tactics.add(t));
  }
  if (tactics.size) return { tactics: [...tactics], method: "legacy_kill_chain" };
  return { tactics: [], method: "none" };
}

/** MITRE ATT&CK tactic coverage for the current feed generation. */
export function deriveAttackTacticCoverage(items, generatedAt) {
  const list = Array.isArray(items) ? items : [];
  const techniqueMap = buildTechniqueTacticMap(list);
  const counts = new Map(ATTACK_TACTICS.map((t) => [t.name, 0]));
  const samples = new Map(ATTACK_TACTICS.map((t) => [t.name, []]));
  const methods = { mitre_tactics: 0, attck_techniques: 0, technique_id_map: 0, legacy_kill_chain: 0, none: 0 };
  let withEvidence = 0;
  const perItem = [];
  for (const item of list) {
    const d = deriveItemTactics(item, techniqueMap);
    methods[d.method] += 1;
    perItem.push(d.tactics);
    if (!d.tactics.length) continue;
    withEvidence += 1;
    for (const t of d.tactics) {
      counts.set(t, counts.get(t) + 1);
      const s = samples.get(t);
      if (s.length < 3 && item && item.id) s.push(String(item.id));
    }
  }
  const tactics = ATTACK_TACTICS.map((t) => ({
    id: t.id, name: t.name, count: counts.get(t.name), sample_item_ids: samples.get(t.name),
  }));
  return {
    block: {
      model: "mitre_attack_enterprise_tactics",
      derivation_version: ATTACK_DERIVATION_VERSION,
      derivation_method:
        "per item: mitre_tactics[].tactic, else attck_techniques[].tactic, else technique ids mapped " +
        "through the technique/tactic pairs in this feed generation, else legacy kill_chain fields. " +
        "Severity and risk score are never used.",
      tactics,
      tactics_observed: tactics.filter((t) => t.count > 0).length,
      tactics_total: ATTACK_TACTICS.length,
      items_evaluated: list.length,
      items_with_attack_evidence: withEvidence,
      method_counts: methods,
      generated_at: generatedAt || null,
    },
    perItem,
  };
}

const UNATTRIBUTED_RE = /^(cdb[-_ ]?unattr|unc[-_ ]?cdb|unattributed|unclassified|unknown|n\/a|none|null|-|tbd)/i;

/** A pipeline placeholder ("Unattributed LockBit cluster", CDB-UNATTR-RAN), not a name. */
function _isPlaceholderLabel(v) {
  const s = String(v || "").trim();
  return !s || UNATTRIBUTED_RE.test(s) || /unattr/i.test(s);
}

function _namedGroup(item) {
  const group = typeof item.mitre_group_name === "string" ? item.mitre_group_name.trim() : "";
  const gid = typeof item.actor_mitre_id === "string" ? item.actor_mitre_id.trim() : "";
  if (group && !_isPlaceholderLabel(group)) return group;
  if (/^G\d{4}$/.test(gid)) {
    const actor = typeof item.actor === "string" ? item.actor.trim() : "";
    return actor && !_isPlaceholderLabel(actor) ? actor : gid;
  }
  return null;
}

/** Evidence that an advisory describes a campaign or actor operation; [] when none. */
export function campaignEvidence(item) {
  if (!item || typeof item !== "object") return [];
  const ev = [];
  if (/campaign/i.test(String(item.threat_type || ""))) ev.push("threat_type");
  if (Array.isArray(item.tags) && item.tags.some((t) => typeof t === "string" && /\bcampaigns?\b/i.test(t))) ev.push("tag");
  const title = String(item.title || "");
  if (/\bcampaigns?\b/i.test(title)) ev.push("title:campaign");
  else if (/\b(ransomware|malware|threat actor|apt|espionage|hacking|botnet)\s+operations?\b/i.test(title)) ev.push("title:operation");
  // Pipeline campaign links and MITRE group labels are keyword-inferred (live:
  // CAMP-APT41Healthcare on CRM XSS CVEs, a Volt Typhoon label on a Senate
  // bill). They say who/which cluster the pipeline guessed, not that an
  // operation exists, so they are supporting evidence only, recorded next to
  // an independent campaign/operation signal.
  if (!ev.length) return ev;
  for (const f of ["campaign_id", "campaign", "campaign_name"]) {
    if (typeof item[f] === "string" && item[f].trim() && !_isPlaceholderLabel(item[f])) { ev.push(f); break; }
  }
  const group = _namedGroup(item);
  if (group) ev.push("mitre_group:" + group);
  return ev;
}

/**
 * Block for /api/v1/intel/campaigns. Keeps the legacy keys (phases,
 * coverage_pct, active_campaigns, total_tactics) so existing readers keep
 * working, with corrected meaning, and adds attack_tactics.
 */
export function buildCampaignsPayload(items, nowIso) {
  const list = Array.isArray(items) ? items : [];
  const { block, perItem } = deriveAttackTacticCoverage(list, nowIso);
  // DEPRECATED (legacy Lockheed-style buckets, kept for existing readers):
  // derived from the ATT&CK tactics above. Replacement: attack_tactics.
  const legacyMap = {
    "Reconnaissance": "recon", "Resource Development": "weaponize",
    "Initial Access": "deliver", "Execution": "exploit",
    "Persistence": "install", "Privilege Escalation": "install",
    "Defense Evasion": "install", "Credential Access": "install",
    "Discovery": "install", "Lateral Movement": "c2",
    "Collection": "c2", "Command and Control": "c2",
    "Exfiltration": "action", "Impact": "action",
  };
  const phases = { recon: 0, weaponize: 0, deliver: 0, exploit: 0, install: 0, c2: 0, action: 0 };
  const campaigns = [];
  list.forEach((item, i) => {
    const tactics = perItem[i];
    const hit = new Set(tactics.map((t) => legacyMap[t]).filter(Boolean));
    hit.forEach((p) => { phases[p] += 1; });
    const evidence = campaignEvidence(item);
    if (evidence.length) {
      campaigns.push({
        id: item.id || item.stix_id, title: item.title, severity: item.severity,
        risk_score: item.risk_score, source: item.source, published: item.published || item.published_at,
        kill_chain: tactics, cve_ids: item.cve_ids || [], tags: item.tags || [], evidence,
      });
    }
  });
  const legacyObserved = Object.values(phases).filter((v) => v > 0).length;
  return {
    phases,
    phases_model: "derived_cyber_kill_chain (deprecated: use attack_tactics)",
    coverage_pct: legacyObserved ? Math.round((legacyObserved / 7) * 100) : 0,
    total_tactics: legacyObserved,
    active_campaigns: campaigns.slice(0, 10),
    active_campaign_count: campaigns.length,
    campaign_semantics: {
      version: CAMPAIGN_SEMANTICS_VERSION,
      rule: "campaign threat_type or tag, or 'campaign' / '<actor> operation' in the title. Pipeline campaign ids/names " +
        "and MITRE group labels are supporting evidence only. Severity, risk score, KEV status, a campaign id or an " +
        "actor label alone never make a campaign.",
    },
    attack_tactics: block,
    generated_at: nowIso,
  };
}

function _groupPattern(name) {
  const n = String(name || "").toLowerCase();
  if (n === "play") return [/\bplay ransomware\b/];
  const parts = n.split("/").map((s) => s.trim()).filter((s) => s.length >= 4);
  return parts.map((p) => new RegExp("\\b" + p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b"));
}

function _strings(v) {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string");
  return [];
}

/**
 * Ransomware classification for one item. Structured fields first
 * (threat_type, tags, malware family), then the title. The description is
 * never read: prose mentions are not evidence. Actor attribution labels are
 * keyword-inferred by the pipeline (live: "LockBit Ransomware Group" on Ryuk
 * sentencing news, Cl0p on a Linux kernel CVE): they never classify an item
 * or name an active group, and are recorded as supporting evidence
 * ("actor_label:<name>") only when independent evidence classified it.
 */
export function classifyRansomware(item, groups) {
  if (!item || typeof item !== "object") return { ransomware: false, evidence: [], groups: [] };
  const evidence = [];
  const named = new Set();
  const structured = [
    ["threat_type", _strings(item.threat_type)],
    ["tags", _strings(item.tags)],
    ["malware", [..._strings(item.malware_family), ..._strings(item.actor_malware), ..._strings(item.malware)]],
  ];
  const scan = (label, values) => {
    for (const raw of values) {
      const v = raw.toLowerCase();
      if (/\bransomware\b/.test(v) || (label === "threat_type" && /\bransom/.test(v))) evidence.push(label + ":ransomware");
      for (const g of groups || []) {
        if (_groupPattern(g.name).some((re) => re.test(v))) { named.add(g.name); evidence.push(label + ":" + g.name); }
      }
    }
  };
  for (const [label, values] of structured) scan(label, values);
  scan("title", _strings(item.title));
  if (evidence.length) {
    // Supporting only: placeholders ("Unattributed LockBit cluster") are dropped.
    const labels = [..._strings(item.actor), ..._strings(item.mitre_group_name)].filter((v) => !_isPlaceholderLabel(v));
    for (const v of new Set(labels.map((x) => x.trim()))) evidence.push("actor_label:" + v);
  }
  return { ransomware: evidence.length > 0, evidence: [...new Set(evidence)], groups: [...named] };
}

/** Block for /api/v1/intel/ransomware. Victim counts stay null: not measured. */
export function buildRansomwarePayload(items, groups, nowIso) {
  const list = Array.isArray(items) ? items : [];
  const hits = [];
  const active = new Map();
  for (const item of list) {
    const c = classifyRansomware(item, groups);
    if (!c.ransomware) continue;
    hits.push({ item, c });
    for (const name of c.groups) active.set(name, (active.get(name) || 0) + 1);
  }
  const byName = new Map((groups || []).map((g) => [g.name, g]));
  const top = [...active.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, n]) => ({
    name, sector: (byName.get(name) || {}).sector || "", status: "IN_CURRENT_FEED", advisories: n, victims_30d: null,
  }));
  return {
    active_groups: active.size,
    monitoring_groups: 0,
    new_victims_30d: null,
    victims_measured: false,
    ransomware_advisories: hits.length,
    items_evaluated: list.length,
    monitor_status: "OPERATIONAL",
    classification: {
      version: RANSOMWARE_CLASSIFIER_VERSION,
      method: "threat_type, tags and malware family fields, then the title. Description text is not used. Pipeline " +
        "actor labels are supporting evidence only and never classify an item. A group counts as active only when " +
        "one of those fields of a current ransomware-classified item names it.",
    },
    recent_advisories: hits.slice(0, 5).map(({ item, c }) => ({
      title: item.title, severity: item.severity, risk_score: item.risk_score, source: item.source,
      published: item.published || item.published_at, evidence: c.evidence,
    })),
    top_groups: top,
    generated_at: nowIso,
  };
}

/** Geographic attribution coverage: actor_country only, with how many items were evaluated. */
export function geoAttributionCoverage(items) {
  const list = Array.isArray(items) ? items : [];
  let attributed = 0;
  for (const item of list) {
    const raw = String((item && item.actor_country) || "").trim();
    if (raw && !/^(unknown|unattributed|n\/a|none|null|-)$/i.test(raw)) attributed += 1;
  }
  return {
    attribution_field: "actor_country",
    attribution_semantics: "Threat-actor attribution country from the feed. Publisher, vendor, victim and IP geography are not treated as origin.",
    items_evaluated: list.length,
    items_with_country_attribution: attributed,
  };
}
