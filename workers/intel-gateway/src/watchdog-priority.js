/**
 * CYBER WATCHDOG PRIORITY -- evidence-cited triage priority for match events.
 *
 * Why not computeActionabilityScore (p23): that engine scores how complete an
 * item's response package is (IOCs, rules, narrative) and assigns floor
 * points when data is missing. Watchdog priority answers a different
 * question -- how urgently an analyst should look at this match -- and must
 * never turn absent evidence into a number. Every point here cites the feed
 * field it came from; a factor with no data is `known: false` and adds
 * nothing, and an item with no core evidence gets score null and band
 * INSUFFICIENT_EVIDENCE, never 0/LOW.
 *
 * Pure and synchronous. Input is a projected feed item (projectItem() in
 * cyber-watchdog.js), so request-path and scheduler events score identically.
 */

// v2: EPSS read on the platform's percent scale (see epssProbability), and
// a string KEV flag ("YES"/"NO") is evidence. v1 events keep their stored
// explanation; they are never re-scored.
export const PRIORITY_VERSION = "watchdog-priority-2";
export const PRIORITY_BANDS = Object.freeze(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INSUFFICIENT_EVIDENCE"]);

// Maximum points per factor. Sums to 100.
const WEIGHTS = Object.freeze({ kev: 30, cvss: 25, epss: 20, severity: 15, activity: 10 });
const LABELS = Object.freeze({
  kev: "CISA KEV", cvss: "CVSS base score", epss: "EPSS exploit probability",
  severity: "Feed severity", activity: "Threat activity signals",
});

// Factors that establish the threat itself. Activity signals alone never do.
const CORE = ["kev", "cvss", "epss", "severity"];
const SEVERITY_POINTS = { CRITICAL: 15, HIGH: 11, MEDIUM: 6, LOW: 2, INFO: 0 };
const BAND_THRESHOLDS = [["CRITICAL", 70], ["HIGH", 45], ["MEDIUM", 20]];
const BAND_RANK = { INSUFFICIENT_EVIDENCE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const ACTIVITY_RE = /\b(exploited in the wild|actively exploited|in-the-wild|ransomware|zero-?day|mass exploitation)\b/i;

function num(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function kevWord(v) {
  if (typeof v !== "string") return null;
  const w = v.trim().toUpperCase();
  if (w === "YES" || w === "TRUE") return true;
  if (w === "NO" || w === "FALSE") return false;
  return null;
}

function kevFlag(item) {
  if (item.kev_present === true || item.kev_confirmed === true || item.kev === true || kevWord(item.kev) === true) return true;
  if (item.kev_present === false || item.kev_confirmed === false || item.kev === false || kevWord(item.kev) === false) return false;
  return null;
}

/** CISA KEV state from the feed: true (listed), false (feed says not listed), null (unknown). */
export function kevListed(item) {
  return item && typeof item === "object" ? kevFlag(item) : null;
}

/**
 * EPSS as a 0..1 probability, from the feed's epss_score.
 *
 * The platform stores EPSS as a PERCENT (0.0-100.0): both producers multiply
 * FIRST.org's probability by 100 (agent/v48_pipeline_hardening/
 * epss_batch_enricher.py, agent/sentinel_blogger.py). So 0.86 means 0.86%,
 * not 86%. A value outside 0..100 is not evidence. This is the one place
 * Watchdog converts it; the matcher's min_epss (a 0..1 probability, as
 * documented to customers) compares against this.
 */
export function epssProbability(item) {
  const n = num(item && item.epss_score);
  if (n === null || n < 0 || n > 100) return null;
  return Math.round(n * 10000) / 1000000;
}

function text(item) {
  return [item.title, item.name, item.summary, item.description, item.ai_summary, item.threat_type]
    .filter((v) => typeof v === "string").join(" ");
}

function bandFor(score) {
  for (const [band, min] of BAND_THRESHOLDS) if (score >= min) return band;
  return "LOW";
}

/**
 * @returns {{version, score: number|null, band, coverage, factors, floors_applied}}
 */
export function computeEventPriority(item) {
  const src = item && typeof item === "object" ? item : {};
  const factors = [];
  const add = (id, label, known, points, evidence) => {
    factors.push({ id, label: LABELS[id] || label, known, points: known ? Math.round(points * 10) / 10 : 0, max: WEIGHTS[id], evidence: known ? evidence : null });
  };

  const kev = kevFlag(src);
  add("kev", "CISA KEV", kev !== null, kev ? WEIGHTS.kev : 0, kev ? "Listed in CISA KEV (known exploited)" : "Feed reports not KEV-listed");

  const cvss = num(src.cvss_score);
  const cvssOk = cvss !== null && cvss >= 0 && cvss <= 10;
  add("cvss", "CVSS base score", cvssOk, cvssOk ? (cvss / 10) * WEIGHTS.cvss : 0, cvssOk ? "cvss_score=" + cvss : null);

  const epss = epssProbability(src);
  const epssOk = epss !== null;
  add("epss", "EPSS exploit probability", epssOk, epssOk ? epss * WEIGHTS.epss : 0, epssOk ? "epss_score=" + num(src.epss_score) + " (percent)" : null);

  const sev = typeof src.severity === "string" ? src.severity.trim().toUpperCase() : "";
  const sevOk = Object.prototype.hasOwnProperty.call(SEVERITY_POINTS, sev);
  add("severity", "Feed severity", sevOk, sevOk ? SEVERITY_POINTS[sev] : 0, sevOk ? "severity=" + sev : null);

  const signals = [];
  const actor = src.actor_display_name || src.actor_tag || src.mitre_group_name;
  if (typeof actor === "string" && actor.trim()) signals.push({ points: 5, evidence: "attributed actor=" + actor.trim().slice(0, 60) });
  const m = text(src).match(ACTIVITY_RE);
  if (m) signals.push({ points: 5, evidence: "feed text: \"" + m[0].toLowerCase() + "\"" });
  add("activity", "Threat activity signals", signals.length > 0, signals.reduce((n, s) => n + s.points, 0), signals.map((s) => s.evidence).join("; "));

  const coreKnown = factors.filter((f) => CORE.includes(f.id) && f.known);
  const coverage = Number((factors.filter((f) => f.known).reduce((n, f) => n + f.max, 0) / 100).toFixed(2));
  if (!coreKnown.length) {
    return { version: PRIORITY_VERSION, score: null, band: "INSUFFICIENT_EVIDENCE", coverage, factors, floors_applied: [] };
  }

  const score = Math.min(100, Math.round(factors.reduce((n, f) => n + f.points, 0)));
  let band = bandFor(score);
  // Floors: evidence that on its own warrants analyst attention, whatever
  // other factors are missing. Each is cited.
  const floors = [];
  const floor = (min, rule) => {
    if (BAND_RANK[min] > BAND_RANK[band]) { band = min; floors.push(rule); }
  };
  if (kev === true && ((cvssOk && cvss >= 9) || sev === "CRITICAL")) floor("CRITICAL", "kev_and_critical_impact");
  if (kev === true) floor("HIGH", "kev_listed");
  if (cvssOk && cvss >= 9) floor("HIGH", "cvss_ge_9");
  if (epssOk && epss >= 0.5) floor("HIGH", "epss_ge_50_percent");
  // The feed's own severity is never contradicted downward by missing data.
  if (sev === "CRITICAL") floor("HIGH", "severity_critical");
  if (sev === "HIGH") floor("MEDIUM", "severity_high");
  return { version: PRIORITY_VERSION, score, band, coverage, factors, floors_applied: floors };
}

/**
 * Stored form: unknown factors, labels and maxima are dropped (they are
 * constants), so 200 retained events stay small in the ledger record.
 */
export function compactPriority(p) {
  return {
    v: p.version, score: p.score, band: p.band, coverage: p.coverage,
    f: p.factors.filter((f) => f.known).map((f) => [f.id, f.points, f.evidence]),
    floors: p.floors_applied,
  };
}

/**
 * Priority of a stored event, expanded to the public shape. Events recorded
 * before this engine carry no priority and their source fields were not
 * stored, so they are reported as INSUFFICIENT_EVIDENCE rather than re-scored
 * from partial data.
 */
export function eventPriority(event) {
  const p = event && event.priority;
  if (!p || typeof p !== "object" || !PRIORITY_BANDS.includes(p.band)) {
    return { version: PRIORITY_VERSION, score: null, band: "INSUFFICIENT_EVIDENCE", coverage: 0, factors: [], floors_applied: [], legacy: true };
  }
  if (Array.isArray(p.factors)) return p;
  const known = new Map((Array.isArray(p.f) ? p.f : []).map((row) => [row[0], row]));
  return {
    version: p.v || PRIORITY_VERSION,
    score: p.score ?? null,
    band: p.band,
    coverage: p.coverage ?? 0,
    factors: Object.keys(WEIGHTS).map((id) => {
      const row = known.get(id);
      return { id, label: LABELS[id], known: !!row, points: row ? row[1] : 0, max: WEIGHTS[id], evidence: row ? row[2] : null };
    }),
    floors_applied: Array.isArray(p.floors) ? p.floors : [],
  };
}

export function priorityRank(band) {
  return BAND_RANK[band] ?? 0;
}
