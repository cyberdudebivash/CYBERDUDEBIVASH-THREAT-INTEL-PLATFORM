/**
 * retention_policy_engine.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Intelligence Retention Policy Engine
 * =======================================
 * Governs lifecycle state of every advisory.
 * NEVER deletes.  Lifecycle archive only.
 *
 * States: ACTIVE -> MONITORING -> ARCHIVED
 * Permanent: KEV, APT, RANSOMWARE, NATION_STATE, MAJOR_BREACH
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

// ── Retention policy (days) ────────────────────────────────────────────────
const RETENTION_DAYS = {
  CRITICAL:      730,  // 24 months
  HIGH:          545,  // 18 months
  MEDIUM:        365,  // 12 months
  LOW:           180,  //  6 months
  INFO:           90,
  UNKNOWN:       180,
};

// Permanent categories (null = never expire)
const PERMANENT_CATEGORIES = new Set([
  "KEV", "APT", "RANSOMWARE", "NATION_STATE", "NATION-STATE",
  "MAJOR_BREACH", "MAJOR BREACH", "SUPPLY_CHAIN", "SUPPLY CHAIN",
]);

const PERMANENT_KEYWORDS = [
  "ransomware", "apt ", " apt-", "nation.state", "nation-state",
  "espionage", "state.sponsored", "state-sponsored",
  "critical infrastructure", "major breach", "supply chain attack",
  "zero.day", "zero-day", "kev",
];

// Lifecycle states
const STATE = {
  ACTIVE:     "ACTIVE",
  MONITORING: "MONITORING",
  ARCHIVED:   "ARCHIVED",
};

class RetentionPolicyEngine {
  constructor() {
    this.stats = {
      active:     0,
      monitoring: 0,
      archived:   0,
      permanent:  0,
      total:      0,
    };
  }

  /**
   * Determine if an advisory is permanently retained.
   */
  isPermanent(item) {
    // Explicit KEV flag
    if (item.is_kev || item.kev || item.cisa_kev) return true;

    // Explicit permanent category
    const cat = String(item.category || item.threat_type || "").toUpperCase();
    if (PERMANENT_CATEGORIES.has(cat)) return true;

    // Keyword scan across all text fields
    const text = [
      item.title || "",
      item.tags || "",
      item.threat_type || "",
      item.actor_tag || "",
      String(item.mitre_tactics || ""),
    ].join(" ").toLowerCase();

    return PERMANENT_KEYWORDS.some(kw => text.includes(kw));
  }

  /**
   * Calculate retention period in days. Returns null for permanent items.
   */
  getRetentionDays(item) {
    if (this.isPermanent(item)) return null;
    const sev = String(item.severity || "MEDIUM").toUpperCase();
    return RETENTION_DAYS[sev] ?? RETENTION_DAYS.MEDIUM;
  }

  /**
   * Calculate retention_until date. Returns null for permanent items.
   */
  getRetentionUntil(item, publishedDate) {
    const days = this.getRetentionDays(item);
    if (days === null) return null;
    const pub = publishedDate instanceof Date ? publishedDate : new Date(publishedDate || Date.now());
    const ret = new Date(pub.getTime() + days * 24 * 60 * 60 * 1000);
    return ret.toISOString();
  }

  /**
   * Determine current lifecycle state.
   */
  getLifecycleState(item, retentionUntil, createdAt) {
    if (retentionUntil === null) return STATE.ACTIVE; // Permanent

    const now = Date.now();
    const retUntil = new Date(retentionUntil).getTime();
    if (now > retUntil) {
      return STATE.ARCHIVED; // Past retention — NEVER delete, just archive
    }

    const created = new Date(createdAt || now).getTime();
    const ageDays = (now - created) / (1000 * 60 * 60 * 24);

    if (ageDays <= 30) return STATE.ACTIVE;
    if (ageDays <= 90) return STATE.MONITORING;
    return STATE.MONITORING;
  }

  /**
   * Build full retention metadata for an advisory.
   */
  buildRetentionMeta(item, publishedDate) {
    const isPermanent = this.isPermanent(item);
    const retDays     = this.getRetentionDays(item);
    const retUntil    = this.getRetentionUntil(item, publishedDate);
    const pubDate     = publishedDate ? new Date(publishedDate).toISOString() : new Date().toISOString();
    const state       = this.getLifecycleState(item, retUntil, pubDate);

    this.stats.total++;
    if (isPermanent) this.stats.permanent++;
    this.stats[state.toLowerCase()]++;

    return {
      is_permanent:    isPermanent,
      retention_days:  retDays,
      retention_until: retUntil,
      retention_category: isPermanent ? "PERMANENT" : String(item.severity || "MEDIUM").toUpperCase(),
      lifecycle_state: state,
      created_at:      pubDate,
      last_evaluated:  new Date().toISOString(),
    };
  }

  /**
   * Apply retention policy to a batch of items.
   * @returns {Array} items enriched with retention_meta field
   */
  applyBatch(items) {
    return items.map(item => {
      const publishedDate = item.published_at || item.timestamp || item.created_at;
      const meta = this.buildRetentionMeta(item, publishedDate);
      return { ...item, retention_meta: meta, lifecycle_state: meta.lifecycle_state };
    });
  }

  /**
   * Policy summary report for governance.
   */
  getPolicySummary() {
    return {
      policy: {
        CRITICAL:      "24 months",
        HIGH:          "18 months",
        MEDIUM:        "12 months",
        LOW:           "6 months",
        KEV:           "PERMANENT",
        APT:           "PERMANENT",
        RANSOMWARE:    "PERMANENT",
        NATION_STATE:  "PERMANENT",
        MAJOR_BREACH:  "PERMANENT",
      },
      compliance: {
        note: "No advisory is ever deleted. Lifecycle archive only.",
        enforcement: "Automatic via retention_policy_engine.js",
      },
      stats: { ...this.stats },
    };
  }

  getStats() {
    return { ...this.stats };
  }
}

export { RetentionPolicyEngine, RETENTION_DAYS, PERMANENT_CATEGORIES, STATE };
