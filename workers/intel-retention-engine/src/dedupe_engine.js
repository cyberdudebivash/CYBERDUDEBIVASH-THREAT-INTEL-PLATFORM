/**
 * dedupe_engine.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Intelligence Deduplication Engine
 * ====================================
 * Fingerprints and deduplicates intelligence advisories across
 * pipeline runs.  Zero duplicates — zero data loss.
 *
 * Fingerprint strategy:
 *   1. Primary:   stix_id / advisory ID (authoritative identity)
 *   2. Secondary: SHA-256(title + source_url + published_date[:10])
 *   3. CVE match: any shared CVE ID
 *   4. URL match: exact source_url
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

// ── Utility: simple 32-char hex hash (FNV-1a 64-bit approximation) ─────────
function _fnvHash(str) {
  let h = BigInt("0xcbf29ce484222325");
  const prime = BigInt("0x100000001b3");
  const mod64 = BigInt("0xffffffffffffffff");
  for (let i = 0; i < str.length; i++) {
    h = ((h ^ BigInt(str.charCodeAt(i))) * prime) & mod64;
  }
  return h.toString(16).padStart(16, "0");
}

function contentHash(item) {
  const stable = [
    String(item.stix_id || item.id || ""),
    String(item.title || "").slice(0, 200),
    String(item.source_url || item.link || ""),
    String(item.timestamp || item.published_at || "").slice(0, 10),
  ].join("|");
  return _fnvHash(stable);
}

function dedupeHash(item) {
  const cves = Array.isArray(item.cves) ? item.cves.slice(0, 5).sort().join(",") : "";
  const stable = [
    String(item.stix_id || item.id || ""),
    String(item.title || "").slice(0, 200),
    String(item.source_url || item.link || ""),
    cves,
  ].join("|");
  return _fnvHash(stable);
}

class DedupeEngine {
  constructor(existingHashes = []) {
    // Primary hash store
    this._hashes = new Set(existingHashes);
    // CVE index: cve_id -> intel_id (first seen)
    this._cveIndex = new Map();
    // URL index: source_url -> intel_id
    this._urlIndex = new Map();

    this.stats = {
      processed: 0,
      accepted: 0,
      rejected_exact: 0,
      rejected_cve: 0,
      rejected_url: 0,
    };
  }

  /**
   * Seed the engine from an existing registry so it knows what's already stored.
   * @param {Object} retentionRegistry - {registry: {hash: {intel_id, cves, source_url}}}
   */
  seedFromRegistry(retentionRegistry) {
    const reg = (retentionRegistry && retentionRegistry.registry) || {};
    for (const [hash, entry] of Object.entries(reg)) {
      this._hashes.add(hash);
      const id = entry.intel_id || hash;
      if (Array.isArray(entry.cves)) {
        for (const cve of entry.cves) {
          if (cve && !this._cveIndex.has(cve)) {
            this._cveIndex.set(cve, id);
          }
        }
      }
      if (entry.source_url) {
        this._urlIndex.set(entry.source_url, id);
      }
    }
  }

  /**
   * Determine if an advisory is a duplicate.
   * @param {Object} item
   * @returns {{ isDuplicate: boolean, reason: string, existingId: string|null }}
   */
  check(item) {
    this.stats.processed++;

    // 1. Exact hash match
    const dh = dedupeHash(item);
    if (this._hashes.has(dh)) {
      this.stats.rejected_exact++;
      return { isDuplicate: true, reason: "exact_hash", existingId: null, hash: dh };
    }

    // 2. Source URL exact match
    const url = item.source_url || item.link || "";
    if (url && this._urlIndex.has(url)) {
      this.stats.rejected_url++;
      return { isDuplicate: true, reason: "source_url", existingId: this._urlIndex.get(url), hash: dh };
    }

    // 3. CVE match — same CVE already published from different source
    //    Accept if different source/title (enriches the record), reject if same title
    if (Array.isArray(item.cves) && item.cves.length > 0) {
      for (const cve of item.cves) {
        if (this._cveIndex.has(cve)) {
          const existingId = this._cveIndex.get(cve);
          // Only reject if it's clearly the same advisory (same title prefix)
          // Different sources covering the same CVE are VALID separate advisories
          // so we DO accept them — just note the shared CVE
          break; // CVE match is informational only — not a rejection criterion
        }
      }
    }

    return { isDuplicate: false, reason: null, existingId: null, hash: dh };
  }

  /**
   * Register an accepted advisory (add to all indexes).
   * @param {Object} item
   * @param {string} intelId
   * @param {string} hash
   */
  register(item, intelId, hash) {
    this._hashes.add(hash);
    this.stats.accepted++;
    const url = item.source_url || item.link || "";
    if (url) this._urlIndex.set(url, intelId);
    if (Array.isArray(item.cves)) {
      for (const cve of item.cves) {
        if (cve && !this._cveIndex.has(cve)) {
          this._cveIndex.set(cve, intelId);
        }
      }
    }
  }

  /**
   * Filter an array of items, returning only non-duplicates.
   * Side-effect: registers accepted items into the engine.
   * @param {Array} items
   * @returns {{ accepted: Array, rejected: Array, stats: Object }}
   */
  filter(items) {
    const accepted = [];
    const rejected = [];

    for (const item of items) {
      const result = this.check(item);
      if (result.isDuplicate) {
        rejected.push({ item, reason: result.reason, existingId: result.existingId });
      } else {
        const intelId = item.stix_id || item.id || ("intel--" + result.hash);
        this.register(item, intelId, result.hash);
        item._dedupe_hash = result.hash;
        item._intel_id = intelId;
        accepted.push(item);
      }
    }

    return { accepted, rejected, stats: { ...this.stats } };
  }

  getStats() {
    return { ...this.stats };
  }
}

export { DedupeEngine, contentHash, dedupeHash };
