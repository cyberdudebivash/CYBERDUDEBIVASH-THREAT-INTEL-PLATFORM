#!/usr/bin/env node
/**
 * P0 #725 — confidential-operator read-only diagnostic for ONE local copy of
 * the exact R2 key api/v1/intel/latest.json.
 *
 * No network calls, storage writes, customer identities or record contents.
 * Use an already-authorized R2 credential outside this process to download
 * the single object into a protected temporary file; delete that temp file
 * after analysis. Do not place it in a public Git checkout or CI artifact.
 *
 * The ONLY positive read-boundary authority is the real Worker function
 * publicTlpJsonVerified(), not a permissive shadow implementation.
 * This diagnostic additionally highlights unlabeled top-level records whose
 * missing title might make the Worker's document walk fail to identify them.
 */
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { publicTlpJsonVerified } from "../workers/intel-gateway/src/intel-static-proxy.js";
import { evaluatePublicIntelligence } from "../workers/intel-gateway/src/freshness-contract.js";

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_NODES = 25000;
const MAX_DEPTH = 40;
const LABELS = Object.freeze(["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED", "MISSING", "INVALID"]);
const MARKER_KEYS = ["id", "advisory_id", "intel_id", "report_url", "internal_report_url", "cve_id", "stix_id", "cve_ids", "threat_id"];

export function auditPublicFeedDocument(doc, nowMs = Date.now()) {
  // Report only safe aggregate counts, never record identifiers, source URLs,
  // titles, IOCs or evidence fields.
  const fresh = evaluatePublicIntelligence(doc, nowMs);
  const count = Object.fromEntries(LABELS.map(label => [label, 0]));
  const evidence = Object.fromEntries(LABELS.map(label => [label, 0]));
  let nestedNodes = 0, maxDepth = 0, missingAdvisoryLabels = 0;
  let budgetExceeded = false;
  const normalize = raw => {
    if (typeof raw !== "string") return "INVALID";
    const label = raw.trim().toUpperCase().replace(/\s+/g, "");
    return LABELS.includes(label) ? label : "INVALID";
  };
  function walk(node, depth) {
    if (++nestedNodes > MAX_NODES || depth > MAX_DEPTH) { budgetExceeded = true; return; }
    maxDepth = Math.max(maxDepth, depth);
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) { for (const value of node) walk(value, depth + 1); return; }
    if (typeof node.title === "string" && MARKER_KEYS.some(k => Object.hasOwn(node, k))
        && !Object.hasOwn(node, "tlp") && !Object.hasOwn(node, "tlp_label")) {
      missingAdvisoryLabels++;
    }
    for (const k of ["tlp", "tlp_label"]) {
      if (Object.hasOwn(node, k)) evidence[normalize(node[k])]++;
    }
    for (const value of Object.values(node)) walk(value, depth + 1);
  }

  const items = Array.isArray(doc?.items) ? doc.items : [];
  for (const item of items) {
    const raw = item?.tlp ?? item?.tlp_label ?? null;
    count[raw === null ? "MISSING" : normalize(raw)]++;
  }
  walk(doc, 0);
  const checked = !budgetExceeded && publicTlpJsonVerified(doc);
  const allTopLevelClear = items.length > 0 && count["TLP:CLEAR"] === items.length;
  const ready = fresh.healthy && checked && allTopLevelClear && missingAdvisoryLabels === 0;
  return {
    verdict: ready ? "DELIVERABLE" : "BLOCKED",
    // Do not reuse this result to authorize customer delivery: the Worker
    // always remains the authority and must independently read the bytes.
    freshness: fresh.healthy ? "FRESH" : "UNAVAILABLE",
    freshness_reason_code: fresh.reason || null,
    worker_public_tlp_gate: checked ? "PASS" : "BLOCKED",
    record_count: items.length,
    top_level_label_counts: count,
    nested_label_counts: evidence,
    unlabeled_advisory_candidates: missingAdvisoryLabels,
    worker_node_budget_exceeded: budgetExceeded,
    // A numerical reason that does not expose which advisory caused failure.
    root_cause_family: !fresh.healthy ? "FEED_FRESHNESS_OR_STRUCTURE"
      : budgetExceeded ? "PUBLICATION_NODE_BUDGET"
      : !checked ? "TLP_BOUNDARY_REJECTION"
      : !allTopLevelClear ? "UNLABELED_OR_RESTRICTED_RECORDS"
      : missingAdvisoryLabels ? "UNLABELED_NESTED_ADVISORY" : "NONE",
  };
}

export function inspectLocalFile(path, nowMs = Date.now()) {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size < 2 || stat.size > MAX_FILE_BYTES) {
    throw new Error("LOCAL_FILE_MISSING_OR_OUT_OF_BOUNDS");
  }
  const raw = readFileSync(path, "utf8");
  let doc;
  try { doc = JSON.parse(raw); }
  catch { throw new Error("LOCAL_DOCUMENT_NOT_JSON"); }
  return auditPublicFeedDocument(doc, nowMs);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.length !== 3 || !process.argv[2]) {
    console.error("Usage: node scripts/p0_r2_public_feed_diagnostic.mjs <LOCAL_PRIVATE_R2_JSON>");
    process.exitCode = 2;
  } else {
    try {
      const result = inspectLocalFile(process.argv[2]);
      console.log(JSON.stringify(result, null, 2));
      if (result.verdict !== "DELIVERABLE") process.exitCode = 1;
    } catch (e) {
      // Never print path, content, parser diagnostics or stack trace:
      // those can contain sensitive local directory names or source bytes.
      console.error("P0_PUBLIC_FEED_DIAGNOSTIC: INPUT_UNAVAILABLE_OR_INVALID");
      process.exitCode = 2;
    }
  }
}
