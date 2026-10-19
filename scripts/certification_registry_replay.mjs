#!/usr/bin/env node
/**
 * P0 OFFLINE certification source-state replay (no network / no R2 / no PUT).
 *
 * Consumes operator-supplied snapshots of the five objects read by the
 * customer-ready catalog Worker: report catalog, persisted certification
 * index, and latest_pro/latest/top10/apex rolling feed windows.
 * Reuses resolveCertification() directly -- no score reimplementation.
 *
 * Results are aggregate only. NEVER customer approval or delivery proof.
 */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveCertification, CERTIFICATION_POLICY_VERSION } from
  '../workers/intel-gateway/src/certification-registry.js';

export const FEED_ORDER = Object.freeze(['latest_pro', 'latest', 'top10', 'apex']);
const REPORT_ID = /^intel--[a-f0-9]{8,64}$/;
const MAX_OBJECT_BYTES = 8 * 1024 * 1024;
const MAX_ITEMS = 20000;
const FIELDS = Object.freeze({
  catalog: '--catalog',
  certificationIndex: '--certification-index',
  latest_pro: '--latest-pro',
  latest: '--latest',
  top10: '--top10',
  apex: '--apex',
});

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}
function normalizedId(item) {
  const raw = item?.stix_id || item?.id;
  const id = typeof raw === 'string' ? raw.replace(/\.html?$/, '') : '';
  return REPORT_ID.test(id) ? id : null;
}
function rows(document, key, field = 'items') {
  const records = Array.isArray(document) ? document :
    object(document) ? (document[field] ?? document.data) : null;
  if (!Array.isArray(records) || records.length > MAX_ITEMS ||
      records.some(r => !object(r))) {
    throw new Error('INVALID_' + key.toUpperCase() + '_ROWS');
  }
  return records;
}

export function replayCertificationSnapshots({
  catalog, certificationIndex, feeds,
}) {
  if (!object(catalog) || !Array.isArray(catalog.reports) ||
      !object(certificationIndex) ||
      certificationIndex.policy_version !== CERTIFICATION_POLICY_VERSION ||
      !object(certificationIndex.records) ||
      !object(feeds) ||
      Object.keys(feeds).length !== FEED_ORDER.length ||
      FEED_ORDER.some(name => !Object.hasOwn(feeds, name))) {
    throw new Error('INCOMPLETE_OR_UNTRUSTED_SNAPSHOT_SET');
  }
  const reportRows = rows(catalog, 'catalog', 'reports');
  if (reportRows.length === 0) throw new Error('EMPTY_REPORT_CATALOG');

  // Mirror _resolveFeedItemsById(): four R2 objects fetched independently;
  // first appearance in precedence order is selected for each report ID.
  const firstSource = new Map();
  for (const name of FEED_ORDER) {
    for (const item of rows(feeds[name], name)) {
      const id = normalizedId(item);
      if (id && !firstSource.has(id)) firstSource.set(id, { source: name, item });
    }
  }

  const counts = {
    CUSTOMER_READY: 0, REJECTED: 0, PENDING_ENRICHMENT: 0,
    WITHHELD: 0, NOT_EVALUATED: 0, OTHER_FAIL_CLOSED: 0,
  };
  const first_source_counts = Object.fromEntries(FEED_ORDER.map(s => [s, 0]));
  let persistedFound = 0, reusedPersisted = 0, newlyEvaluated = 0;
  let outsideFeed = 0, storedReadyWithoutFeed = 0;
  const seen = new Set();
  const records = certificationIndex.records;
  for (const entry of reportRows) {
    if (!object(entry) || typeof entry.id !== 'string' ||
        !REPORT_ID.test(entry.id) || seen.has(entry.id)) {
      throw new Error('INVALID_OR_DUPLICATE_CATALOG_ID');
    }
    const id = entry.id;
    seen.add(id);
    const source = firstSource.get(id);
    if (source) first_source_counts[source.source]++;
    else outsideFeed++;
    const existing = Object.hasOwn(records, id) ? records[id] : undefined;
    if (existing !== undefined) persistedFound++;
    const { record, isNew } = resolveCertification(existing, source?.item);
    if (!object(record) || typeof record.publication_status !== 'string')
      throw new Error('INCOMPLETE_CERTIFICATION_RESULT');
    if (isNew) newlyEvaluated++;
    else if (existing !== undefined && record === existing) reusedPersisted++;
    const state = record.publication_status;
    if (record.certification_status === 'NOT_EVALUATED') counts.NOT_EVALUATED++;
    else if (Object.hasOwn(counts, state)) counts[state]++;
    else counts.OTHER_FAIL_CLOSED++;
    if (!source && state === 'CUSTOMER_READY')
      storedReadyWithoutFeed++;
  }
  const fullCoverage = outsideFeed === 0;
  const allReady = counts.CUSTOMER_READY === seen.size;
  return {
    schema_version: 'offline_certification_registry_replay.v1',
    verdict: allReady ? 'LOCAL_ALL_READY_NOT_DELIVERY_CERTIFIED' :
      'LOCAL_WITHHELD_OR_NOT_EVALUATED',
    catalog_candidates: seen.size,
    report_feed_matches: seen.size - outsideFeed,
    outside_feed_windows: outsideFeed,
    first_source_counts,
    persisted_records_present: persistedFound,
    persisted_records_reused: reusedPersisted,
    re_evaluated_from_source: newlyEvaluated,
    persisted_customer_ready_without_feed: storedReadyWithoutFeed,
    publication_status_counts: counts,
    all_source_ids_covered: fullCoverage,
    replayed_persisted_results_not_independently_verified: true,
    source_snapshots_current_not_verified: true,
    production_r2_state_verified: false,
    full_catalog_rejection_reasons_verified: false,
    deployed_worker_parity_verified: false,
    report_http_delivery_certified: false,
    customer_release_certified: false,
    cloudflare_requests: 0,
  };
}

function parseArgs(argv) {
  if (argv.length !== Object.keys(FIELDS).length * 2) throw new Error('SIX_SNAPSHOTS_REQUIRED');
  const parsed = {};
  const expected = new Set(Object.values(FIELDS));
  for (let i = 0; i < argv.length; i += 2) {
    const option = argv[i], file = argv[i + 1];
    if (!expected.has(option) || !file || file.startsWith('--') ||
        Object.hasOwn(parsed, option)) throw new Error('INVALID_OFFLINE_SNAPSHOT_ARGUMENTS');
    parsed[option] = file;
  }
  if (Object.keys(parsed).length !== expected.size) throw new Error('SIX_SNAPSHOTS_REQUIRED');
  return parsed;
}
async function boundedLocalJSON(filename) {
  const path = resolve(filename);
  const { stat, open } = await import('node:fs/promises');
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_OBJECT_BYTES ||
      metadata.size === 0) throw new Error('INVALID_OR_OVERSIZED_LOCAL_SNAPSHOT');
  const handle = await open(path, 'r');
  try {
    // File size is checked again after open to reject a replaced/growing file.
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_OBJECT_BYTES || opened.size === 0)
      throw new Error('INVALID_OR_OVERSIZED_LOCAL_SNAPSHOT');
    const text = await handle.readFile({encoding:'utf8'});
    if (Buffer.byteLength(text) > MAX_OBJECT_BYTES)
      throw new Error('INVALID_OR_OVERSIZED_LOCAL_SNAPSHOT');
    return JSON.parse(text);
  } finally { await handle.close(); }
}
async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const snapshots = {};
    for (const [name, flag] of Object.entries(FIELDS))
      snapshots[name] = await boundedLocalJSON(args[flag]);
    const result = replayCertificationSnapshots({
      catalog: snapshots.catalog,
      certificationIndex: snapshots.certificationIndex,
      feeds: Object.fromEntries(FEED_ORDER.map(s => [s, snapshots[s]])),
    });
    console.log(JSON.stringify(result, null, 2));
    // The *successful command* means replay completed -- not a customer GO.
    // An unresolved, withheld or not-evaluated result must block a release gate.
    process.exitCode = result.verdict === 'LOCAL_ALL_READY_NOT_DELIVERY_CERTIFIED' ? 0 : 2;
  } catch (error) {
    console.log(JSON.stringify({
      schema_version:'offline_certification_registry_replay.v1',
      verdict:'BLOCKED_INVALID_LOCAL_EVIDENCE',
      issue: String(error?.message || 'UNKNOWN_ERROR').replace(/[^A-Z0-9_]/gi,'_').slice(0,90),
      cloudflare_requests:0, customer_release_certified:false,
    }, null, 2));
    process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main();
