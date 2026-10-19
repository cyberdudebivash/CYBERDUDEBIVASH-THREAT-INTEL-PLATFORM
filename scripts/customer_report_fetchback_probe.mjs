#!/usr/bin/env node
/**
 * SENTINEL APEX customer-ready public report fetch-back canary (read-only).
 * Strictly separate public advisory feed health from customer-ready report
 * availability. This NEVER certifies paid entitlement or release readiness.
 * Network budget: one catalog GET plus at most three approved report GETs.
 */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const ORIGIN = 'https://intel.cyberdudebivash.com';
export const CATALOG_PATH = '/api/reports/index.json';
const MAX_BYTES = 1_048_576;
const MAX_REPORTS = 3;

const CATALOG_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
// The v2 report catalog emitter uses canonical UTC, never inferred local time.
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

function canonicalCatalogTime(value) {
  if (typeof value !== 'string' || !UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  // Date.parse may silently normalize impossible calendar dates.
  // Reject these instead of treating corrected dates as trusted provenance.
  if (new Date(parsed).toISOString().slice(0, 19) !== value.slice(0, 19)) return null;
  return parsed;
}
const REPORT_PATH = /^\/reports\/20\d{2}\/(?:0[1-9]|1[0-2])\/(intel--[a-f0-9]{8,64})\.html$/;

export function approvedReportPath(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const paths = [entry.path, entry.url].filter(v => v !== undefined && v !== null);
  if (paths.length === 0) return null;
  const normalized = [];
  for (const value of paths) {
    if (typeof value !== 'string' || value.length > 300 ||
        !value || /[%\\]/.test(value)) return null;
    let url;
    try { url = new URL(value, ORIGIN); } catch { return null; }
    if (url.origin !== ORIGIN || url.username || url.password ||
        url.port || url.search || url.hash || !REPORT_PATH.test(url.pathname) ||
        url.pathname.includes('..')) return null;
    normalized.push(url.pathname);
  }
  if (new Set(normalized).size !== 1) return null;
  const path = normalized[0];
  const id = REPORT_PATH.exec(path)[1];
  if (entry.id !== id) return null;
  return path;
}

export function evaluatePublicReportCatalog(catalog, {
  sampleSize = MAX_REPORTS, nowMs = Date.now(),
} = {}) {
  const issues = [];
  if (!Number.isSafeInteger(sampleSize) || sampleSize < 1 || sampleSize > MAX_REPORTS)
    throw new RangeError('INVALID_SAMPLE_BUDGET');
  const isObject = catalog && typeof catalog === 'object' && !Array.isArray(catalog);
  if (!isObject || catalog.schema_version !== '2.0.0' ||
      catalog.feed_type !== 'customer_ready_catalog') issues.push('INVALID_CATALOG_SCHEMA');
  // A response can be internally consistent yet be an obsolete snapshot.
  // Fresh, provenance-compatible generation and validation are mandatory.
  if (!Number.isFinite(nowMs)) throw new RangeError('INVALID_AUDIT_CLOCK');
  const generated = canonicalCatalogTime(catalog?.generated_at);
  const validated = canonicalCatalogTime(catalog?.validated_at);
  if (generated === null) issues.push('INVALID_CATALOG_GENERATED_AT');
  if (validated === null) issues.push('INVALID_CATALOG_VALIDATED_AT');
  for (const [key, time] of [['GENERATED', generated], ['VALIDATED', validated]]) {
    if (time === null) continue;
    if (time > nowMs + MAX_FUTURE_SKEW_MS)
      issues.push('CATALOG_' + key + '_IN_FUTURE');
    if (nowMs - time > CATALOG_MAX_AGE_MS)
      issues.push('CATALOG_' + key + '_STALE');
  }
  if (generated !== null && validated !== null && validated < generated)
    issues.push('CATALOG_VALIDATION_PRECEDES_GENERATION');
  const positiveCounts = ['total_candidates', 'customer_ready_count', 'withheld_count',
    'total_reports', 'reports_listed'];
  for (const key of positiveCounts) {
    if (!Number.isSafeInteger(catalog?.[key]) || catalog[key] < 0)
      issues.push('INVALID_CATALOG_COUNT_' + key.toUpperCase());
  }
  const candidates = catalog?.total_candidates;
  const ready = catalog?.customer_ready_count;
  const withheld = catalog?.withheld_count;
  const listed = catalog?.reports_listed;
  const reports = catalog?.reports;
  if (!Array.isArray(reports)) issues.push('INVALID_REPORT_LIST');
  if (Number.isSafeInteger(candidates) && Number.isSafeInteger(ready) &&
      Number.isSafeInteger(withheld) && ready + withheld !== candidates)
    issues.push('CATALOG_COUNT_MISMATCH');
  if (Array.isArray(reports) && Number.isSafeInteger(listed) &&
      listed !== reports.length) issues.push('CATALOG_LISTED_COUNT_MISMATCH');
  if (Number.isSafeInteger(listed) && Number.isSafeInteger(ready) && listed > ready)
    issues.push('CATALOG_LIST_EXCEEDS_READY');
  if (Number.isSafeInteger(candidates) && candidates === 0) issues.push('NO_REPORT_CANDIDATES');
  if (Number.isSafeInteger(candidates) && candidates > 0 && ready === 0)
    issues.push('ZERO_CUSTOMER_READY_REPORTS');
  if (Number.isSafeInteger(ready) && ready > 0 && listed === 0)
    issues.push('READY_REPORTS_NOT_LISTED');
  const safeSamples = [];
  if (Array.isArray(reports)) {
    for (const report of reports.slice(0, sampleSize)) {
      const path = approvedReportPath(report);
      if (!path || safeSamples.some(x => x.path === path)) {
        issues.push('INVALID_OR_DUPLICATE_REPORT_LOCATOR');
      } else safeSamples.push({ path, id: report.id });
    }
  }
  const complete = issues.length === 0 && safeSamples.length > 0;
  return {
    schema_version: 'public-report-fetchback.v1',
    verdict: complete ? 'PUBLIC_REPORT_FETCHBACK_REQUIRED' : 'BLOCKED',
    exit_code: complete ? 0 : 2,
    issues: [...new Set(issues)].sort(),
    total_candidates: Number.isSafeInteger(candidates) ? candidates : null,
    customer_ready_count: Number.isSafeInteger(ready) ? ready : null,
    withheld_count: Number.isSafeInteger(withheld) ? withheld : null,
    candidate_paths: complete ? safeSamples : [],
    feed_health_is_not_report_delivery: true,
    customer_release_certified: false,
    paid_entitlement_certified: false,
    all_reports_delivered_certified: false,
  };
}

async function readBounded(response) {
  const announced = Number(response.headers.get('content-length') || 0);
  if (announced > MAX_BYTES || !response.body?.getReader) throw new Error('INVALID_OR_OVERSIZE_RESPONSE');
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_BYTES) throw new Error('RESPONSE_TOO_LARGE');
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks, bytes).toString('utf8');
}

export async function fetchPublic(path, fetchFn = globalThis.fetch) {
  if (path !== CATALOG_PATH && !REPORT_PATH.test(path)) throw new Error('UNAPPROVED_PATH');
  if (typeof fetchFn !== 'function') throw new Error('FETCH_UNAVAILABLE');
  const response = await fetchFn(ORIGIN + path, {
    method: 'GET', redirect: 'error', cache: 'no-store',
    signal: AbortSignal.timeout(9000),
    headers: { Accept: path === CATALOG_PATH ? 'application/json' : 'text/html' },
  });
  if (response.status !== 200) throw new Error('HTTP_' + response.status);
  const mime = (response.headers.get('content-type') || '').toLowerCase();
  if (!mime.startsWith(path === CATALOG_PATH ? 'application/json' : 'text/html'))
    throw new Error('UNEXPECTED_CONTENT_TYPE');
  return readBounded(response);
}

export async function runPublicReportFetchback({ fetchFn = globalThis.fetch } = {}) {
  let catalog;
  try {
    catalog = JSON.parse(await fetchPublic(CATALOG_PATH, fetchFn));
  } catch {
    return { verdict:'INCONCLUSIVE_CATALOG_UNAVAILABLE', exit_code:2,
      customer_release_certified:false, public_report_sample_certified:false,
      issues:['CATALOG_FETCH_OR_PARSE_FAILED'] };
  }
  const precheck = evaluatePublicReportCatalog(catalog);
  if (precheck.exit_code !== 0) {
    return { ...precheck, public_report_sample_certified:false };
  }
  const probes = [];
  for (const { path, id } of precheck.candidate_paths) {
    try {
      const html = await fetchPublic(path, fetchFn);
      if (!/<html(?:\s|>)/i.test(html) || !html.includes(id))
        throw new Error('REPORT_CONTENT_ID_NOT_VERIFIED');
      probes.push({ path, status:'PASS' });
    } catch {
      probes.push({ path, status:'FAIL' });
    }
  }
  const allPass = probes.length > 0 && probes.every(p => p.status === 'PASS');
  return {
    ...precheck,
    verdict: allPass ? 'PUBLIC_REPORT_SAMPLE_PASS_NOT_CUSTOMER_RELEASE' : 'BLOCKED_REPORT_FETCHBACK',
    exit_code: allPass ? 0 : 2, probes,
    public_report_sample_certified: allPass,
    customer_release_certified:false,
    paid_entitlement_certified:false,
    all_reports_delivered_certified:false,
  };
}

async function main() {
  if (process.argv.length !== 2) {
    console.error('P0_READ_ONLY_PROBE_TAKES_NO_ARGS');
    process.exitCode = 2;
    return;
  }
  const result = await runPublicReportFetchback();
  console.log(JSON.stringify(result,null,2));
  process.exitCode = result.exit_code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    console.error('INCONCLUSIVE_INTERNAL_ERROR');
    process.exitCode = 2;
  });
}
