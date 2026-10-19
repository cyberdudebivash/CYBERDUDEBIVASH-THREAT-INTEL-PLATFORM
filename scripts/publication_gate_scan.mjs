#!/usr/bin/env node
/**
 * P0: bounded READ-ONLY authoritative publication-reason sample.
 *
 * Public latest/top10/apex feeds are deliberately sanitized/projected, so
 * recomputing evaluatePublicationGate(item) on them manufactures missing
 * P20/P23/P25 evidence and misleading blocker counts. Use their IDs ONLY to
 * select a bounded sample; ask the same Worker publication-status route that
 * controls /reports/** for the real reason codes. This cannot explain all
 * reports in the separate customer-ready catalog.
 *
 * Budget per one-shot operator run: 3 feed GETs + <=3 status GETs. No writes,
 * authentication, Cloudflare APIs, paid routes, R2 LIST, cron or auto-repeat.
 */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { summarizePublicationGate } from './publication_gate_audit_policy.mjs';

export const ORIGIN = 'https://intel.cyberdudebivash.com';
export const FEEDS = Object.freeze([
  '/api/v1/intel/latest.json',
  '/api/v1/intel/top10.json',
  '/api/v1/intel/apex.json',
]);
const REPORT_ID = /^intel--[a-f0-9]{8,64}$/;
const MAX_BYTES = 1_048_576;
const MAX_ITEMS = 500;
export const MAX_STATUS_PROBES = 3;
const REASON = /^[A-Z0-9_]{2,100}$/;

export function classifyAuthoritativeStatus(value, expectedId) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !REPORT_ID.test(expectedId) || value.report_id !== expectedId ||
      !['CUSTOMER_READY', 'REJECTED', 'BLOCKED'].includes(value.state) ||
      typeof value.customer_ready !== 'boolean' ||
      value.customer_ready !== (value.state === 'CUSTOMER_READY') ||
      !Array.isArray(value.reason_codes) ||
      value.reason_codes.some(code => typeof code !== 'string' || !REASON.test(code)) ||
      (value.customer_ready && value.reason_codes.length > 0) ||
      (!value.customer_ready && value.reason_codes.length === 0)) {
    return null;
  }
  return {
    report_id: expectedId,
    publication_state: value.state,
    customer_ready: value.customer_ready,
    blocking_gates: value.reason_codes,
  };
}

async function fixedJSON(path, fetchFn) {
  if (!FEEDS.includes(path) &&
      !/^\/api\/v1\/reports\/intel--[a-f0-9]{8,64}\/publication-status$/.test(path)) {
    throw new Error('UNAPPROVED_PATH');
  }
  const response = await fetchFn(ORIGIN + path, {
    method: 'GET', redirect: 'error', cache: 'no-store',
    signal: AbortSignal.timeout(8000),
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 200 ||
      !(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) {
    throw new Error('NON_200_OR_BAD_MIME');
  }
  const sizeHeader = response.headers.get('content-length');
  if (sizeHeader && (Number(sizeHeader) > MAX_BYTES || !Number.isFinite(Number(sizeHeader)))) {
    throw new Error('OVERSIZE');
  }
  if (!response.body?.getReader) throw new Error('NO_BOUNDED_BODY');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new Error('OVERSIZE');
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
}

export async function auditAuthoritativePublicationSample({ fetchFn = globalThis.fetch } = {}) {
  const errors = [], candidates = new Set();
  const successes = [];
  for (const path of FEEDS) {
    try {
      const data = await fixedJSON(path, fetchFn);
      const items = Array.isArray(data) ? data :
        Array.isArray(data?.items) ? data.items :
        Array.isArray(data?.data) ? data.data : null;
      if (!items || items.length > MAX_ITEMS || items.some(item =>
        !item || typeof item !== 'object' || Array.isArray(item))) {
        throw new Error('INVALID_FEED');
      }
      successes.push(path);
      for (const item of items) {
        // ID is the ONLY field used from the public projection.
        const id = item.id || item.stix_id;
        if (typeof id !== 'string' || !REPORT_ID.test(id)) {
          errors.push('PUBLIC_FEED_ID_UNPROVEN');
          continue;
        }
        candidates.add(id);
      }
    } catch (_) {
      errors.push('PUBLIC_FEED_UNAVAILABLE_OR_INVALID');
    }
  }

  const results = [];
  if (errors.length === 0 && candidates.size > 0) {
    for (const id of [...candidates].slice(0, MAX_STATUS_PROBES)) {
      try {
        const status = await fixedJSON('/api/v1/reports/' + id + '/publication-status', fetchFn);
        const classified = classifyAuthoritativeStatus(status, id);
        if (!classified) throw new Error('INVALID_VERDICT');
        results.push(classified);
      } catch (_) {
        errors.push('PUBLICATION_STATUS_UNAVAILABLE_OR_INVALID');
      }
    }
  }
  const summarized = summarizePublicationGate({
    results, successfulEndpoints: successes, expectedEndpoints: FEEDS, errors,
  });
  const complete = summarized.exit_code !== 2 &&
    results.length > 0 && results.length <= MAX_STATUS_PROBES &&
    errors.length === 0;
  const hasWithheld = summarized.rejected + summarized.blocked > 0;
  return {
    schema_version: 'publication_reason_sample.3.0',
    verdict: !complete ? 'INCONCLUSIVE_AUTHORITY_SAMPLE' :
      hasWithheld ? 'AUTHORITATIVE_SAMPLE_WITHHELD' : 'AUTHORITATIVE_SAMPLE_READY_NOT_RELEASE',
    exit_code: !complete ? 2 : hasWithheld ? 1 : 0,
    scope: 'At most three public feed IDs; NOT the entire customer-ready report catalog',
    sampled: results.length,
    rejected: summarized.rejected,
    blocked: summarized.blocked,
    customer_ready: summarized.customer_ready,
    sample_reason_counts: complete ? summarized.reason_counts : {},
    sample_withheld: complete ? summarized.withheld_samples : [],
    issues: [...new Set(errors)].sort(),
    sampled_statuses_from_worker: complete,
    full_catalog_reasons_verified: false,
    customer_release_certified: false,
    paid_entitlement_certified: false,
  };
}

async function main() {
  if (process.argv.length !== 2) {
    console.error('P0_READ_ONLY_SCAN_TAKES_NO_ARGS');
    process.exitCode = 2;
    return;
  }
  const outcome = await auditAuthoritativePublicationSample();
  console.log(JSON.stringify(outcome, null, 2));
  process.exitCode = outcome.exit_code;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    console.error('INCONCLUSIVE_SCAN_ERROR');
    process.exitCode = 2;
  });
}
