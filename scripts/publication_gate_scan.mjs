#!/usr/bin/env node
/**
 * P0 bounded, read-only publication gate audit. It does NOT certify public
 * report delivery, nor authorize any R2/Pages/Cloudflare writes or charges.
 * Run: node scripts/publication_gate_scan.mjs
 * All feed windows must be readable for this scan to declare completeness.
 */
import { evaluatePublicationGate } from '../workers/intel-gateway/src/publication-gate.js';
import { summarizePublicationGate } from './publication_gate_audit_policy.mjs';

const BASE_URL = 'https://intel.cyberdudebivash.com';
const FEED_ENDPOINTS = Object.freeze([
  '/api/v1/intel/latest.json',
  '/api/v1/intel/top10.json',
  '/api/v1/intel/apex.json',
]);
const MAX_PER_FEED = 500;

async function fetchFeed(endpoint) {
  try {
    const response = await fetch(BASE_URL + endpoint, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache', 'User-Agent': 'SentinelApex-PublicationGateScan/2.0' },
    });
    if (!response.ok) throw new Error(`HTTP_${response.status}`);
    const data = await response.json();
    const items = Array.isArray(data) ? data :
      Array.isArray(data?.items) ? data.items :
      Array.isArray(data?.data) ? data.data : null;
    if (!items || items.length > MAX_PER_FEED) throw new Error('INVALID_OR_OVERSIZED_FEED');
    if (items.some(item => !item || typeof item !== 'object' || Array.isArray(item))) {
      throw new Error('MALFORMED_FEED_ITEM');
    }
    return { items };
  } catch (error) {
    // Log only bounded error types/codes, never response bodies, tokens or URLs.
    const code = /^HTTP_[0-9]{3}$|^INVALID_OR_OVERSIZED_FEED$|^MALFORMED_FEED_ITEM$/.test(error?.message || '')
      ? error.message : error?.name === 'TimeoutError' ? 'TIMEOUT' : 'FETCH_OR_PARSE_FAILED';
    return { error: `${endpoint}: ${code}` };
  }
}

async function main() {
  if (process.argv.length > 2) {
    console.error('[scan] Unexpected CLI arguments; production origin is fixed.');
    process.exitCode = 2;
    return;
  }
  const byId = new Map();
  const successes = [], errors = [];
  for (const endpoint of FEED_ENDPOINTS) {
    const result = await fetchFeed(endpoint);
    if (result.error) { errors.push(result.error); continue; }
    successes.push(endpoint);
    for (const item of result.items) {
      const candidate = item.stix_id || item.id;
      if (typeof candidate !== 'string' || !candidate) {
        errors.push(`${endpoint}: ITEM_MISSING_ID`);
        continue;
      }
      const id = candidate.replace(/\.html?$/, '');
      if (!byId.has(id)) byId.set(id, item);
    }
  }
  const results = [];
  for (const [id, item] of byId) {
    try {
      const gate = evaluatePublicationGate(item);
      results.push({
        report_id: id,
        publication_state: gate.publication_state,
        customer_ready: gate.customer_ready,
        blocking_gates: gate.blocking_gates,
      });
    } catch (_) {
      errors.push('EVALUATION_FAILED');
    }
  }
  const report = summarizePublicationGate({
    results, successfulEndpoints: successes,
    expectedEndpoints: FEED_ENDPOINTS, errors,
  });
  report.schema_version = 'publication_gate_scan.2.0';
  report.scanned_at = new Date().toISOString();
  console.log(JSON.stringify(report, null, 2));
  console.error(`[scan] ${report.verdict}: candidates=${report.candidates_evaluated}, ready=${report.customer_ready}, rejected=${report.rejected}, blocked=${report.blocked}, invalid=${report.malformed_or_conflicting}`);
  process.exitCode = report.exit_code;
}
main().catch(error => {
  console.error(`[scan] INCONCLUSIVE: ${error?.name || 'ERROR'}`);
  process.exitCode = 2;
});
