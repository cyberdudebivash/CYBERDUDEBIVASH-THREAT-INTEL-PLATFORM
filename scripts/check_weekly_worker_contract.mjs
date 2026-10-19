/**
 * Fail-closed parity gate for the exact Worker R2 weekly route, BEFORE upload.
 * Never logs advisory bodies or customer PII. No network, filesystem writes,
 * Cloudflare mutations, or source substitution. Node 22+.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import {
  MAX_PUBLIC_BODY_BYTES,
  publicTlpJsonVerified,
  weeklyBriefIsCurrent,
} from '../workers/intel-gateway/src/intel-static-proxy.js';

export function validateWorkerWeeklyCandidate(raw, currentMs = Date.now()) {
  if (!Buffer.isBuffer(raw)) throw new TypeError('Expected raw JSON buffer');
  if (raw.byteLength < 2 || raw.byteLength > MAX_PUBLIC_BODY_BYTES) {
    throw new Error('WEEKLY_WORKER_CONTRACT_BODY_SIZE');
  }
  let doc;
  try { doc = JSON.parse(raw.toString('utf8')); }
  catch { throw new Error('WEEKLY_WORKER_CONTRACT_INVALID_JSON'); }
  if (!publicTlpJsonVerified(doc)) {
    throw new Error('WEEKLY_WORKER_CONTRACT_TLP_DENIED');
  }
  if (!weeklyBriefIsCurrent(doc, currentMs)) {
    throw new Error('WEEKLY_WORKER_CONTRACT_STALE_OR_INVALID');
  }
  return {week: doc.week, size_bytes: raw.byteLength};
}

// Run as CLI only when executed directly, not when imported for tests.
const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  const path = process.argv[2] || resolve(dirname(fileURLToPath(import.meta.url)), '..', 'api/v1/intel/weekly_brief.json');
  try {
    const result = validateWorkerWeeklyCandidate(readFileSync(path));
    console.log('[PASS] Weekly candidate passes exact Worker TLP, body-size, schema/date freshness gates:',
      result.week, '(' + result.size_bytes + ' bytes)');
  } catch (err) {
    console.error('::error::Weekly R2 publication blocked:', err.message);
    process.exitCode = 1;
  }
}
