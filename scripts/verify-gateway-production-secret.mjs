/**
 * Interpret Wrangler's production-environment `secret list` JSON without
 * printing credentials, secret names or the response. The caller is
 * responsible for running `wrangler secret list --env production` and for
 * failing closed if that command itself fails. No network operations here.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function hasRequiredGatewayJwtSecret(source) {
  if (typeof source !== 'string' || source.length === 0 ||
      source.length > 65536) return false;
  try {
    const entries = JSON.parse(source);
    return Array.isArray(entries) &&
      entries.length <= 512 &&
      entries.some(entry => entry && typeof entry === 'object' &&
        !Array.isArray(entry) &&
        entry.name === 'CDB_JWT_SECRET');
  } catch {
    return false;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let source = null;
  try { source = readFileSync(0, 'utf8'); } catch {}
  if (!hasRequiredGatewayJwtSecret(source)) {
    process.stderr.write('FATAL: named-production CDB_JWT_SECRET presence not verifiable\n');
    process.exitCode = 1;
  } else {
    process.stdout.write('Named production JWT signing secret presence verified\n');
  }
}
