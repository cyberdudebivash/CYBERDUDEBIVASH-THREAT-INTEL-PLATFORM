// Read-only post-deploy acceptance of the public Revenue Engine health reply.
// This is a liveness/identity/version check, never an exact Git SHA attestation.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REVENUE_ENGINE_ID = 'SENTINEL-REVENUE-ENGINE';

export function healthMatches(body, expectedVersion) {
  return typeof expectedVersion === 'string' &&
    /^[0-9]+(?:\.[0-9]+)*$/.test(expectedVersion) &&
    body !== null && typeof body === 'object' && !Array.isArray(body) &&
    body.status === 'ok' &&
    body.engine === REVENUE_ENGINE_ID &&
    body.version === expectedVersion;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    process.stderr.write('Usage: node verify-public-health.mjs <response-json> <expected-version>\n');
    process.exitCode = 2;
  } else {
    try {
      // Restrict response size; health output must be small and unauthenticated.
      const bytes = readFileSync(process.argv[2]);
      if (bytes.length > 8192) throw new Error('oversized health response');
      const obj = JSON.parse(bytes.toString('utf8'));
      if (!healthMatches(obj, process.argv[3])) throw new Error('unexpected health identity or version');
      process.stdout.write('Public health: expected service, version, and ok status verified.\n');
    } catch {
      process.stderr.write('Public health acceptance FAILED.\n');
      process.exitCode = 1;
    }
  }
}
