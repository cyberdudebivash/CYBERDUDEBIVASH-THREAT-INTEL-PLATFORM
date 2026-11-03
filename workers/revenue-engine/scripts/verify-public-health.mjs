// Read-only post-deploy check: public health must reflect the EXACT approved
// source SHA, in addition to service identity and version. It verifies the
// current route's deployed config claim; it is not a cryptographic bundle hash.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REVENUE_ENGINE_ID = 'SENTINEL-REVENUE-ENGINE';
export const EXPECTED_SHA_PATTERN = /^[a-f0-9]{40}$/;

export function healthMatches(body, expectedVersion, expectedSha) {
  return typeof expectedVersion === 'string' &&
    /^[0-9]+(?:\.[0-9]+)*$/.test(expectedVersion) &&
    typeof expectedSha === 'string' &&
    EXPECTED_SHA_PATTERN.test(expectedSha) &&
    body !== null && typeof body === 'object' && !Array.isArray(body) &&
    body.status === 'ok' &&
    body.engine === REVENUE_ENGINE_ID &&
    body.version === expectedVersion &&
    body.release_sha === expectedSha;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 5) {
    process.stderr.write('Usage: node verify-public-health.mjs <response-json> <expected-version> <approved-commit-sha>\n');
    process.exitCode = 2;
  } else {
    try {
      // Bound response bytes to reduce accidental logs and memory exposure.
      const bytes = readFileSync(process.argv[2]);
      if (bytes.length > 8192) throw new Error('oversized health response');
      const obj = JSON.parse(bytes.toString('utf8'));
      if (!healthMatches(obj, process.argv[3], process.argv[4])) {
        throw new Error('unexpected public health release identity');
      }
      process.stdout.write('Public health: service, version, and approved SHA claim verified.\n');
    } catch {
      process.stderr.write('Public health release-identity acceptance FAILED.\n');
      process.exitCode = 1;
    }
  }
}
