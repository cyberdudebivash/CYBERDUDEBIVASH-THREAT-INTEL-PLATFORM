/**
 * P0 release ordering: prove the gateway serving the canonical production route
 * is the exact checkout commit BEFORE any paid/temporary credential is created.
 * Read-only, bounded, and independent of GitHub Actions job completion state.
 */
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const LIVE_URL = 'https://intel.cyberdudebivash.com/api/health/live';
const SHA_RE = /^[0-9a-f]{40}$/;

export async function awaitGatewayDeployment({
  expectedSha,
  fetchImpl = fetch,
  sleep = ms => new Promise(r => setTimeout(r, ms)),
  maxAttempts = 18,
  intervalMs = 12000,
  requestTimeoutMs = 4000,
  log = () => {},
} = {}) {
  if (!SHA_RE.test(expectedSha || '')) throw new Error('GATEWAY_DEPLOY_SHA_INVALID');
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 24) {
    throw new Error('GATEWAY_DEPLOY_ATTEMPTS_INVALID');
  }

  let reason = 'not_probed';
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetchImpl(LIVE_URL, {
        method: 'GET',
        headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
        cache: 'no-store',
        signal: AbortSignal.timeout(requestTimeoutMs),
      });

      if (res.status !== 200) {
        reason = 'http_non_200';
      } else {
        const live = await res.json();
        if (live?.status === 'alive' && live?.deploy_commit_sha === expectedSha) {
          log('GATEWAY_EXACT_SHA_CONFIRMED ' + expectedSha + ' attempt=' + attempt);
          return { attempt, sha: expectedSha };
        }
        reason = live?.status === 'alive' && SHA_RE.test(live?.deploy_commit_sha || '')
          ? 'deployment_sha_not_converged' : 'invalid_liveness_contract';
      }
    } catch {
      reason = 'liveness_unavailable';
    }

    // Never certify a different deployed commit and never touch auth state
    // on a missing/failed endpoint. All attempts are read-only GET requests.
    if (attempt < maxAttempts) {
      log('GATEWAY_DEPLOY_PENDING attempt=' + attempt + '/' + maxAttempts + ' reason=' + reason);
      await sleep(intervalMs);
    }
  }

  throw new Error('GATEWAY_DEPLOY_NOT_CONVERGED expected=' + expectedSha + ' last_reason=' + reason);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  awaitGatewayDeployment({
    expectedSha: process.env.GITHUB_SHA,
    log: message => console.log(message),
  }).catch(e => {
    console.error(e.message);
    process.exitCode = 1;
  });
}
