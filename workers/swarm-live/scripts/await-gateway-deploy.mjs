/**
 * P0 release ordering: prove the gateway serving the canonical production route
 * is the exact checkout commit BEFORE any paid/temporary credential is created.
 * Read-only, bounded, and independent of GitHub Actions job completion state.
 */
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

// Resolve git execution to the repository ROOT, independent of workflow\n// working-directory=workers/swarm-live. Git pathspecs are otherwise scoped to\n// the current working directory and can silently match zero files.\nconst REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');\nconst GATEWAY_RUNTIME_PATHS = Object.freeze([\n  'workers/intel-gateway/src', 'workers/intel-gateway/package.json',\n  'workers/intel-gateway/wrangler.toml', 'config/version.json',\n  'scripts/generate_api_manifests.py', 'scripts/public_api_sanitizer.py',\n]);\n\n// Runtime parity is allowed only when the live Worker is an earlier commit
// with IDENTICAL customer-serving gateway source/config. This supports
// workflow-only fixes without an unnecessary Cloudflare redeploy.
export function gatewayRuntimeParity(liveSha, expectedSha, { git = execFileSync, repoRoot = REPO_ROOT } = {}) {
  if (!SHA_RE.test(liveSha || '') || !SHA_RE.test(expectedSha || '')) return false;
  if (liveSha === expectedSha) return true;
  try {
    git('git', ['-C', repoRoot, 'fetch', '--no-tags', '--depth=1', 'origin', liveSha], {
      stdio: 'ignore', timeout: 15000,
    });
    git('git', ['-C', repoRoot, 'diff', '--exit-code', '--quiet', liveSha, expectedSha,
      '--', ...GATEWAY_RUNTIME_PATHS,
    ], { stdio: 'ignore', timeout: 15000 });
    return true;
  } catch {
    return false;
  }
}

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
  runtimeParity = gatewayRuntimeParity,
} = {}) {
  if (!SHA_RE.test(expectedSha || '')) throw new Error('GATEWAY_DEPLOY_SHA_INVALID');
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 24) {
    throw new Error('GATEWAY_DEPLOY_ATTEMPTS_INVALID');
  }

  let reason = 'not_probed';
  const parityCache = new Map();
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
        if (live?.status === 'alive' && SHA_RE.test(live?.deploy_commit_sha || '')) {
          const liveSha = live.deploy_commit_sha;
          if (!parityCache.has(liveSha)) {
            parityCache.set(liveSha, await runtimeParity(liveSha, expectedSha));
          }
          if (parityCache.get(liveSha)) {
            log('GATEWAY_RUNTIME_PARITY_CONFIRMED live=' + liveSha + ' checkout=' + expectedSha + ' attempt=' + attempt);
            return { attempt, sha: liveSha, runtime_equivalent: true };
          }
          reason = 'deployment_sha_not_converged';
        } else {
          reason = 'invalid_liveness_contract';
        }
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
