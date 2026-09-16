import coreApp from './index.js';
import {
  beginApexMeshBoundary,
  completeApexMeshBoundary,
} from './apex-mesh-boundary.js';
import { applyCorsPolicy } from './cors-policy.js';

// Wrangler instantiates this class through GUMROAD_PROVISIONING_LOCK. When
// production-entry.js becomes the Worker main module, named exports must be
// re-exported from the entry module as well as from the underlying core.
export { GumroadProvisioningLock } from './index.js';

/**
 * P0 V4.43 production edge.
 *
 * Only explicitly approved compute routes are admitted into the private
 * Super Agent Mesh. Every other API, auth, payment, webhook, report, TAXII,
 * cron and public-read path delegates byte-for-byte to the existing gateway.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const boundary = await beginApexMeshBoundary(request, env);
    if (boundary?.blockedResponse) {
      return applyCorsPolicy(boundary.blockedResponse, request, path, method);
    }

    const response = await coreApp.fetch(request, env, ctx);
    if (!boundary?.session) return response;

    const certified = await completeApexMeshBoundary(boundary.session, response, env);
    // coreApp already applies this policy. Reapplying at the wrapper is
    // deliberately safe/idempotent and covers mesh-generated fail-closed
    // responses that never passed through the core response choke point.
    return applyCorsPolicy(certified, request, path, method);
  },

  async scheduled(event, env, ctx) {
    return coreApp.scheduled(event, env, ctx);
  },
};
