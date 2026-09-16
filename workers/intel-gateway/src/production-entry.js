import coreApp from './index.js';
import {
  beginApexMeshBoundary,
  completeApexMeshBoundary,
} from './apex-mesh-boundary.js';

// Wrangler instantiates this class through GUMROAD_PROVISIONING_LOCK. When
// production-entry.js becomes the Worker main module, named exports must be
// re-exported from the entry module as well as from the underlying core.
export { GumroadProvisioningLock } from './index.js';

/**
 * P0 V4.43 production edge.
 *
 * Only explicitly approved mutating/compute routes are admitted into the
 * private Super Agent Mesh. Every other API, auth, payment, webhook, report,
 * TAXII, cron and public-read path delegates byte-for-byte to the existing
 * gateway core.
 */
export default {
  async fetch(request, env, ctx) {
    const boundary = await beginApexMeshBoundary(request, env);
    if (boundary?.blockedResponse) return boundary.blockedResponse;

    const response = await coreApp.fetch(request, env, ctx);
    return completeApexMeshBoundary(boundary?.session, response, env);
  },

  async scheduled(event, env, ctx) {
    return coreApp.scheduled(event, env, ctx);
  },
};
