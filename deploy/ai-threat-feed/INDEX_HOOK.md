# Wire routeAiFeed next to routeWatchdog in workers/intel-gateway/src/index.js

import { routeAiFeed } from './ai-threat-feed.js';

After the Watchdog `if (watched) return jsonResp(...)` block:

const aiFed = await routeAiFeed({
  path, method, auth: watchdogAuth,
  freshness_status: feed ? (feed.freshness_status || 'FRESH') : 'EMPTY',
  hubCatalog: (feed && feed.ai_threat_feed) || [],
  advisories: (feed && (feed.items || feed.advisories)) || [],
  pricingSnapshot: typeof getPricingSnapshot === 'function' ? getPricingSnapshot() : null,
  body,
  isOperator: isWatchdogOperator(request, env),
});
if (aiFed) return jsonResp(aiFed.body, aiFed.status, { 'Cache-Control': 'no-store' });

first-party-plane.js add /api/ai-feed/offer /health /live
cors-policy.js PUBLIC add /api/ai-feed/offer /health only (live stays BROWSER)
