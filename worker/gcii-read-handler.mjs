/** GCII read-only feed handler. Mount explicitly in the existing Worker router after acceptance. */
import { listIncidents } from './gcii-d1-repository.mjs';

const MAX_AGE_SECONDS = 120;
const HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store, max-age=0',
  'x-content-type-options': 'nosniff',
  'access-control-allow-origin': 'https://soc.cyberdudebivash.in',
  'vary': 'Origin'
};
function error(status, message) {
  return new Response(JSON.stringify({error:message}), {status, headers:HEADERS});
}
export async function handleGCIIRead(request, env) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response(null, {status:405, headers:{...HEADERS,allow:'GET, HEAD'}});
  }
  if (!env || !env.GCII_DB) return error(503, 'feed unavailable');
  try {
    const rows = await listIncidents(env.GCII_DB, 100);
    // This is a diagnostic API, not the signed canonical v1 feed:
    // the canonical schema requires deterministic SHA-256 over its envelope.
    const body = JSON.stringify({
      schema:'cdb.global-incidents.readonly.v1',
      generated_at_utc:new Date().toISOString(),
      incidents:rows,
      warning:'Unverified read-only diagnostic; not a canonical signed intelligence feed.'
    });
    if (new TextEncoder().encode(body).length > 1048576) return error(503,'feed too large');
    return new Response(request.method === 'HEAD' ? null : body, {status:200,headers:HEADERS});
  } catch (_) {
    return error(503,'feed unavailable');
  }
}
