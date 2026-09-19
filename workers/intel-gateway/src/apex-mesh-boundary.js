import { evaluateKeyRecordAccess } from './subscription-lifecycle.js';
import { SWARM_MESH_CAPABILITY, tierAllowsSwarm } from './swarm-access.js';

const enc = new TextEncoder();
const MESH_VERSION = 'cdb.mesh.v1';
const TOKEN_ISSUER = 'cdb-apex-mesh';
const SERVICE_SUBJECT = 'sentinel-apex';
const TOKEN_SCOPE = 'mesh.invoke';
const MAX_INPUT_BYTES = 32768;
const MAX_OUTPUT_BYTES = 524288;
const MAX_MESH_RESPONSE_BYTES = 65536;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ROUTES = Object.freeze({
  'POST /api/intel/correlate': Object.freeze({ capability: SWARM_MESH_CAPABILITY }),
});

class MeshAccessError extends Error {
  constructor(code, status = 403) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function canonical(value) {
  if (value === null || typeof value !== 'object') {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError('unsupported canonical value');
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function hex(bytes) {
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}

async function sha256Bytes(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

async function sha256Text(value) {
  return sha256Bytes(enc.encode(value));
}

async function hmac(secret, value) {
  const raw = enc.encode(secret);
  if (raw.byteLength < 32) throw new Error('mesh service credential unavailable');
  const key = await crypto.subtle.importKey(
    'raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(value))));
}

function randomHex(bytes = 16) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return hex(value);
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const decoded = atob(base64);
  return Uint8Array.from(decoded, c => c.charCodeAt(0));
}

async function verifyJwtHs256(token, secret) {
  if (!secret || enc.encode(secret).byteLength < 32) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const [headerPart, payloadPart, signaturePart] = parts;
    const header = JSON.parse(new TextDecoder().decode(fromBase64Url(headerPart)));
    if (header?.alg !== 'HS256') return null;
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    const valid = await crypto.subtle.verify(
      'HMAC', key, fromBase64Url(signaturePart), enc.encode(`${headerPart}.${payloadPart}`),
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(payloadPart)));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    if (payload.exp && (!Number.isFinite(payload.exp) || payload.exp < Math.floor(Date.now() / 1000))) return null;
    return payload;
  } catch {
    return null;
  }
}

function routePolicy(request) {
  const path = new URL(request.url).pathname;
  return ROUTES[`${request.method.toUpperCase()} ${path}`] || null;
}

function safeCorrelationId(request) {
  const supplied = request.headers.get('X-Request-ID') || '';
  return ID.test(supplied) ? supplied : `sentinel-corr-${crypto.randomUUID()}`;
}

function normalizeTier(value) {
  const tier = String(value || '').trim().toUpperCase();
  if (!tierAllowsSwarm(tier)) throw new MeshAccessError('mesh_paid_tier_required', 403);
  return tier;
}

function authMaterial(request) {
  const apiKey = (request.headers.get('X-API-Key') || '').trim();
  const sentinelKey = (request.headers.get('X-Sentinel-Key') || '').trim();
  const bearer = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const queryKey = new URL(request.url).searchParams.get('api_key') || '';
  return apiKey || bearer || queryKey || sentinelKey;
}

/**
 * A deliberately strict projection of Sentinel's existing auth authorities.
 * It is NOT a replacement router/auth system: the canonical gateway still
 * executes resolveAuth(), scope gating, quota/credit checks and handler logic.
 * This projection exists only so mesh admission cannot trust a client tier.
 */
async function resolveMeshPrincipal(request, env) {
  const raw = authMaterial(request);
  if (!raw) throw new MeshAccessError('mesh_auth_required', 401);

  if (raw.split('.').length === 3) {
    const payload = await verifyJwtHs256(raw, env?.CDB_JWT_SECRET);
    if (!payload) throw new MeshAccessError('mesh_auth_invalid', 401);
    const sub = typeof payload.sub === 'string' && payload.sub ? payload.sub : null;
    if (!sub) throw new MeshAccessError('mesh_auth_invalid', 401);
    try {
      const revoked = await env.SECURITY_HUB_KV?.get(`jwt_revoked:${raw.slice(-24)}`);
      if (revoked) throw new MeshAccessError('mesh_token_revoked', 401);
      const denied = await env.SECURITY_HUB_KV?.get(`jwt_deny:${sub}`);
      if (denied) throw new MeshAccessError('mesh_subscription_denied', 403);
    } catch (error) {
      if (error instanceof MeshAccessError) throw error;
      throw new MeshAccessError('mesh_auth_service_unavailable', 503);
    }
    return { sub, tier: normalizeTier(payload.tier), source: 'jwt' };
  }

  if (raw.length < 16 || !env?.API_KEYS_KV?.get) {
    throw new MeshAccessError('mesh_auth_invalid', 401);
  }

  let record;
  try {
    record = await env.API_KEYS_KV.get(raw, 'json');
  } catch {
    throw new MeshAccessError('mesh_auth_service_unavailable', 503);
  }
  if (!record || typeof record !== 'object') throw new MeshAccessError('mesh_auth_invalid', 401);

  const access = evaluateKeyRecordAccess(record);
  if (!access.allowed) throw new MeshAccessError(access.error || 'mesh_subscription_denied', 403);
  const sub = String(record.customer_id || raw.slice(0, 8));
  if (!sub) throw new MeshAccessError('mesh_auth_invalid', 401);
  return { sub, tier: normalizeTier(record.tier), source: 'api_key' };
}

async function tenantIdFor(principal) {
  return `sentinel-${(await sha256Text(`principal:${principal.sub}`)).slice(0, 48)}`;
}

async function missionIdFor(tenantId, correlationId, request, capability) {
  const path = new URL(request.url).pathname;
  const value = [
    MESH_VERSION,
    SERVICE_SUBJECT,
    tenantId,
    correlationId,
    request.method.toUpperCase(),
    path,
    capability,
  ].join('\u0000');
  return `sentinel-${(await sha256Text(value)).slice(0, 48)}`;
}

async function issueServiceToken(env, tenantId, now = Math.floor(Date.now() / 1000)) {
  const secret = env?.APEX_MESH_SERVICE_KEY;
  if (typeof secret !== 'string' || enc.encode(secret).byteLength < 32) {
    throw new Error('mesh service credential unavailable');
  }
  const body = {
    iss: TOKEN_ISSUER,
    sub: SERVICE_SUBJECT,
    tenant: tenantId,
    scopes: [TOKEN_SCOPE],
    iat: now,
    exp: now + 300,
    jti: randomHex(16),
  };
  const raw = canonical(body);
  return `${hex(enc.encode(raw))}.${await hmac(secret, raw)}`;
}

function fail(status, code) {
  return Response.json(
    { error: code, message: 'SENTINEL APEX execution could not be certified. Retry with the same X-Request-ID when possible.' },
    {
      status,
      headers: {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
      },
    },
  );
}

async function meshFetch(env, path, body, tenantId) {
  if (!env?.APEX_MESH || typeof env.APEX_MESH.fetch !== 'function') {
    throw new Error('mesh service binding unavailable');
  }
  const token = await issueServiceToken(env, tenantId);
  const response = await env.APEX_MESH.fetch(
    new Request(`https://cdb-apex-mesh.internal${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: canonical(body),
    }),
  );
  const text = await response.text();
  if (enc.encode(text).byteLength > MAX_MESH_RESPONSE_BYTES) throw new Error('mesh response too large');
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { /* contract check below */ }
  return { response, payload };
}

function validateCorrelationInput(raw) {
  if (enc.encode(raw).byteLength > MAX_INPUT_BYTES) throw new MeshAccessError('mesh_input_too_large', 413);
  let body;
  try { body = JSON.parse(raw); } catch { throw new MeshAccessError('invalid_json', 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new MeshAccessError('invalid_request', 400);
  if (typeof body.ioc_value !== 'string' || !body.ioc_value.trim() || body.ioc_value.length > 256) {
    throw new MeshAccessError('ioc_value_required', 400);
  }
  if (body.ioc_type !== undefined && typeof body.ioc_type !== 'string') {
    throw new MeshAccessError('invalid_ioc_type', 400);
  }
}

function admissionMatches(payload, expected) {
  return Boolean(
    payload
    && payload.version === MESH_VERSION
    && payload.state === 'admitted'
    && typeof payload.execution_id === 'string'
    && payload.tenant_id === expected.tenant_id
    && payload.mission_id === expected.mission_id
    && payload.correlation_id === expected.correlation_id
    && payload.capability === expected.capability
  );
}

function completionMatches(payload, session) {
  return Boolean(
    payload
    && payload.version === MESH_VERSION
    && payload.mission_id === session.missionId
    && payload.execution_id === session.executionId
    && typeof payload.state === 'string'
  );
}

export async function beginApexMeshBoundary(request, env) {
  const policy = routePolicy(request);
  if (!policy) return null;

  try {
    const raw = await request.clone().text();
    validateCorrelationInput(raw);
    const principal = await resolveMeshPrincipal(request, env);
    const tenantId = await tenantIdFor(principal);
    const correlationId = safeCorrelationId(request);
    const missionId = await missionIdFor(tenantId, correlationId, request, policy.capability);
    const admission = {
      version: MESH_VERSION,
      tenant_id: tenantId,
      mission_id: missionId,
      correlation_id: correlationId,
      capability: policy.capability,
      local_plan: principal.tier,
      subscription_status: 'active',
      input_sha256: await sha256Text(raw),
    };

    const { response, payload } = await meshFetch(env, '/v1/mesh/admit', admission, tenantId);
    if (!response.ok || !admissionMatches(payload, admission)) {
      const status = response.status === 403 ? 403 : response.status === 409 ? 409 : 503;
      return { blockedResponse: fail(status, status === 403 ? 'agent_capability_denied' : status === 409 ? 'agent_request_conflict' : 'agent_mesh_unavailable') };
    }

    return {
      session: Object.freeze({
        tenantId,
        missionId,
        correlationId,
        capability: policy.capability,
        executionId: payload.execution_id,
      }),
    };
  } catch (error) {
    if (error instanceof MeshAccessError) return { blockedResponse: fail(error.status, error.code) };
    return { blockedResponse: fail(503, 'agent_mesh_unavailable') };
  }
}

export async function completeApexMeshBoundary(session, response, env) {
  if (!session) return response;
  try {
    const bytes = new Uint8Array(await response.clone().arrayBuffer());
    if (bytes.byteLength > MAX_OUTPUT_BYTES) return fail(503, 'agent_output_too_large');
    const completion = {
      version: MESH_VERSION,
      tenant_id: session.tenantId,
      mission_id: session.missionId,
      correlation_id: session.correlationId,
      capability: session.capability,
      outcome: response.status >= 200 && response.status < 300 ? 'succeeded' : 'failed',
      output_sha256: await sha256Bytes(bytes),
    };
    const { response: meshResponse, payload } = await meshFetch(env, '/v1/mesh/complete', completion, session.tenantId);
    if (!meshResponse.ok || !completionMatches(payload, session)) return fail(503, 'agent_mesh_unavailable');

    const headers = new Headers(response.headers);
    headers.set('X-CDB-Mesh-Certified', 'true');
    headers.set('X-CDB-Mesh-Execution', session.executionId);
    headers.set('X-CDB-Mesh-Correlation', session.correlationId);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  } catch {
    return fail(503, 'agent_mesh_unavailable');
  }
}

export const __test = Object.freeze({
  canonical,
  routePolicy,
  normalizeTier,
  authMaterial,
  verifyJwtHs256,
  resolveMeshPrincipal,
  tenantIdFor,
  missionIdFor,
  issueServiceToken,
  validateCorrelationInput,
  admissionMatches,
  completionMatches,
});
