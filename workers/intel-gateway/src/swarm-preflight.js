import { dailyQuotaConfig, dailyQuotaKey, secondsUntilNextUtcMidnight, utcDateString } from './daily-quota.js';

export const SWARM_ALLOWED_TIERS = Object.freeze(new Set(['PRO', 'ENTERPRISE', 'MSSP']));

export function mapSwarmAuthError(error) {
  const code = String(error || '');
  const table = {
    invalid_key: ['KEY_INVALID', 401],
    invalid_token: ['KEY_INVALID', 401],
    token_revoked: ['TOKEN_REVOKED', 401],
    key_expired: ['KEY_EXPIRED', 403],
    subscription_expired: ['KEY_EXPIRED', 403],
    subscription_suspended: ['SUBSCRIPTION_SUSPENDED', 403],
    subscription_cancelled: ['SUBSCRIPTION_CANCELLED', 403],
    subscription_refunded: ['SUBSCRIPTION_REFUNDED', 403],
    subscription_status_invalid: ['SUBSCRIPTION_STATE_INVALID', 403],
    subscription_status_denied: ['SUBSCRIPTION_DENIED', 403],
    rate_limited: ['RATE_LIMITED', 429],
    auth_service_unavailable: ['VERIFY_UNAVAILABLE', 503],
  };
  const [reason, status] = table[code] || ['ACCESS_DENIED', 403];
  return { reason, status };
}

function toCount(value) {
  const n = Number.parseInt(String(value ?? '0'), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

export async function readSwarmQuotaSnapshot(env, { identifier, ip, tier, rateLimits, now = new Date() }) {
  if (!env?.RATE_LIMIT_KV?.get || !identifier || !ip) {
    return { available: false, error: 'quota_store_unavailable' };
  }

  const date = utcDateString(now);
  const minute = Math.floor(now.getTime() / 60000);
  const minuteLimit = Number(rateLimits?.[tier] || rateLimits?.FREE || 0);
  const daily = dailyQuotaConfig(tier);

  try {
    const [minuteRaw, dailyRaw] = await Promise.all([
      env.RATE_LIMIT_KV.get(`rl:${ip}:${minute}`),
      env.RATE_LIMIT_KV.get(dailyQuotaKey(identifier, date)),
    ]);
    const minuteUsed = toCount(minuteRaw);
    const dailyUsed = toCount(dailyRaw);
    return {
      available: true,
      per_minute: {
        limit: minuteLimit,
        used: minuteUsed,
        remaining: Math.max(0, minuteLimit - minuteUsed),
        exhausted: minuteLimit > 0 && minuteUsed >= minuteLimit,
      },
      per_day: {
        limit: daily.limit,
        used: dailyUsed,
        remaining: Math.max(0, daily.limit - dailyUsed),
        exhausted: dailyUsed >= daily.limit,
        reset_utc: new Date(now.getTime() + secondsUntilNextUtcMidnight(now) * 1000).toISOString(),
      },
    };
  } catch {
    return { available: false, error: 'quota_store_unavailable' };
  }
}

export function buildSwarmPreflightDecision({ credentialPresented, auth, record = null, quota = null }) {
  if (!credentialPresented) {
    return {
      http_status: 401,
      body: { status: 'denied', allowed: false, swarm_entitled: false, reason: 'AUTH_REQUIRED' },
    };
  }

  if (auth?.error) {
    const mapped = mapSwarmAuthError(auth.error);
    return {
      http_status: mapped.status,
      body: { status: mapped.status === 503 ? 'unavailable' : 'denied', allowed: false, swarm_entitled: false, reason: mapped.reason },
    };
  }

  if (!auth?.key) {
    return {
      http_status: 401,
      body: { status: 'denied', allowed: false, swarm_entitled: false, reason: 'KEY_INVALID' },
    };
  }

  const tier = String(auth.tier || 'FREE').toUpperCase();
  if (!SWARM_ALLOWED_TIERS.has(tier)) {
    return {
      http_status: 403,
      body: { status: 'denied', allowed: false, swarm_entitled: false, reason: 'TIER_NOT_ENTITLED', tier },
    };
  }

  if (!quota?.available) {
    return {
      http_status: 503,
      body: { status: 'unavailable', allowed: false, swarm_entitled: false, reason: 'VERIFY_UNAVAILABLE', tier },
    };
  }

  if (quota.per_minute?.exhausted || quota.per_day?.exhausted) {
    return {
      http_status: 429,
      body: { status: 'denied', allowed: false, swarm_entitled: false, reason: 'QUOTA_EXHAUSTED', tier, quota },
    };
  }

  const subscriptionStatus = record?.subscription_status || 'active';
  const expiresAt = record?.expires_at || null;
  return {
    http_status: 200,
    body: {
      status: 'ok',
      allowed: true,
      swarm_entitled: true,
      tier,
      subscription_status: subscriptionStatus,
      expires_at: expiresAt,
      credential_type: auth.jwt ? 'jwt' : 'api_key',
      quota,
    },
  };
}
