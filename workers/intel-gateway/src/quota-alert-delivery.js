/**
 * P0: customer quota warnings must not be marked "sent" before the Revenue
 * Engine confirms that it actually queued the message.
 *
 * A one-hour KV reservation limits single-view retries to ~24/day/key;
 * failed/denied/malformed upstream requests become retryable after its TTL.
 * A 25-hour marker is written ONLY after a strict 200 + matching acknowledgment.
 *
 * Cloudflare KV is eventually consistent, so this is explicitly best-effort
 * suppression, NOT globally linearizable exactly-once delivery. The gateway
 * must not fail a customer's successful API request because email is down.
 */
export const QUOTA_ALERT_PENDING_SECONDS = 3600;
export const QUOTA_ALERT_SENT_SECONDS = 90000;

export async function dispatchQuotaAlertOnce({ kv, key, deliver }) {
  if (!kv || typeof kv.get !== 'function' || typeof kv.put !== 'function' ||
      typeof key !== 'string' || !key.startsWith('alert_sent:80pct:') ||
      typeof deliver !== 'function') {
    return { outcome: 'not_attempted' };
  }

  const old = await kv.get(key);
  // Both the old "1" marker and the new "pending"/"sent" markers suppress
  // in-window retries; their TTLs are deliberately different.
  if (old !== null && old !== undefined) {
    return { outcome: 'suppressed' };
  }

  // Reserve BEFORE the network call to reduce concurrent duplicate sends.
  // A failed request leaves only the short reservation; later authenticated
  // customer usage may retry without blocking the customer request.
  await kv.put(key, 'pending', { expirationTtl: QUOTA_ALERT_PENDING_SECONDS });

  try {
    const response = await deliver();
    if (!response || response.status !== 200 || typeof response.json !== 'function') {
      return { outcome: 'retry_after_reservation' };
    }
    const result = await response.json();
    if (!result || result.status !== 'triggered' || result.trigger !== 'usage_80pct') {
      return { outcome: 'retry_after_reservation' };
    }
    await kv.put(key, 'sent', { expirationTtl: QUOTA_ALERT_SENT_SECONDS });
    return { outcome: 'queued' };
  } catch {
    // Includes network, parse, and KV post-ack write failures. If the last
    // write failed after upstream acceptance, retry may duplicate: no claim
    // of exactly-once delivery without a durable upstream idempotency key.
    return { outcome: 'retry_after_reservation' };
  }
}
