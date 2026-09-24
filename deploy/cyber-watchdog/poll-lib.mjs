/**
 * Pure decisions for the Cyber Watchdog customer poller.
 * The poller does not scan the internet.
 */

export function pollDecision(status, text) {
  if (status === 401 || status === 403) return { action: "fail", exitCode: 3, replace: false };
  let parsed = null;
  if (status === 200 || status === 503) {
    try { parsed = JSON.parse(text); } catch { parsed = null; }
  }
  if (parsed && parsed.freshness_status && parsed.freshness_status !== "FRESH") {
    return { action: "keep", exitCode: 4, replace: false, parsed };
  }
  if (status === 429 || status >= 500) return { action: "retry", exitCode: 6, replace: false };
  if (status !== 200) return { action: "fail", exitCode: 6, replace: false };
  if (!parsed || typeof parsed !== "object") return { action: "fail", exitCode: 5, replace: false };
  if (parsed.freshness_status !== "FRESH") return { action: "keep", exitCode: 4, replace: false, parsed };
  return { action: "write", exitCode: 0, replace: true, parsed };
}

export function retryDelayMs(attempt, retryAfterHeader) {
  const header = Number(retryAfterHeader);
  if (Number.isFinite(header) && header >= 0 && header <= 120) return header * 1000;
  return Math.min(30000, 1000 * (2 ** attempt));
}
