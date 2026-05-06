// ==============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- AI Alert Engine v143.0.0
// Enterprise-tier active alerting: Telegram + custom Webhooks
// Endpoints:
//   POST /api/alerts/subscribe   -- register Telegram chat_id or webhook URL
//   GET  /api/alerts/subscriptions -- list active subscriptions (auth required)
//   POST /api/alerts/test        -- fire a test alert to registered endpoint
//   POST /api/alerts/dispatch    -- internal: dispatch anomaly alert batch
//   GET  /api/alerts/history     -- last 100 dispatched alerts (Enterprise)
//   DELETE /api/alerts/unsubscribe -- remove subscription
//
// Tier gates:
//   Enterprise: real-time alerts, full 30-day forecast, all channels
//   Pro:        daily digest only, Telegram only, top-5 alerts/day
//   Free:       blocked
// ==============================================================================

/* -- Null-safe helpers -------------------------------------------------------- */
const safe    = (v, fb = "UNKNOWN") => (v == null ? fb : String(v));
const safeNum = (v, fb = 0)        => (typeof v === "number" && isFinite(v) ? v : Number(v) || fb);
const safeArr = (v)                => (Array.isArray(v) ? v : []);

/* -- KV key builders ---------------------------------------------------------- */
const ALERT_SUB_PREFIX   = "alert_sub:";
const ALERT_HIST_KEY     = "alert_history";
const ALERT_QUOTA_PREFIX = "alert_quota:";   // daily dispatch counter per key
const MAX_HISTORY        = 100;
const PRO_DAILY_LIMIT    = 5;                // max alerts/day for Pro tier

/* ===========================================================================
   handleAlertSubscribe  -- POST /api/alerts/subscribe
   Body: { channel: "telegram"|"webhook", chat_id?: string, url?: string,
           interests?: string[], min_risk?: number }
   =========================================================================== */
export async function handleAlertSubscribe(request, env, auth, rid) {
  if (!auth || !auth.valid) {
    return _jsonErr(401, "Authentication required to subscribe to alerts.", rid);
  }
  if (auth.tier === "free") {
    return _jsonErr(403, "Alert subscriptions require Pro or Enterprise tier. Upgrade at /upgrade.html", rid);
  }

  let body;
  try { body = await request.json(); } catch { body = {}; }

  const channel   = safe(body.channel, "telegram").toLowerCase();
  const chatId    = safe(body.chat_id || body.chatId || "", "");
  const webhookUrl = safe(body.url || body.webhook_url || "", "");
  const interests = safeArr(body.interests).map(i => safe(i)).filter(Boolean);
  const minRisk   = Math.max(0, Math.min(10, safeNum(body.min_risk, auth.tier === "enterprise" ? 5 : 7)));

  // Validation
  if (channel === "telegram" && !chatId) {
    return _jsonErr(400, "chat_id is required for Telegram channel. Use /start in @CyberDudeBivashBot to get your chat_id.", rid);
  }
  if (channel === "webhook" && !webhookUrl.startsWith("http")) {
    return _jsonErr(400, "A valid HTTPS webhook URL is required for webhook channel.", rid);
  }
  if (!["telegram", "webhook", "email"].includes(channel)) {
    return _jsonErr(400, "Supported channels: telegram, webhook, email", rid);
  }

  const subId  = `${auth.key_id || auth.email || rid}_${channel}`;
  const subKey = ALERT_SUB_PREFIX + subId;

  const subscription = {
    sub_id:     subId,
    key_id:     safe(auth.key_id,  ""),
    email:      safe(auth.email,   ""),
    tier:       safe(auth.tier,    "pro"),
    channel,
    chat_id:    chatId,
    webhook_url: webhookUrl,
    interests:  interests.length ? interests : ["critical", "high", "zero-day"],
    min_risk:   minRisk,
    daily_limit: auth.tier === "enterprise" ? 0 : PRO_DAILY_LIMIT, // 0 = unlimited
    created_at: new Date().toISOString(),
    active:     true,
    test_sent:  false,
  };

  if (env.KV) {
    await env.KV.put(subKey, JSON.stringify(subscription), { expirationTtl: 60 * 60 * 24 * 365 });
    // Also add to subscription index
    let idx = [];
    try { idx = JSON.parse(await env.KV.get("alert_sub_index") || "[]"); } catch {}
    if (!idx.includes(subId)) { idx.push(subId); }
    await env.KV.put("alert_sub_index", JSON.stringify(idx));
  }

  return _json(200, {
    success:     true,
    sub_id:      subId,
    channel,
    min_risk:    minRisk,
    interests:   subscription.interests,
    tier:        auth.tier,
    daily_limit: subscription.daily_limit === 0 ? "unlimited" : subscription.daily_limit,
    message:     `CHECK Subscribed! You will receive ${auth.tier === "enterprise" ? "real-time" : "daily digest"} alerts via ${channel}.`,
    next_step:   channel === "telegram"
      ? `Send /start to @CyberDudeBivashBot and confirm chat_id: ${chatId}`
      : `Ensure your webhook at ${webhookUrl} accepts POST with JSON body.`,
    rid,
  });
}

/* ===========================================================================
   handleAlertSubscriptions  -- GET /api/alerts/subscriptions
   =========================================================================== */
export async function handleAlertSubscriptions(request, env, auth, rid) {
  if (!auth || !auth.valid) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier === "free")  return _jsonErr(403, "Pro+ required.", rid);

  let idx = [];
  try { idx = JSON.parse(await env.KV.get("alert_sub_index") || "[]"); } catch {}

  const subs = [];
  for (const subId of idx) {
    try {
      const raw = await env.KV.get(ALERT_SUB_PREFIX + subId);
      if (!raw) continue;
      const sub = JSON.parse(raw);
      // Only return subs belonging to this key/email
      if (sub.key_id === auth.key_id || sub.email === auth.email) {
        subs.push({
          sub_id:     sub.sub_id,
          channel:    sub.channel,
          interests:  sub.interests,
          min_risk:   sub.min_risk,
          daily_limit: sub.daily_limit === 0 ? "unlimited" : sub.daily_limit,
          active:     sub.active,
          created_at: sub.created_at,
        });
      }
    } catch {}
  }

  return _json(200, { subscriptions: subs, count: subs.length, rid });
}

/* ===========================================================================
   handleAlertTest  -- POST /api/alerts/test
   =========================================================================== */
export async function handleAlertTest(request, env, auth, rid) {
  if (!auth || !auth.valid) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier === "free")  return _jsonErr(403, "Pro+ required.", rid);

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const subId = safe(body.sub_id || body.subId, "");

  if (!subId) return _jsonErr(400, "sub_id is required.", rid);

  let sub;
  try {
    const raw = await env.KV.get(ALERT_SUB_PREFIX + subId);
    if (!raw) return _jsonErr(404, "Subscription not found.", rid);
    sub = JSON.parse(raw);
  } catch {
    return _jsonErr(500, "Failed to load subscription.", rid);
  }

  const testPayload = _buildAlertPayload({
    title:            "FLASK TEST ALERT -- SENTINEL APEX v143.0.0",
    cve_id:           "CVE-2024-TEST-001",
    severity:         "CRITICAL",
    predictive_risk:  9.5,
    zero_day_probability: 0.87,
    ai_summary:       "This is a test alert from SENTINEL APEX AI Engine. Real alerts will include full CVE analysis, MITRE ATT&CK mapping, and recommended actions.",
    recommended_action: "No action required -- this is a test.",
    tier:             auth.tier,
    is_test:          true,
  });

  const result = await _dispatch(sub, testPayload, env);

  // Mark test sent
  sub.test_sent = true;
  if (env.KV) await env.KV.put(ALERT_SUB_PREFIX + subId, JSON.stringify(sub));

  return _json(200, {
    success: result.ok,
    channel: sub.channel,
    message: result.ok ? `CHECK Test alert dispatched via ${sub.channel}.` : `FAIL Dispatch failed: ${result.error}`,
    rid,
  });
}

/* ===========================================================================
   handleAlertDispatch  -- POST /api/alerts/dispatch  (internal / admin)
   Called by: pipeline after anomaly detection, cron triggers
   Body: { advisories: [...], min_risk?: number, force?: boolean }
   =========================================================================== */
export async function handleAlertDispatch(request, env, auth, rid) {
  // Admin-only endpoint
  const secret = request.headers.get("X-Admin-Secret") || "";
  const envSecret = (env.WORKER_ADMIN_SECRET || "");
  if (!envSecret || secret !== envSecret) {
    return _jsonErr(403, "Admin secret required for alert dispatch.", rid);
  }

  let body;
  try { body = await request.json(); } catch { body = {}; }

  const advisories = safeArr(body.advisories);
  const minRisk    = safeNum(body.min_risk, 7.0);
  const force      = body.force === true;

  // Filter advisories by risk threshold
  const alerts = advisories
    .filter(a => {
      const risk = safeNum(a.apex_ai?.predictive_risk || a.predictive_risk, 0);
      return force || risk >= minRisk;
    })
    .slice(0, 50)  // max 50 per dispatch
    .map(a => ({
      title:               safe(a.title || a.cve_id || a.id, "Unknown Advisory"),
      cve_id:              safe(a.cve_id || a.id, "N/A"),
      severity:            safe((a.severity || "UNKNOWN").toUpperCase()),
      predictive_risk:     safeNum(a.apex_ai?.predictive_risk || a.predictive_risk, 0),
      zero_day_probability: safeNum(a.apex_ai?.zero_day_probability || a.zero_day_probability, 0),
      ai_summary:          safe(a.apex_ai?.ai_summary || a.summary || "", ""),
      recommended_action:  safe(a.apex_ai?.recommended_action || a.recommended_action || "", "Patch immediately if affected."),
      mitre_techniques:    safeArr(a.apex_ai?.mitre_techniques || a.mitre_techniques),
      published:           safe(a.published || a.date || "", ""),
      cvss:                safeNum(a.cvss_score || a.cvss || a.base_score, 0),
    }));

  if (!alerts.length) {
    return _json(200, { dispatched: 0, message: "No advisories met the risk threshold.", rid });
  }

  // Load all active subscriptions
  let idx = [];
  try { idx = JSON.parse(await env.KV.get("alert_sub_index") || "[]"); } catch {}

  let dispatched = 0;
  let errors     = 0;
  const today    = new Date().toISOString().split("T")[0];

  for (const subId of idx) {
    try {
      const raw = await env.KV.get(ALERT_SUB_PREFIX + subId);
      if (!raw) continue;
      const sub = JSON.parse(raw);
      if (!sub.active) continue;

      // Tier filtering: Pro gets top-1 per dispatch; Enterprise gets all
      const isTierEnterprise = sub.tier === "enterprise";
      const isTierPro        = sub.tier === "premium" || sub.tier === "pro";
      if (!isTierEnterprise && !isTierPro) continue;

      // Daily quota for Pro
      if (!isTierEnterprise && sub.daily_limit > 0) {
        const quotaKey = ALERT_QUOTA_PREFIX + subId + ":" + today;
        const used     = safeNum(parseInt(await env.KV.get(quotaKey) || "0"), 0);
        if (used >= sub.daily_limit) continue;
        await env.KV.put(quotaKey, String(used + 1), { expirationTtl: 86400 });
      }

      // Filter by subscription interests + min_risk
      const relevantAlerts = alerts.filter(a => {
        const risk = a.predictive_risk;
        if (risk < sub.min_risk) return false;
        if (!sub.interests || !sub.interests.length) return true;
        const sev = (a.severity || "").toLowerCase();
        return sub.interests.some(i => sev.includes(i.toLowerCase()) || i === "all");
      });
      if (!relevantAlerts.length) continue;

      // Pro: top-1 only
      const toSend = isTierEnterprise ? relevantAlerts : relevantAlerts.slice(0, 1);

      for (const alert of toSend) {
        const payload = _buildAlertPayload({ ...alert, tier: sub.tier, is_test: false });
        const result  = await _dispatch(sub, payload, env);
        if (result.ok) dispatched++;
        else errors++;
      }
    } catch { errors++; }
  }

  // Record in history
  await _recordHistory(env, {
    ts:         new Date().toISOString(),
    alerts_in:  advisories.length,
    above_threshold: alerts.length,
    dispatched,
    errors,
    min_risk:   minRisk,
    rid,
  });

  return _json(200, {
    dispatched,
    errors,
    alerts_processed: alerts.length,
    subscriptions_checked: idx.length,
    rid,
  });
}

/* ===========================================================================
   handleAlertHistory  -- GET /api/alerts/history
   =========================================================================== */
export async function handleAlertHistory(request, env, auth, rid) {
  if (!auth || !auth.valid) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier !== "enterprise") return _jsonErr(403, "Alert history requires Enterprise tier.", rid);

  let history = [];
  try { history = JSON.parse(await env.KV.get(ALERT_HIST_KEY) || "[]"); } catch {}

  return _json(200, {
    history: history.slice(-50),
    count:   history.length,
    rid,
  });
}

/* ===========================================================================
   handleAlertUnsubscribe  -- DELETE /api/alerts/unsubscribe
   =========================================================================== */
export async function handleAlertUnsubscribe(request, env, auth, rid) {
  if (!auth || !auth.valid) return _jsonErr(401, "Authentication required.", rid);

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const subId = safe(body.sub_id || body.subId, "");
  if (!subId) return _jsonErr(400, "sub_id required.", rid);

  try {
    const raw = await env.KV.get(ALERT_SUB_PREFIX + subId);
    if (!raw) return _jsonErr(404, "Subscription not found.", rid);
    const sub = JSON.parse(raw);
    // Ownership check
    if (sub.key_id !== auth.key_id && sub.email !== auth.email) {
      return _jsonErr(403, "You can only unsubscribe your own subscriptions.", rid);
    }
    sub.active = false;
    await env.KV.put(ALERT_SUB_PREFIX + subId, JSON.stringify(sub));
    return _json(200, { success: true, message: "Unsubscribed successfully.", rid });
  } catch {
    return _jsonErr(500, "Failed to process unsubscribe.", rid);
  }
}

/* -- Internal: build alert payload ------------------------------------------- */
function _buildAlertPayload(a) {
  const risk    = safeNum(a.predictive_risk, 0);
  const zdp     = safeNum(a.zero_day_probability, 0);
  const riskBar = "##".repeat(Math.round(risk)) + "..".repeat(Math.max(0, 10 - Math.round(risk)));
  const emoji   = risk >= 9 ? "RED" : risk >= 7 ? "ORANGE" : risk >= 5 ? "YELLOW" : "GREEN";

  const telegramText = [
    `${emoji} *SENTINEL APEX ALERT*${a.is_test ? " (TEST)" : ""}`,
    ``,
    `*${safe(a.title, "Unknown Advisory").replace(/[*_[\]()~>#+=|{}.!-]/g, "\\$&").slice(0, 120)}*`,
    ``,
    `NEW CVE: \`${safe(a.cve_id, "N/A")}\``,
    `FAST Severity: \`${safe(a.severity, "UNKNOWN")}\``,
    `CHART Predictive Risk: \`${risk.toFixed(1)}/10\` ${riskBar}`,
    `DNA Zero-Day Prob: \`${(zdp * 100).toFixed(1)}%\``,
    ``,
    `BOT *AI Analysis:*`,
    safe(a.ai_summary, "").slice(0, 300) || "_No AI analysis available_",
    ``,
    `SHIELD *Action:* ${safe(a.recommended_action, "Patch immediately if affected.").slice(0, 200)}`,
    ``,
    a.mitre_techniques?.length ? `TARGET MITRE: \`${safeArr(a.mitre_techniques).slice(0, 5).join(", ")}\`` : null,
    ``,
    `LINK [View Full Intel](https://intel.cyberdudebivash.com) | [Upgrade](https://intel.cyberdudebivash.com/upgrade.html)`,
    ``,
    `_CYBERDUDEBIVASH SENTINEL APEX v143.0.0_`,
  ].filter(l => l !== null).join("\n");

  return {
    text:       telegramText,
    cve_id:     safe(a.cve_id, "N/A"),
    severity:   safe(a.severity, "UNKNOWN"),
    risk_score: risk,
    zdp:        zdp,
    title:      safe(a.title, "Unknown"),
    summary:    safe(a.ai_summary, ""),
    action:     safe(a.recommended_action, ""),
    is_test:    a.is_test === true,
    ts:         new Date().toISOString(),
  };
}

/* -- Internal: dispatch to channel ------------------------------------------- */
async function _dispatch(sub, payload, env) {
  try {
    if (sub.channel === "telegram") {
      return await _sendTelegram(payload.text, sub.chat_id, env);
    }
    if (sub.channel === "webhook") {
      return await _sendWebhook(payload, sub.webhook_url, env);
    }
    return { ok: false, error: `Unsupported channel: ${sub.channel}` };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function _sendTelegram(text, chatId, env) {
  const token = env.TELEGRAM_BOT_TOKEN || "";
  if (!token) return { ok: false, error: "TELEGRAM_BOT_TOKEN not configured in Worker secrets." };
  if (!chatId) return { ok: false, error: "chat_id not set." };

  const resp = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      chat_id:    chatId,
      text:       text.slice(0, 4096),
      parse_mode: "MarkdownV2",
      disable_web_page_preview: false,
    }),
  });

  const data = await resp.json().catch(() => ({}));
  if (resp.ok && data.ok) return { ok: true };
  return { ok: false, error: data.description || `HTTP ${resp.status}` };
}

async function _sendWebhook(payload, url, env) {
  if (!url || !url.startsWith("http")) return { ok: false, error: "Invalid webhook URL." };

  const resp = await fetch(url, {
    method:  "POST",
    headers: {
      "Content-Type":       "application/json",
      "X-Sentinel-Source":  "CYBERDUDEBIVASH-SENTINEL-APEX",
      "X-Sentinel-Version": "143.0.0",
      "X-Alert-Type":       payload.is_test ? "test" : "threat_alert",
    },
    body: JSON.stringify({
      source:       "SENTINEL_APEX_v143",
      alert_type:   payload.is_test ? "test" : "threat_alert",
      cve_id:       payload.cve_id,
      title:        payload.title,
      severity:     payload.severity,
      predictive_risk: payload.risk_score,
      zero_day_probability: payload.zdp,
      ai_summary:   payload.summary,
      recommended_action: payload.action,
      timestamp:    payload.ts,
      platform_url: "https://intel.cyberdudebivash.com",
    }),
  });

  if (resp.ok) return { ok: true };
  return { ok: false, error: `Webhook returned HTTP ${resp.status}` };
}

/* -- Internal: history logging ------------------------------------------------ */
async function _recordHistory(env, entry) {
  if (!env.KV) return;
  try {
    let history = [];
    try { history = JSON.parse(await env.KV.get(ALERT_HIST_KEY) || "[]"); } catch {}
    history.push(entry);
    if (history.length > MAX_HISTORY) history = history.slice(-MAX_HISTORY);
    await env.KV.put(ALERT_HIST_KEY, JSON.stringify(history));
  } catch {}
}

/* -- Response helpers --------------------------------------------------------- */
function _json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Sentinel-Version": "143.0.0" },
  });
}

function _jsonErr(status, message, rid) {
  return _json(status, { error: true, message, rid, version: "143.0.0" });
}
