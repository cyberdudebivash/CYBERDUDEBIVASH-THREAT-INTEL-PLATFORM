/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  Cloudflare Worker v184.0
 * intel-gateway/src/index.js
 *
 * v184.0 GOD-MODE-GLOBAL-RELEASE (2026-06-22)
 * - Razorpay payment pipeline: /api/payments/razorpay/verify + webhook
 * - HMAC-SHA256 constant-time webhook signature verification (crypto.subtle)
 * - Idempotency guard: KV key rzp_verified:{payment_id} prevents replay attacks
 * - Webhook dedup: rzp_webhook:{payment_id} prevents double-provisioning on
 *   payment.captured + order.paid events
 * - Gumroad webhook URL token auth: GUMROAD_WEBHOOK_SECRET ?secret= guard
 * - Gumroad idempotency: gumroad_sale:{sale_id} dedup in SECURITY_HUB_KV
 * - 5 God Mode Worker modules: Brand Protection, Vendor Risk, Geopolitical Risk,
 *   NLP Query (NLQ), Incident Response (NIST SP 800-61r3)
 * - NLQ falsy-zero fix: min_cvss/min_risk filters now use != null (not !f.x)
 * - Incident Response KV pagination: cursor loop, 1000-item safety cap
 * - MSSP tier: RATE_LIMITS.MSSP = 1200 req/15min, TIERS.MSSP added
 * - AI Copilot v3.0: DeepSeek R1+V3 -> GROQ -> OpenRouter -> deterministic fallback
 *
 * ENTERPRISE PRODUCTION HARDENING v184.0 (preserved)
 * - Real JWT HS256 (crypto.subtle HMAC-SHA256) - no more fake 16-char check
 * - API key validation against API_KEYS_KV
 * - Brute-force lockout: 5 failures -> 15-min IP lockout (RATE_LIMIT_KV)
 * - Sliding-window rate limiting per IP/tier (RATE_LIMIT_KV)
 * - Security headers on ALL responses (HSTS, X-Frame, X-Content-Type, Referrer-Policy)
 * - CSP on HTML report responses
 * - Audit logging via ctx.waitUntil (SECURITY_HUB_KV, 30-day TTL)
 * - POST /auth/login  -- issue HS256 JWT from valid API key
 * - POST /auth/logout -- revoke JWT via SECURITY_HUB_KV blocklist
 * - GET/POST/DELETE /api/admin/* -- admin API gated by ADMIN_SECRET
 * - TAXII 2.1: /taxii/ discovery, /taxii/collections/, /taxii/collections/{id}/objects/
 * - ctx passed through to handleRequest for waitUntil support
 *
 * Routes (all v184.0 routes preserved):
 *   GET  /api/health
 *   GET  /api/v1/intel/latest.json
 *   GET  /api/v1/intel/apex.json            (premium tier gate)
 *   GET  /api/v1/intel/ai_summary.json      (premium tier gate)
 *   GET  /api/v1/intel/top10.json
 *   GET  /api/v1/intel/stats
 *   GET  /api/v1/intel/campaigns
 *   GET  /api/v1/intel/ransomware
 *   GET  /api/v1/intel/apt
 *   GET  /api/v1/intel/epss
 *   GET  /api/v1/intel/defcon
 *   GET  /api/v1/intel/pulse
 *   GET  /api/v1/intel/darkweb
 *   GET  /api/v1/intel/cybermap
 *   GET  /api/v1/news/feed
 *   GET  /api/reports/index.json
 *   GET  /api/reports/latest.json
 *   GET  /api/reports/stats.json
 *   POST /auth/login                        (NEW v184.0)
 *   POST /auth/logout                       (NEW v184.0)
 *   POST /api/v1/ioc/lookup
 *   GET  /api/v1/ioc/lookup
 *   GET  /api/preview
 *   GET  /api/feed(.json)
 *   GET  /reports/**
 *   GET  /taxii/                            (NEW v184.0 - TAXII 2.1 server discovery)
 *   GET  /taxii/collections/               (NEW v184.0)
 *   GET  /taxii/collections/{id}/objects/  (NEW v184.0 - PRO/ENTERPRISE)
 *   GET  /api/admin/health                 (NEW v184.0 - ADMIN_SECRET)
 *   GET  /api/admin/audit                  (NEW v184.0 - ADMIN_SECRET)
 *   POST /api/admin/keys                   (NEW v184.0 - ADMIN_SECRET)
 *   DELETE /api/admin/keys/{key}           (NEW v184.0 - ADMIN_SECRET)
 */