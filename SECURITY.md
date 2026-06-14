# Security Policy — CYBERDUDEBIVASH(R) SENTINEL APEX

**Platform Version:** v180.0 (ENTERPRISE-HARDENING)
**Last Updated:** 2026-06-14
**Contact:** security@cyberdudebivash.com

---

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 180.x   | Yes       | Current production — enterprise hardened |
| 170.x   | Yes       | Supported with backport patches |
| < 170.0 | No        | End of life |

---

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues, PR comments, or public forums.

**Preferred channel:**
- Email: security@cyberdudebivash.com
- Subject line: `[SECURITY] <brief-description>`
- PGP: Available on request via the email above

**What to include:**
1. Vulnerability type (OWASP category if applicable)
2. Affected endpoint / component
3. Steps to reproduce (HTTP request, curl command, or PoC)
4. Potential impact (data exposure, auth bypass, DoS, etc.)
5. Suggested fix or mitigation (if known)

**Response SLA:**

| Severity | Acknowledgment | Assessment | Fix Timeline |
|----------|---------------|------------|--------------|
| CRITICAL | 4 hours       | 24 hours   | 7 days       |
| HIGH     | 24 hours      | 72 hours   | 30 days      |
| MEDIUM   | 48 hours      | 7 days     | 90 days      |
| LOW      | 7 days        | 30 days    | Next release |

---

## Security Controls (v180.0)

### Authentication

- **JWT HS256** — all access tokens are HMAC-SHA256 signed JWTs issued by `POST /auth/login`
  - Signature verified on every request using `crypto.subtle` (Web Crypto API)
  - Tokens expire in 24 hours; revocation via `POST /auth/logout` (KV blocklist)
  - Secret: `CDB_JWT_SECRET` — Cloudflare Worker runtime secret, minimum 32 bytes
  - **NEVER hardcoded** — must be set via `npx wrangler secret put CDB_JWT_SECRET`

- **API Key validation** — keys validated against `API_KEYS_KV` (Cloudflare KV namespace)
  - Key format: `cdb_pro_<40 random hex chars>` or `cdb_ent_<40 hex>`
  - Issued via admin API: `POST /api/admin/keys` (requires `ADMIN_SECRET`)
  - Expiry supported: optional `expires_at` field per key record

### Brute Force Protection

- 5 failed authentication attempts triggers a 15-minute IP lockout
- Lockout state stored in `RATE_LIMIT_KV` with automatic expiry
- Lockout applies to `POST /auth/login` only

### Rate Limiting

Sliding window per IP per minute:

| Tier       | Limit / minute |
|------------|----------------|
| FREE       | 30 requests    |
| PRO        | 120 requests   |
| ENTERPRISE | 600 requests   |

Rate limit state stored in `RATE_LIMIT_KV` with 61-second TTL.

### Security Headers

All API responses include:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
X-Sentinel-Version: 180.0
X-Sentinel-Platform: CYBERDUDEBIVASH-SENTINEL-APEX
```

HTML report responses additionally include `Content-Security-Policy`.

### Audit Logging

- All authenticated API requests logged to `SECURITY_HUB_KV`
- Auth events (login, logout, failed attempts) logged with IP, timestamp, and outcome
- 30-day retention; retrievable via `GET /api/admin/audit` (admin only)

### Admin API

- Protected by `ADMIN_SECRET` — a Cloudflare Worker runtime secret
- Never exposed in responses or logs
- Endpoints: `/api/admin/health`, `/api/admin/audit`, `/api/admin/keys`

---

## Credential Policy

**NEVER commit to source control:**
- `CDB_JWT_SECRET`
- `ADMIN_SECRET`
- `CF_API_TOKEN`
- `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_ACCESS_KEY`
- `TG_BOT_TOKEN`

**Set secrets via:**
```bash
npx wrangler secret put CDB_JWT_SECRET     # JWT signing key (min 32 random bytes)
npx wrangler secret put ADMIN_SECRET       # Admin API key
# Generate: openssl rand -hex 32
```

**GitHub Actions secrets** (for CI/CD only — not exposed to Worker at runtime):
- `CF_API_TOKEN` — deploy token
- `CF_ACCOUNT_ID` — account identifier

---

## Scope

This policy covers:
- `intel.cyberdudebivash.com` — Cloudflare Worker API gateway
- All `/api/*`, `/auth/*`, `/taxii/*`, `/reports/*` endpoints
- GitHub Actions CI/CD pipeline

Out of scope:
- Social engineering attacks
- Physical attacks
- Third-party Cloudflare infrastructure
- `www.cyberdudebivash.com` and `blog.cyberdudebivash.in` (separate scope)

---

## Bug Bounty

No formal bug bounty program at this time. Security researchers who responsibly disclose
vulnerabilities will be acknowledged publicly (if desired) and may receive service credits.

---

(c) 2026 CyberDudeBivash Pvt. Ltd. | GSTIN: 21ARKPN8270G1ZP
