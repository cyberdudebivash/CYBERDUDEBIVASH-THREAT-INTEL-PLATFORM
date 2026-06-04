# API PROVISIONING CERTIFICATION
## SENTINEL APEX v175.0 — Phase 6 Commercial Readiness Sprint
**Audited:** 2026-06-04 | **Auditor Role:** Principal API Economy Architect

---

## AUDIT SCOPE

Files audited: `agent/api/auth.py`, `agent/api/rate_limiter.py`, `agent/api/api_server.py`, `agent/api/premium_api.py`, `agent/api/enterprise_api.py`, `agent/api/public_api.py`, `get-api-key.html`, `api-key-manager.html`, `api-docs.html`

---

## CURRENT API ARCHITECTURE

### Tier Model (from auth.py)

```
TIER_FREE       = "FREE"
TIER_STANDARD   = "STANDARD"
TIER_PREMIUM    = "PREMIUM"
TIER_PRO        = "PRO"        # legacy alias — maps to PREMIUM internally
TIER_ENTERPRISE = "ENTERPRISE"
```

**Issue:** The backend uses 5 tiers (FREE, STANDARD, PREMIUM, PRO, ENTERPRISE) while the frontend sells 4 plans (Community, PRO, Enterprise, MSSP). STANDARD tier has no corresponding frontend plan. PRO is a legacy alias. MSSP has no dedicated backend tier.

**Severity: P1** — Tier mismatch creates provisioning confusion.

### Authentication Methods (from auth.py)
- API key (Bearer token)
- JWT tokens (HS256, 24-hour expiry)
- Revocation registry: `data/security/revoked_keys.json`

### API Key Storage (from auth.py / config.py)
```python
CDB_STANDARD_API_KEYS   = [...]  # from env/config
CDB_PREMIUM_API_KEYS    = [...]
CDB_PRO_API_KEYS        = [...]
CDB_ENTERPRISE_API_KEYS = [...]
```

**Critical Finding:** API keys are stored in configuration variables — not in a database. This means:
- Adding a new customer key requires a config file edit + service restart (or config reload)
- No runtime key generation
- No expiry enforcement at the key level (only via config)
- No per-key metadata (customer name, expiry date, plan)

**Severity: P0** — Config-based key storage is not production-ready for a paying customer base.

### Rate Limiting (from rate_limiter.py)

```python
TIER_LIMITS = {
    "FREE":       API_RATE_LIMIT_PUBLIC,   # 100/day (from config)
    "STANDARD":   API_RATE_LIMIT_STANDARD,
    "PREMIUM":    API_RATE_LIMIT_PREMIUM,
    "PRO":        API_RATE_LIMIT_PRO,      # same as PREMIUM
    "ENTERPRISE": API_RATE_LIMIT_ENTERPRISE,
}
```

**Implementation:** Token-bucket algorithm, sliding window, in-memory (not Redis).

**Issue:** In-memory rate limiting resets on service restart — customers lose their quota tracking. For single-node deployment this works but doesn't persist across restarts.

**Severity: P2** — Acceptable for Phase 1, must migrate to Redis for Phase 2.

---

## API KEY LIFECYCLE AUDIT

### 1. Key Generation

**Current State:** Manual — operator generates keys using a Python one-liner or adds to config manually.

**Gap:** No automated generation system. No GUI for key management.

**Certification: FAIL** — No automated provisioning upon payment.

**Required Fix (Phase 1 — Simple Script):**
```python
#!/usr/bin/env python3
"""generate_key.py — Manual API key provisioner"""
import secrets, hashlib, json, datetime, sys

def generate_key(tier: str, customer_email: str, days: int) -> dict:
    key = f"SA-{tier.upper()}-{secrets.token_hex(16).upper()}"
    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return {
        "key": key,
        "key_hash": key_hash,
        "tier": tier,
        "customer": customer_email,
        "created": datetime.datetime.utcnow().isoformat(),
        "expires": expiry.isoformat()
    }

if __name__ == "__main__":
    # Usage: python generate_key.py pro customer@email.com 30
    tier, email, days = sys.argv[1], sys.argv[2], int(sys.argv[3])
    result = generate_key(tier, email, days)
    print(json.dumps(result, indent=2))
    print(f"\nAdd to config: '{result['key']}'")
```

---

### 2. Key Activation

**Current State:** Key is added to config → service reload required to recognize it.

**Gap:** There is no activation timestamp, no activation event logged, no customer portal showing key status.

**Certification: FAIL**

**Required Fix:** Maintain a `data/keys/active_keys.json` registry:
```json
{
  "SA-PRO-ABC123...": {
    "hash": "sha256...",
    "tier": "PRO",
    "customer_email": "customer@company.com",
    "reference_id": "SA-20260604-A7X2",
    "activated_at": "2026-06-04T10:00:00Z",
    "expires_at": "2026-07-04T10:00:00Z",
    "status": "active"
  }
}
```

Auth handler reads from this file + revocation registry. Enables:
- Runtime key activation without restart (file reload)
- Per-key expiry enforcement
- Audit trail per key

---

### 3. Tier Enforcement

**Current State:** Tiers enforced via separate key lists in config. Works.

**Gap:** No MSSP tier defined. PRO/PREMIUM aliasing creates confusion. No "trial" tier for 7-day free trial (promised on pricing.html).

**Certification: CONDITIONAL PASS**

**Required Fix — Canonical Tier Mapping:**

| Frontend Plan | Backend Tier | API Calls/day | Notes |
|--------------|-------------|--------------|-------|
| Community | FREE | 100 | Existing |
| PRO (Monthly) | PRO | 5,000 | Existing (map to PREMIUM internally) |
| PRO (Annual) | PRO | 5,000 | Same tier, longer expiry |
| Enterprise | ENTERPRISE | 50,000 | Existing |
| MSSP | MSSP | 500,000 | **NEW — needs adding to config** |
| Trial (7-day) | TRIAL | 500 | **NEW — needs adding** |

---

### 4. Quota Enforcement

**Current State:** Token-bucket rate limiter, in-memory. Works per-request.

**Gap:**
- No daily quota reset tracking persisted to disk
- No quota visibility for customers (no `/api/quota` endpoint)
- No pre-quota warning (no 429 response with `Retry-After` header confirmed)

**Certification: CONDITIONAL PASS**

**Required Endpoint — Quota Status:**
```
GET /api/quota
Authorization: Bearer SA-PRO-[KEY]

Response:
{
  "tier": "PRO",
  "quota_daily": 5000,
  "used_today": 237,
  "remaining": 4763,
  "resets_at": "2026-06-05T00:00:00Z",
  "subscription_expires": "2026-07-04T10:00:00Z"
}
```

---

### 5. Suspension

**Current State:** Revocation registry at `data/security/revoked_keys.json` — key SHA-256 hashes listed here are rejected immediately.

**Functionality:** Works. Operator can add hash to file → key immediately rejected without restart.

**Gap:**
- No automated suspension on subscription expiry
- No customer notification when key is suspended
- No self-service reactivation path

**Certification: CONDITIONAL PASS**

**Required Suspension Flow:**
```
Expiry date reached → Cron job checks active_keys.json →
  If expires_at < now: set status = "expired" →
  Send expiry email to customer →
  Key still works for 3-day grace period →
  After grace: add hash to revoked_keys.json →
  Customer gets 401 response with message:
  {
    "error": "subscription_expired",
    "message": "Your subscription expired on [DATE]. Renew at: https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html",
    "reference": "SA-XXXX"
  }
```

---

### 6. Expiration

**Current State:** No expiry mechanism in code. Keys in config do not expire.

**Certification: FAIL — No expiry enforcement.**

**Required Fix:** Add expiry check to `AuthHandler.resolve_tier()`:
```python
def _check_expiry(self, key: str) -> bool:
    """Returns True if key is still valid (not expired)."""
    registry = self._load_key_registry()  # load active_keys.json
    if key in registry:
        expiry = datetime.fromisoformat(registry[key]["expires_at"])
        if datetime.now(timezone.utc) > expiry:
            self._log_audit_event("key_expired", key)
            return False  # key expired
    return True
```

---

### 7. Key Rotation

**Current State:** No rotation mechanism. Keys are permanent once issued.

**Gap:** No customer-initiated rotation, no admin rotation tool, no rotation policy.

**Certification: FAIL**

**Required Rotation Flow (Phase 1 — Manual):**
1. Customer emails support requesting rotation
2. Operator generates new key via `generate_key.py`
3. Operator adds old key hash to `revoked_keys.json`
4. Operator adds new key to `active_keys.json`
5. Operator emails new key to customer
6. Update CRM with new key hash

**Required Rotation Flow (Phase 2 — Automated):**
```
POST /api/rotate-key
Authorization: Bearer SA-PRO-[OLD-KEY]

Response:
{
  "new_key": "SA-PRO-[NEW-KEY]",
  "old_key_expires": "2026-06-11T00:00:00Z"  // 7-day overlap
}
```

---

## PROVISIONING WORKFLOW — END-TO-END DESIGN

```
Customer Paid (Formspree submission received)
        ↓
Operator verifies payment (Step 2 of RevOps Playbook)
        ↓
Operator runs: python generate_key.py pro customer@email.com 30
        ↓
Key generated: SA-PRO-A1B2C3D4E5F6...
        ↓
Operator adds entry to data/keys/active_keys.json
        ↓
Operator adds key to CDB_PRO_API_KEYS in config (if file-reload not available)
        ↓
Operator sends API Key Delivery Email (template from RevOps Playbook)
        ↓
Customer receives key — can call API within minutes
        ↓
CRM updated: status = ACTIVE, key_hash = [hash], key_issued_at = [now]
        ↓
Renewal reminder cron: D-14, D-7, D-3 before expires_at
```

---

## PROVISIONING CERTIFICATION SUMMARY

| Capability | Status | Priority Fix |
|-----------|--------|-------------|
| Key Generation | ❌ Manual only | Create generate_key.py script |
| Key Activation | ❌ Config-only, requires restart | Create active_keys.json runtime registry |
| Tier Enforcement | ⚠️ Works but mismatched | Add MSSP + TRIAL tiers |
| Quota Enforcement | ⚠️ Works, no customer visibility | Add /api/quota endpoint |
| Suspension | ✅ Revocation registry works | Add auto-suspension on expiry |
| Expiration | ❌ No expiry enforcement | Add expiry check to auth.py |
| Key Rotation | ❌ Not implemented | Add rotation protocol (manual first) |

**Overall Provisioning Certification: CONDITIONAL PASS (Manual Workflow)**

The system has the architectural foundations but requires the runtime key registry and generate_key.py script to be operational before the first paying customer.

---

*Audit completed: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
