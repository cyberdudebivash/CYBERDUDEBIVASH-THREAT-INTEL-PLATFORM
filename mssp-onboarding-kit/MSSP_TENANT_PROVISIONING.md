# MSSP TENANT PROVISIONING WORKFLOW
## SENTINEL APEX v177.0 — Sub-Key Provisioning for MSSP End Clients
**Version:** 1.0 | **Date:** 2026-06-04

---

## OVERVIEW

This document defines the exact workflow for provisioning API sub-keys for MSSP end clients. Each sub-key is a standard PRO or ENTERPRISE key tied to the MSSP's reference and the end client's identity.

---

## WHEN TO PROVISION A SUB-KEY

Sub-keys are provisioned when an MSSP client:
1. Needs to integrate SENTINEL APEX directly into their own SIEM (not via MSSP's master key)
2. Needs a dedicated API key for audit trail purposes
3. Requires a separate rate limit allocation for heavy usage

Most MSSP clients use the master key via the MSSP's infrastructure. Sub-keys are for direct client integration scenarios.

---

## SUB-KEY REQUEST WORKFLOW

### Step 1 — MSSP Submits Sub-Key Request

**Channel:** Email to bivash@cyberdudebivash.com
**Subject line:** `Sub-key request — [MSSP_ID] / [CLIENT_NAME]`

**Required fields:**
```
MSSP Partner ID: [MSSP-YYYYMMDD-XXXX]
Client Company: [NAME]
Client Contact Name: [NAME]
Client Contact Email: [EMAIL]
Tier Requested: PRO or ENTERPRISE
Duration: 30 days / 365 days
Use Case: SIEM integration / Direct API / Threat hunting
SIEM Platform: Splunk / Sentinel / QRadar / Elastic / Other
```

**Operator response time:** 2 hours during business hours (9am–9pm IST), 4 hours otherwise.

---

### Step 2 — Operator Provisions Sub-Key

```bash
# Provision PRO sub-key for MSSP end client
python agent/tools/generate_key.py generate \
  --tier pro \
  --email [CLIENT_EMAIL] \
  --ref [MSSP_ID]-[CLIENT_SHORTNAME] \
  --days [30 or 365]

# Example:
python agent/tools/generate_key.py generate \
  --tier pro \
  --email soc@clientcompany.com \
  --ref MSSP-20260604-A7X2-CLIENTCO \
  --days 30

# Output:
# Key: SA-PRO-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Hash stored in: data/keys/active_keys.json
# Audit logged in: data/keys/audit.log
```

**Key metadata stored:**
```json
{
  "tier": "PRO",
  "customer_email": "soc@clientcompany.com",
  "customer_name": "[CLIENT NAME]",
  "company": "[CLIENT COMPANY]",
  "reference_id": "MSSP-20260604-A7X2-CLIENTCO",
  "api_calls_per_day": 5000,
  "issued_at": "2026-06-04T...",
  "expires_at": "2026-07-04T...",
  "mssp_parent": "MSSP-20260604-A7X2"
}
```

---

### Step 3 — Deliver Sub-Key to MSSP

**Email to MSSP contact (not directly to end client):**
```
Subject: Sub-key for [CLIENT_NAME] — MSSP-[ID]

Hi [MSSP_CONTACT],

Sub-key provisioned for [CLIENT_NAME]:

API Key: SA-PRO-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Tier: PRO
Daily limit: 5,000 API calls
Expires: [DATE]
Reference: [MSSP_ID]-[CLIENT_SHORTNAME]

[If ENTERPRISE requested]:
API Key: SA-ENT-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Daily limit: 50,000 API calls

Integration quickstart for [THEIR_SIEM]:
https://intel.cyberdudebivash.com/docs/quickstart.html

Let me know once [CLIENT_NAME] is connected.

— Bivash
```

---

### Step 4 — MSSP Delivers Key to End Client

The MSSP delivers the sub-key to their end client via their own communication channel. This maintains the MSSP's client relationship and keeps SENTINEL APEX in the background.

---

## SUB-KEY LIFECYCLE MANAGEMENT

### Renewal
When a sub-key expires, the MSSP requests renewal via the same email process. Operator extends the key:
```bash
# Extend by 30 more days:
python agent/tools/generate_key.py generate \
  --tier pro \
  --email [SAME_CLIENT_EMAIL] \
  --ref [SAME_REFERENCE] \
  --days 30
# Old key is replaced; new key issued
```

### Suspension (Client offboarded by MSSP)
When an MSSP removes a client:
```bash
python agent/tools/generate_key.py expire \
  --key [CLIENT_KEY_PREFIX]
```
Notify the MSSP once completed.

### Emergency Revocation (Security incident)
If a sub-key is compromised:
```bash
python agent/tools/generate_key.py revoke \
  --key [CLIENT_KEY_PREFIX] \
  --reason "Credential compromise reported by MSSP [MSSP_ID]"
```
New key provisioned within 1 hour.

---

## SUB-KEY AUDIT

Monthly, the operator should:
```bash
# Review all active sub-keys:
python agent/tools/generate_key.py list

# Check for expiring sub-keys (next 14 days):
# grep expires_at data/keys/active_keys.json | [filter to <14 days]

# Cross-reference with data/mssp/partners.json
# Ensure all active MSSP partners have valid sub-keys for their client count
```

---

## CAPACITY PLANNING

| MSSP Phase | Sub-Keys | Master Key Calls Used |
|------------|----------|----------------------|
| Phase 1 (5 clients) | Up to 25 sub-keys | ~25,000/day at 5,000/client |
| Phase 2 (20 clients) | Up to 100 sub-keys | ~100,000/day at 5,000/client |
| Master key limit | Unlimited sub-keys | 500,000/day total |

**Note:** Sub-keys have their own rate limits. Master key calls and sub-key calls are counted separately. The master key's 500,000/day limit covers MSSP's own infrastructure usage; sub-key limits are per-key.

---

*MSSP Tenant Provisioning v1.0 · SENTINEL APEX v177.0 · 2026-06-04*
