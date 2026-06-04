# CYBERDUDEBIVASH® SENTINEL APEX — Customer Onboarding Package
**Classification:** Customer-Facing Documentation
**Platform:** SENTINEL APEX CTI Platform — v174.1
**Platform URL:** https://intel.cyberdudebivash.com
**Document Date:** 2026-06-04
**Version:** 1.0

---

## Welcome to SENTINEL APEX

SENTINEL APEX is a production-grade Cyber Threat Intelligence (CTI) platform delivering structured, machine-readable threat intelligence feeds covering high-risk and critical vulnerabilities. The platform provides STIX 2.1-formatted intelligence with Admiralty-graded confidence scores, Cloudflare-backed global delivery, and real-time enrichment via EPSS and CISA KEV cross-validation.

This guide covers everything you need to go from API key to live threat detection in under 60 minutes.

---

## Section 1: Quick Start (5 Steps)

### Step 1: Receive Your API Key
Upon subscription confirmation, you will receive an email containing:
- Your API key (Bearer token format)
- Your tier: Free / Pro / Enterprise / MSSP
- Your rate limit: requests per minute/hour per tier
- This onboarding document link

Store your API key in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets, or equivalent). Do not commit it to source control.

### Step 2: Verify Authentication
Test your key immediately after receipt:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://intel.cyberdudebivash.com/api/health
```

Expected response:
```json
{"status": "healthy", "version": "170.0"}
```

If you receive a 401 response, confirm your key is copied correctly (no leading/trailing whitespace) and that your key is activated. Contact support if the issue persists.

### Step 3: Pull Your First Feed
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://intel.cyberdudebivash.com/api/apex.json
```

This returns the full APEX threat feed in JSON format with STIX IDs, confidence scores, risk ratings, CVE identifiers, severity classifications, and enrichment metadata.

### Step 4: Validate Feed Structure
Confirm you can parse the feed and access key fields:
```bash
curl -s -H "Authorization: Bearer YOUR_API_KEY" \
  https://intel.cyberdudebivash.com/api/apex.json \
  | python3 -c "
import json, sys
feed = json.load(sys.stdin)
print(f'Items: {len(feed)}')
for item in feed[:3]:
    print(f'  {item.get(\"cve_id\")}: severity={item.get(\"severity\")}, confidence={item.get(\"confidence_score\")}, risk={item.get(\"risk_score\")}')
"
```

### Step 5: Integrate into Your Stack
Choose your integration path:
- **SIEM integration:** See Section 4
- **STIX/MISP import:** See Section 5
- **Detection packs:** See Section 6
- **Custom pipeline:** Use the Python SDK example in Section 4.1

---

## Section 2: API Authentication

### 2.1 Bearer Token Format
All authenticated API requests must include the `Authorization` header:

```
Authorization: Bearer <your_api_key>
```

The API key is a UUID-format string. Example header:
```
Authorization: Bearer xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 2.2 Tier Rate Limits

| Tier | Price | Rate Limit | Feed Refresh | AI Summary |
|---|---|---|---|---|
| Free | $0/mo | Lowest | Hourly | No |
| Pro | $49/mo | Medium | 15 minutes | No |
| Enterprise | $499/mo | High | 5 minutes | Yes |
| MSSP | $1,999/mo | Highest | Real-time | Yes + Sub-tenants |

Rate limit headers are returned with every response:
- `X-RateLimit-Limit`: requests allowed per window
- `X-RateLimit-Remaining`: requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when window resets

### 2.3 Authentication Errors

| HTTP Status | Meaning | Action |
|---|---|---|
| 401 Unauthorized | Missing or invalid API key | Check key format; confirm key is active |
| 403 Forbidden | Key valid but tier lacks access | Upgrade tier |
| 429 Too Many Requests | Rate limit exceeded | Respect `Retry-After` header |

---

## Section 3: Available Endpoints

| Endpoint | Auth Required | Description |
|---|---|---|
| `GET /api/health` | No | Platform health status |
| `GET /api/latest.json` | Yes | Latest threat feed (compact) |
| `GET /api/apex.json` | Yes | Full APEX feed with enrichment |
| `GET /api/ai_summary.json` | Yes (Enterprise+) | AI-generated threat summary |

---

## Section 4: Feed Integration Examples

### 4.1 Python SDK Example

```python
import requests
import json
from datetime import datetime

SENTINEL_APEX_KEY = "your_api_key_here"  # Use environment variable in production
BASE_URL = "https://intel.cyberdudebivash.com"

def fetch_apex_feed():
    """Fetch the full APEX threat feed."""
    headers = {"Authorization": f"Bearer {SENTINEL_APEX_KEY}"}
    response = requests.get(f"{BASE_URL}/api/apex.json", headers=headers)
    response.raise_for_status()
    return response.json()

def filter_critical_threats(feed, min_confidence=0.20, min_risk=8.0):
    """Filter feed to high-confidence, high-risk items."""
    return [
        item for item in feed
        if item.get("confidence_score", 0) >= min_confidence
        and item.get("risk_score", 0) >= min_risk
    ]

def main():
    print(f"[{datetime.utcnow().isoformat()}] Fetching SENTINEL APEX feed...")
    feed = fetch_apex_feed()
    print(f"Feed items: {len(feed)}")

    critical = filter_critical_threats(feed)
    print(f"Critical/high-priority items (confidence>=0.20, risk>=8.0): {len(critical)}")

    for item in critical:
        print(f"  {item.get('cve_id')} | Severity: {item.get('severity')} | "
              f"Risk: {item.get('risk_score')} | Confidence: {item.get('confidence_score')}")

if __name__ == "__main__":
    main()
```

### 4.2 cURL Examples

**Fetch latest feed:**
```bash
curl -s -H "Authorization: Bearer $APEX_KEY" \
  https://intel.cyberdudebivash.com/api/latest.json \
  | jq '.[] | {cve: .cve_id, severity: .severity, risk: .risk_score}'
```

**Filter CRITICAL items only:**
```bash
curl -s -H "Authorization: Bearer $APEX_KEY" \
  https://intel.cyberdudebivash.com/api/apex.json \
  | jq '[.[] | select(.severity == "CRITICAL")]'
```

**Get AI summary (Enterprise+):**
```bash
curl -s -H "Authorization: Bearer $APEX_KEY" \
  https://intel.cyberdudebivash.com/api/ai_summary.json \
  | jq '.summary'
```

### 4.3 Splunk SIEM Integration

Add as a scripted input in Splunk:

```python
# splunk_apex_input.py — place in $SPLUNK_HOME/etc/apps/your_app/bin/
import requests
import json
import sys

APEX_KEY = "your_api_key"
BASE_URL = "https://intel.cyberdudebivash.com"

headers = {"Authorization": f"Bearer {APEX_KEY}"}
response = requests.get(f"{BASE_URL}/api/apex.json", headers=headers)
feed = response.json()

for item in feed:
    # Output as Splunk key=value format
    print(json.dumps({
        "sourcetype": "sentinel_apex_cti",
        "event": item
    }))
```

**Splunk search to alert on CRITICAL items:**
```
index=threat_intel sourcetype=sentinel_apex_cti severity=CRITICAL
| table cve_id, risk_score, confidence_score, source, _time
| sort -risk_score
```

### 4.4 Microsoft Sentinel / Azure Log Analytics Integration

```python
import requests
import json
import datetime
import hashlib
import hmac
import base64
import os

# Azure Log Analytics workspace credentials
workspace_id = os.environ["LA_WORKSPACE_ID"]
shared_key = os.environ["LA_SHARED_KEY"]
log_type = "SentinelApexCTI"

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

def post_to_log_analytics(body):
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = build_signature(workspace_id, shared_key, rfc1123date, content_length, "POST", "application/json", "/api/logs")
    uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    return response.status_code

apex_feed = requests.get(
    "https://intel.cyberdudebivash.com/api/apex.json",
    headers={"Authorization": f"Bearer {os.environ['APEX_KEY']}"}
).json()

status = post_to_log_analytics(json.dumps(apex_feed))
print(f"Log Analytics ingestion status: {status}")
```

---

## Section 5: STIX/MISP Import Guide

### 5.1 STIX 2.1 Import (OpenCTI)

All 19 feed items carry valid STIX IDs. To import into OpenCTI:

1. Export the feed in STIX bundle format:
```bash
curl -s -H "Authorization: Bearer $APEX_KEY" \
  https://intel.cyberdudebivash.com/api/apex.json \
  | python3 -c "
import json, sys
items = json.load(sys.stdin)
bundle = {
    'type': 'bundle',
    'id': 'bundle--sentinel-apex-$(date +%Y%m%d)',
    'objects': items
}
print(json.dumps(bundle, indent=2))
" > apex_stix_bundle.json
```

2. In OpenCTI: go to **Data > Import > Upload file**, select `apex_stix_bundle.json`
3. Map `confidence_score` → OpenCTI confidence field
4. Map `severity` → OpenCTI threat level

### 5.2 MISP Import

Using PyMISP:
```python
from pymisp import PyMISP, MISPEvent, MISPAttribute
import requests

apex_feed = requests.get(
    "https://intel.cyberdudebivash.com/api/apex.json",
    headers={"Authorization": f"Bearer YOUR_KEY"}
).json()

misp = PyMISP("https://your-misp-instance.com", "YOUR_MISP_KEY")

for item in apex_feed:
    event = MISPEvent()
    event.info = f"SENTINEL APEX: {item.get('cve_id')} - {item.get('severity')}"
    event.threat_level_id = 1 if item.get('severity') == 'CRITICAL' else 2
    event.distribution = 1

    cve_attr = MISPAttribute()
    cve_attr.type = "vulnerability"
    cve_attr.value = item.get("cve_id")
    cve_attr.comment = f"Risk: {item.get('risk_score')}, Confidence: {item.get('confidence_score')}"
    event.add_attribute(**cve_attr)

    misp.add_event(event)
    print(f"Imported: {item.get('cve_id')}")
```

---

## Section 6: Detection Pack Usage

SENTINEL APEX ships detection content for common security tooling.

### 6.1 Sigma Rules
Located in: `dist/detections/sigma/`

```bash
# Convert Sigma rules to Splunk SPL
sigma convert -t splunk dist/detections/sigma/apex_*.yml

# Convert to Elastic/KQL
sigma convert -t lucene dist/detections/sigma/apex_*.yml
```

### 6.2 YARA Rules
Located in: `dist/detections/yara/`

```bash
# Scan a directory with YARA rules
yara dist/detections/yara/apex_rules.yar /path/to/scan -r
```

### 6.3 KQL Queries (Microsoft Sentinel / Defender)
Located in: `dist/detections/kql/`

Import directly into Microsoft Sentinel via Analytics > Create > Import rule.

### 6.4 Suricata Rules
Located in: `dist/detections/suricata/`

```bash
# Add to Suricata rules path
cp dist/detections/suricata/apex_*.rules /etc/suricata/rules/
suricata-update
systemctl reload suricata
```

---

## Section 7: Upgrade Path

| From | To | Action |
|---|---|---|
| Free | Pro | Visit https://intel.cyberdudebivash.com/upgrade — select Pro tier |
| Pro | Enterprise | Contact support or upgrade via portal |
| Enterprise | MSSP | Contact support for MSSP onboarding |

Upon upgrade, your API key tier is updated automatically within minutes. No key rotation is required.

---

## Section 8: Support

| Channel | Use Case | Response Time |
|---|---|---|
| Email: root@cyberdudebivash.in | Technical issues, billing, onboarding | 24–48 hours |
| Platform: https://intel.cyberdudebivash.com | Feed access, API issues | N/A — self-service |

**For MSSP and Enterprise customers:** Priority support terms are defined in your service agreement.

**For security disclosures:** Please report platform security issues directly to root@cyberdudebivash.in with subject line "SECURITY DISCLOSURE — SENTINEL APEX".

---

*Document version: 1.0 | 2026-06-04 | CYBERDUDEBIVASH® SENTINEL APEX*
*This document is provided to licensed customers of the SENTINEL APEX platform.*
