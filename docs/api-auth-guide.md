# SENTINEL APEX API — Authentication Guide

**Version:** v1.0.0  
**Status:** Production  
**Base URL:** `https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`

---

## Overview

SENTINEL APEX provides a threat intelligence feed API accessible to subscribers. The public feed endpoint requires no authentication. Private and enriched endpoints require a Bearer token.

---

## Public Endpoint (No Auth Required)

```bash
GET https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json
```

Returns the latest 25 curated threat intelligence items. No API key required.

```bash
curl -s https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json | python3 -m json.tool
```

---

## Authentication

All private endpoints require an API key passed as a Bearer token:

```
Authorization: Bearer sa_YOUR_API_KEY_HERE
```

### Getting Your API Key

| Tier       | Source                    | Included Features                              |
|------------|---------------------------|------------------------------------------------|
| FREE       | Self-service signup        | Public feed, 25 items/day, no CVSS/KEV         |
| PRO        | Gumroad subscription       | 200+ items/day, CVSS/KEV/EPSS, actor attribution |
| ENTERPRISE | Direct: bivashnayak.ai007@gmail.com | Full feed, SLA, multi-tenant, SIEM integration |

---

## 401 Unauthorized — Troubleshooting

If you receive `HTTP 401 Unauthorized`, check the following:

### 1. Correct Authorization header format

```bash
# CORRECT:
curl -H "Authorization: Bearer sa_abc123def456" https://...

# WRONG — missing "Bearer":
curl -H "Authorization: sa_abc123def456" https://...

# WRONG — Basic auth:
curl -u "user:sa_abc123def456" https://...

# WRONG — Query param (not supported):
curl "https://...?api_key=sa_abc123def456"
```

### 2. Key rotation

PRO keys rotate every 90 days. Check your subscription email for the renewal notice. Re-fetch your key from the Gumroad dashboard.

### 3. Key not yet activated

New keys provisioned via Gumroad may take up to 5 minutes to activate. Wait and retry.

### 4. Expired subscription

If your Gumroad subscription lapsed, the key is deactivated. Renew at your Gumroad subscription page.

### 5. Contact support

If none of the above resolve the 401:
- Email: bivashnayak.ai007@gmail.com  
- Subject: `[API AUTH] 401 - <your key prefix, first 8 chars only>`
- Include: timestamp, endpoint URL, response body

---

## Python SDK (Quick Start)

Install: no pip required — pure stdlib except optional `requests`.

```python
# Copy scripts/sentinel_apex_sdk.py to your project, then:
from sentinel_apex_sdk import SentinelApexClient, SentinelApexAuthError

client = SentinelApexClient(api_key="sa_YOUR_KEY")

try:
    feed = client.get_feed()
except SentinelApexAuthError as e:
    print(f"Auth failed: {e}")
    # Follow 401 troubleshooting guide above

# Filter critical items
critical = feed.filter_by_severity("critical", "high")
print(f"Critical/High items: {len(critical)}")

# Filter CISA KEV
kev_items = feed.filter_kev()
for item in kev_items:
    print(f"KEV: {item.cve_id} — {item.title}")

# Filter by threat actor
apt28_items = feed.filter_actor("APT28")
for item in apt28_items:
    print(f"APT28: {item.cve_id} CVSS={item.cvss_score}")
```

SDK source: `scripts/sentinel_apex_sdk.py`  
SDK CLI: `python3 scripts/sentinel_apex_sdk.py --health`

---

## Go SDK (Minimal Example)

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

const feedURL = "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json"

type FeedItem struct {
    ID        string  `json:"id"`
    Title     string  `json:"title"`
    Severity  string  `json:"severity"`
    CveID     string  `json:"cve_id"`
    CvssScore float64 `json:"cvss_score"`
    KevListed bool    `json:"kev_listed"`
}

func fetchFeed(apiKey string) ([]FeedItem, error) {
    req, _ := http.NewRequest("GET", feedURL, nil)
    if apiKey != "" {
        req.Header.Set("Authorization", "Bearer "+apiKey)
    }
    req.Header.Set("User-Agent", "SentinelApexGoSDK/1.0.0")
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode == 401 {
        return nil, fmt.Errorf("401 Unauthorized: check Authorization: Bearer <key>")
    }
    body, _ := io.ReadAll(resp.Body)
    var items []FeedItem
    json.Unmarshal(body, &items)
    return items, nil
}

func main() {
    items, err := fetchFeed(os.Getenv("SENTINEL_APEX_API_KEY"))
    if err != nil {
        panic(err)
    }
    for _, item := range items {
        fmt.Printf("[%s] %s  CVE=%s  CVSS=%.1f\n",
            item.Severity, item.Title, item.CveID, item.CvssScore)
    }
}
```

---

## JavaScript / Node.js SDK (Minimal Example)

```javascript
const FEED_URL = 'https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json';

async function fetchFeed(apiKey = '') {
  const headers = { 'User-Agent': 'SentinelApexJSSDK/1.0.0' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

  const resp = await fetch(FEED_URL, { headers });
  if (resp.status === 401) {
    throw new Error('401 Unauthorized — check Authorization: Bearer <key>');
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// Usage:
const apiKey = process.env.SENTINEL_APEX_API_KEY || '';
fetchFeed(apiKey).then(items => {
  const critical = items.filter(i => i.severity === 'high' || i.severity === 'critical');
  const kevItems = items.filter(i => i.kev_listed);
  console.log(`Total: ${items.length}, Critical/High: ${critical.length}, KEV: ${kevItems.length}`);
}).catch(console.error);
```

---

## Rate Limits

| Tier       | Requests/min | Items/day | NVD Enrichment |
|------------|-------------|-----------|----------------|
| FREE       | 10          | 25        | No             |
| PRO        | 60          | 200+      | Yes            |
| ENTERPRISE | Unlimited   | Full feed | Yes + Bulk     |

Rate limit responses return `HTTP 429 Too Many Requests` with a `Retry-After` header.

---

## SLA Reference

Full SLA documentation: [docs/SLA.md](SLA.md)

| Tier       | Uptime SLA | Feed Latency | Support Response |
|------------|------------|--------------|------------------|
| FREE       | Best effort| 4h batch     | Community        |
| PRO        | 99.9%      | 1h           | 24h email        |
| ENTERPRISE | 99.95%     | 15 min       | 4h dedicated     |

---

## Changelog

- **v1.0.0** (2026-05-27): Initial API auth guide — addresses P1.3c customer gap (401 with no docs)
