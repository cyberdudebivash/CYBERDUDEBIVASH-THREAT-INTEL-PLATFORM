# SENTINEL APEX v46.0 — P0 INCIDENT RESOLUTION PLAYBOOK
**Incident:** Total sync failure / Dashboard data fetch blocked post v46 update  
**Severity:** P0 / Production Blocker  
**Platform:** intel.cyberdudebivash.com  
**Date:** 2026-03-14

---

## INCIDENT SUMMARY

**Symptoms observed:**
- `SYNC: INITIALIZING...` never resolves (status bar)
- "SYNCING GOC NEURAL CORE..." spinner loops indefinitely
- All dashboard metrics display `—` (dashes)
- No intelligence cards loaded
- All NEXUS/CORTEX/GOC sections stuck in "Computing..." / "Loading..." / "Analyzing signals..."

**Root cause probability matrix:**

| Vector | Probability | Impact |
|--------|-------------|--------|
| `feed_manifest.json` empty or missing | **85%** | Total dashboard failure |
| GitHub Actions pipeline crash | **75%** | No data generation |
| Wrong manifest fetch URL in index.html | **40%** | Fetch 404 |
| CORS block on custom domain | **25%** | Fetch blocked |
| v46 schema change crashing JS parser | **30%** | Parse failure |

---

## PHASE 1 — IMMEDIATE TRIAGE (5 MINUTES)

### Step 1.1: Check browser console
```
F12 → Console tab → Look for:
  - "Failed to fetch" → Network/CORS issue
  - "Unexpected token" → JSON parse error  
  - "404 Not Found" → Wrong URL path
  - "SyntaxError" → Manifest is empty or malformed
  - No errors at all → JS init not wired to fetch
```

### Step 1.2: Check manifest endpoint directly
```bash
# Open in browser or curl:
https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/data/stix/feed_manifest.json

# Expected: JSON array with advisory objects
# IF 404: Manifest was never generated or path changed
# IF empty []: Pipeline ran but produced no data
# IF valid JSON: CORS is the issue — use CDN URL
```

### Step 1.3: Check GitHub Actions
```
GitHub → Repo → Actions tab
→ Look at last 3 runs of sentinel-blogger workflow
→ Any red X = pipeline crashed = no new data
→ Check the failed step and error message
```

---

## PHASE 2 — FIX PROCEDURES BY ROOT CAUSE

### FIX A: Pipeline never ran / crashed (Most likely)

```bash
# Trigger manual run:
GitHub → Repo → Actions → sentinel-blogger → "Run workflow" button

# If workflow fails on Python step:
# 1. Check requirements.txt is current
# 2. Check all GitHub Secrets are set correctly
# 3. Read pipeline.log artifact from Actions run
```

**Deploy hardened workflow:**
```bash
# Copy sentinel-blogger-hardened.yml to:
.github/workflows/sentinel-blogger.yml

# This adds: manifest validation, backup/restore on failure, 
# retry logic, failure Discord notification
```

### FIX B: Manifest exists but dashboard can't load it

**Patch index.html data fetch:**

Find in index.html the existing data fetch/init code and replace with the content of `DATA_FETCH_ENGINE_PATCH.js`.

The patch provides:
- 3-source fallback: Primary → GitHub Raw → jsDelivr CDN
- 3-retry per source with 2s delay
- Null-safe schema parsing (v46 new fields won't crash)
- Proper error banner when all sources fail
- Auto-refresh every 5 minutes

**Integration:**
```html
<!-- In index.html, at end of <body> or in <script> section -->
<!-- REPLACE existing init code with: -->
<script>
// [paste full contents of DATA_FETCH_ENGINE_PATCH.js here]
</script>
```

### FIX C: CORS blocking fetch from intel.cyberdudebivash.com

The GitHub Pages CORS policy may block cross-origin fetches from the custom domain.

**Immediate fix:** Use jsDelivr CDN URL in index.html:
```javascript
// Change manifest URL to:
const MANIFEST_URL = 'https://cdn.jsdelivr.net/gh/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM@main/data/stix/feed_manifest.json';
// jsDelivr serves with: Access-Control-Allow-Origin: *
```

### FIX D: Empty manifest (pipeline ran, no data)

```bash
# Check feed accessibility:
python3 -c "
import urllib.request
FEEDS = [
    'https://feeds.feedburner.com/TheHackersNews',
    'https://www.bleepingcomputer.com/feed/',
    'https://krebsonsecurity.com/feed/',
]
for url in FEEDS:
    try:
        urllib.request.urlopen(url, timeout=5)
        print(f'OK: {url}')
    except Exception as e:
        print(f'FAIL: {url} — {e}')
"

# If feeds are down: Platform will self-recover on next successful fetch
# Add more fallback feeds to config.py
```

### FIX E: v46 schema change breaking JS parser

If manifest loads but metrics still `—`, the v46 schema added new required fields that break the existing parser:

```javascript
// UNSAFE (v45 pattern — crashes on missing field):
const risk = advisory.risk_score;  // undefined in v46 if field renamed

// SAFE (v46 hardened pattern):
const risk = advisory.risk_score ?? advisory.risk ?? advisory.cvss_score ?? 0;
const title = advisory.title ?? advisory.name ?? advisory.feed_title ?? 'Unknown';
const ts = advisory.timestamp ?? advisory.created_at ?? advisory.date ?? '';
```

The `DATA_FETCH_ENGINE_PATCH.js` uses `safeGet()` throughout to prevent this.

---

## PHASE 3 — DEPLOY FIXES

### Deployment sequence (zero-regression):

```bash
# 1. Run diagnostic to confirm failure vector
python3 p0_diagnostic.py

# 2. Deploy hardened workflow
cp sentinel-blogger-hardened.yml .github/workflows/sentinel-blogger.yml

# 3. Trigger manual pipeline run
# GitHub → Actions → Run workflow

# 4. Verify manifest generated
curl https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/data/stix/feed_manifest.json | python3 -m json.tool | head -50

# 5. Patch index.html with DATA_FETCH_ENGINE_PATCH.js
# Find and replace existing init/fetch logic

# 6. Commit and push
git add .
git commit -m "fix(p0): v46 sync failure — hardened data fetch + pipeline"
git push

# 7. Wait 2-3 minutes for GitHub Pages deployment
# 8. Hard refresh intel.cyberdudebivash.com (Ctrl+Shift+R)
# 9. Verify dashboard shows LIVE status and metric values
```

---

## PHASE 4 — VERIFICATION CHECKLIST

- [ ] `SYNC: LIVE` shown in status bar (not INITIALIZING)
- [ ] "SYNCING GOC NEURAL CORE..." spinner replaced with data
- [ ] Total Advisories metric shows a number (not —)
- [ ] Critical / High / Avg Risk / Total IOCs all populated  
- [ ] NEXUS section: Threat Exposure Index shows numeric value
- [ ] NEXUS section: Correlated Campaigns shows actor names
- [ ] CORTEX section: Knowledge Graph Nodes populated
- [ ] No error banner at top of page
- [ ] Browser console: no failed fetch errors

---

## LONG-TERM HARDENING (POST-INCIDENT)

1. **Add manifest health check endpoint** — dedicated URL returning manifest age + advisory count
2. **Stale manifest detection** — alert if manifest is >24h old
3. **Fallback static data** — embed last-known-good 10 advisories directly in index.html as `EMBEDDED_INTEL` constant (eliminates all fetch failures for basic visibility)
4. **Monitoring webhook** — POST to Discord/Slack when sync fails
5. **Canary data record** — always embed one "canary advisory" in manifest to detect empty-manifest scenarios

---

## FILES DELIVERED

| File | Purpose |
|------|---------|
| `DATA_FETCH_ENGINE_PATCH.js` | Production data-fetch engine for index.html |
| `sentinel-blogger-hardened.yml` | Hardened GitHub Actions workflow |
| `p0_diagnostic.py` | Automated failure-vector diagnostic |
| `P0_DIAGNOSTIC.md` | Manual diagnostic guide |
| `P0_RESOLUTION_PLAYBOOK.md` | This file |

© 2026 CyberDudeBivash Pvt. Ltd. — Sentinel APEX Engineering
