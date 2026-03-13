# SENTINEL APEX v46.0 — P0 INCIDENT DIAGNOSTIC
**Incident:** Total sync failure / Dashboard data fetch failure post v46 update  
**Severity:** P0 — Production blocker  
**Platform:** intel.cyberdudebivash.com

---

## ROOT CAUSE ANALYSIS — 5 FAILURE VECTORS (RUN IN ORDER)

### VECTOR 1: feed_manifest.json — Missing or Empty (MOST LIKELY)
```bash
# Check if manifest exists and has data
curl -s "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/data/stix/feed_manifest.json" | head -100

# Expected: JSON with array of advisory objects
# Failure indicators:
#   - 404 → Path broken in v46 restructure
#   - Empty file / {"advisories": []} → Pipeline hasn't run
#   - HTML content returned → GitHub Pages routing issue
```

### VECTOR 2: GitHub Actions — Pipeline Run Status
```bash
# Check last 5 workflow runs via GitHub API
curl -s "https://api.github.com/repos/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs?per_page=5" \
  -H "Accept: application/vnd.github+json" | python3 -m json.tool | grep -E "conclusion|status|name|created_at"

# Failure indicators:
#   - conclusion: "failure" → sentinel_blogger.py is crashing
#   - No recent runs → Workflow trigger broken
#   - conclusion: "success" but data still empty → Commit push failing
```

### VECTOR 3: CORS / Custom Domain Fetch Block
```bash
# Check CORS headers on the data endpoint
curl -I -H "Origin: https://intel.cyberdudebivash.com" \
  "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/data/stix/feed_manifest.json"

# Failure indicator: Missing Access-Control-Allow-Origin header
# GitHub Pages serves CORS for *.github.io but custom domain cross-fetch may be blocked
```

### VECTOR 4: Dashboard JS — Data Source URL Mismatch
In index.html, search for the manifest fetch URL:
```javascript
// Search for patterns like:
const MANIFEST_URL = '...'
fetch('data/stix/feed_manifest.json')
fetch('./data/stix/feed_manifest.json')
fetch('https://raw.githubusercontent.com/...')

// If v46 renamed data directories, this URL is stale
```

### VECTOR 5: v46 Schema Breaking Change
```bash
# Check if manifest schema changed in v46 — new required fields breaking JS parser
# In sentinel_blogger.py, check the manifest write function
# Look for new keys added without dashboard-side handling: null/undefined crashes
```

---

## EXPECTED FIX MAP BY VECTOR

| Vector | Fix Location | Fix Action |
|--------|-------------|------------|
| V1 - Manifest missing | GitHub Actions | Force re-run workflow |
| V2 - Pipeline crash | agent/sentinel_blogger.py | Fix crash, re-run |
| V3 - CORS block | index.html | Use GitHub Raw API URL with no-cors or embed data |
| V4 - URL mismatch | index.html | Update fetch URL to correct v46 path |
| V5 - Schema break | index.html JS parser | Add null-safe parsing with fallback defaults |
