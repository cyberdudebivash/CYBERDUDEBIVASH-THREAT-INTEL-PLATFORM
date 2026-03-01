# 🔥 SENTINEL APEX v26.0 "Phoenix" — CRITICAL FIX + UPGRADE PACKAGE

> **PRODUCTION INCIDENT RESOLUTION + NEW FEATURES**

---

## 🚨 CRITICAL ISSUE FIXED

Your GitHub Actions workflow is failing with:

```
fatal: not a git repository (or any of the parent directories): .git
Error: Action failed with "The process '/usr/bin/git' failed with exit code 128"
```

**ROOT CAUSE:** The `peaceiris/actions-gh-pages@v3` action loses git context when deploying from root directory.

**SOLUTION:** This package replaces it with `JamesIves/github-pages-deploy-action@v4` which handles this correctly.

---

## 📦 PACKAGE CONTENTS

```
SENTINEL_APEX_v26_UPGRADE/
│
├── .github/workflows/
│   └── sentinel-blogger.yml     # ✅ FIXED workflow (REPLACE)
│
├── agent/v26/
│   ├── __init__.py              # v26 module init
│   ├── config_v26.py            # v26 configuration
│   ├── temporal_decay.py        # NEW: Time-based scoring
│   └── ioc_correlation.py       # NEW: IOC clustering
│
├── patches/
│   └── index_html_v26_fix.patch # Dashboard timestamp fix
│
├── apply_v26_fix.py             # Automated fix script
├── requirements_v26.txt         # v26 dependencies
├── VERSION                      # 26.0.0
├── CHANGELOG_v26.md             # Full changelog
└── README_v26.md                # This file
```

---

## ⚡ QUICK FIX (5 minutes)

### Step 1: Replace Workflow File
Upload `sentinel-blogger.yml` to `.github/workflows/` (replace existing)

### Step 2: Fix index.html (Line ~2285)

**FIND:**
```javascript
const lastTs = data.length ? timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';
```

**REPLACE WITH:**
```javascript
let sortedData = [...data].sort((a, b) =>
    new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
);
const lastTs = sortedData.length ? timeSince(sortedData[0].timestamp) : '—';
```

### Step 3: Commit & Push
```bash
git add -A
git commit -m "v26.0: Fix deployment + timestamp bug"
git push origin main
```

### Step 4: Trigger Workflow
Go to: `Actions → CDB Sentinel Blogger → Run workflow`

---

## 🎯 WHAT THIS FIXES

| Issue | Status |
|-------|--------|
| GitHub Actions deployment failure | ✅ FIXED |
| "Last Sync: 3d ago" showing stale | ✅ FIXED |
| Fresh reports not appearing | ✅ FIXED |
| gh-pages not updating | ✅ FIXED |

---

## ✨ NEW FEATURES IN v26.0

### 1. Temporal Decay Engine
Older threats automatically score lower, keeping focus on current threats.

### 2. IOC Correlation Engine  
Automatically clusters related threats based on shared indicators.

### 3. Enhanced Resilience
Circuit breaker pattern and graceful degradation for better uptime.

---

## 📋 FILE PLACEMENT GUIDE

| File | Destination | Action |
|------|-------------|--------|
| `sentinel-blogger.yml` | `.github/workflows/` | **REPLACE** |
| `agent/v26/*` | `agent/v26/` | **ADD** (new folder) |
| `requirements_v26.txt` | Repository root | **ADD** |
| `VERSION` | Repository root | **REPLACE** |
| `CHANGELOG_v26.md` | Repository root | **ADD** |
| `index.html` | Edit in place | **EDIT line 2285** |

---

## 🔍 VERIFICATION CHECKLIST

After applying fixes:

- [ ] GitHub Actions workflow runs successfully
- [ ] No "fatal: not a git repository" errors
- [ ] Dashboard shows "Last Sync: < 1h"
- [ ] Fresh threat reports visible
- [ ] Status endpoint returns v26.0

**Test URLs:**
- Dashboard: https://intel.cyberdudebivash.com
- Status: https://intel.cyberdudebivash.com/data/status/status.json
- Manifest: https://intel.cyberdudebivash.com/data/stix/feed_manifest.json

---

## 🛠️ TECHNICAL DETAILS

### Workflow Changes (Key Differences)

```yaml
# OLD (v25 - BROKEN)
- uses: peaceiris/actions-gh-pages@v3
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    publish_dir: ./
    keep_files: true

# NEW (v26 - FIXED)
- uses: JamesIves/github-pages-deploy-action@v4
  with:
    branch: gh-pages
    folder: .
    clean: false
    single-commit: false
```

### Why JamesIves Works
- Properly handles repository root deployment
- Maintains git context throughout deployment
- Better error handling and recovery
- Active maintenance and updates

---

## 📞 SUPPORT

**Issues?** Open a GitHub issue or contact:
- Email: support@cyberdudebivash.com
- Twitter: @cyberbivash

---

*CYBERDUDEBIVASH® SENTINEL APEX v26.0 "Phoenix"*  
*(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.*
