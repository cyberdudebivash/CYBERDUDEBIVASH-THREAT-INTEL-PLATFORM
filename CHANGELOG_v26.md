# CYBERDUDEBIVASH® SENTINEL APEX v26.0 CHANGELOG
## Codename: Phoenix 🔥

**Release Date:** March 2026  
**Classification:** PRODUCTION CRITICAL FIX + FEATURE RELEASE

---

## 🚨 CRITICAL FIXES

### GitHub Actions Deployment Failure (RESOLVED)
**Issue:** Workflow failing with `fatal: not a git repository` error  
**Root Cause:** `peaceiris/actions-gh-pages@v3` loses git context when using `publish_dir: ./`  
**Solution:** Migrated to `JamesIves/github-pages-deploy-action@v4`

```yaml
# BEFORE (BROKEN - v25.0)
- uses: peaceiris/actions-gh-pages@v3
  with:
    publish_dir: ./  # ← Causes .git context loss

# AFTER (FIXED - v26.0)
- uses: JamesIves/github-pages-deploy-action@v4
  with:
    branch: gh-pages
    folder: .
    clean: false
```

### Dashboard "Last Sync: 3d ago" Bug (RESOLVED)
**Issue:** Dashboard showing stale timestamp even when fresh data exists  
**Root Cause:** index.html line 2285 reads from OLDEST array entry instead of NEWEST  
**Location:** `index.html:2285`

```javascript
// BEFORE (BUGGY - v25.0)
const lastTs = data.length ? timeSince(data[data.length - 1].timestamp || data[0].timestamp) : '—';
//                                     ^^^^^^^^^^^^^^^^^^^^^^^^ WRONG: Reads OLDEST

// AFTER (FIXED - v26.0)
let sortedData = [...data].sort((a, b) =>
    new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
);
const lastTs = sortedData.length ? timeSince(sortedData[0].timestamp) : '—';
//                                           ^^^^^^^^^^^ CORRECT: Reads NEWEST
```

---

## ✨ NEW FEATURES

### 1. Temporal Decay Engine
Time-based relevance decay for threat scores. Older threats automatically become less prominent.

- **Half-life:** 30 days (configurable)
- **Minimum factor:** 30% (threats never fully disappear)
- **Recent boost:** +10% for threats < 24h old

```python
from agent.v26 import apply_temporal_decay

result = apply_temporal_decay(
    score=9.8,          # Original CVSS score
    timestamp=threat_ts  # When threat was discovered
)
# Returns: {"decayed_score": 7.35, "decay_factor": 0.75, "age_days": 15}
```

### 2. IOC Correlation Engine
Automatically correlates threats based on shared Indicators of Compromise.

- **Multi-type support:** IP, domain, hash, email, CVE, URL
- **Campaign clustering:** Groups related threats
- **Confidence scoring:** Based on IOC quantity and diversity

```python
from agent.v26 import get_ioc_correlation_engine

engine = get_ioc_correlation_engine()
engine.index_report("CDB-APEX-001", iocs)
correlations = engine.find_correlations("CDB-APEX-001")
```

### 3. Enhanced Resilience
- **Circuit breaker pattern:** Automatic failure recovery
- **Graceful degradation:** Continue with partial functionality
- **Retry logic:** Exponential backoff for transient failures

---

## 🔧 IMPROVEMENTS

| Area | v25.0 | v26.0 |
|------|-------|-------|
| Sync interval | 6 hours | 4 hours |
| Deployment action | peaceiris/actions-gh-pages@v3 | JamesIves/github-pages-deploy-action@v4 |
| Pre-flight checks | Basic | Comprehensive |
| Post-sync verification | Minimal | Full |
| Error recovery | None | Circuit breaker + retry |

---

## 📁 FILES CHANGED

### Modified
- `.github/workflows/sentinel-blogger.yml` - Complete rewrite
- `index.html` - Line 2285 timestamp fix
- `VERSION` - Updated to 26.0.0

### Added
- `agent/v26/__init__.py` - v26 module init
- `agent/v26/config_v26.py` - v26 configuration
- `agent/v26/temporal_decay.py` - Temporal decay engine
- `agent/v26/ioc_correlation.py` - IOC correlation engine
- `requirements_v26.txt` - v26 dependencies
- `apply_v26_fix.py` - Automated fix script
- `patches/index_html_v26_fix.patch` - Manual patch

---

## 🚀 UPGRADE INSTRUCTIONS

### Option A: Automated (Recommended)
```bash
# Run the fix script
python apply_v26_fix.py

# Replace workflow
cp .github/workflows/sentinel-blogger.yml.v26 .github/workflows/sentinel-blogger.yml

# Commit and push
git add -A
git commit -m "Upgrade to SENTINEL APEX v26.0"
git push origin main
```

### Option B: Manual
1. Replace `.github/workflows/sentinel-blogger.yml` with v26 version
2. Edit `index.html` line 2285 (apply patch)
3. Copy `agent/v26/` folder to repository
4. Add `requirements_v26.txt`
5. Commit and push

---

## ✅ VERIFICATION

After upgrade, verify:

1. **Workflow succeeds:** Check GitHub Actions
2. **Dashboard updates:** "Last Sync" shows recent time
3. **Fresh data:** New threat reports visible
4. **No errors:** Check Actions logs for clean run

---

## 🔙 ROLLBACK

If issues occur:
```bash
git revert HEAD
git push origin main
```

---

## 📞 SUPPORT

- **Platform:** https://intel.cyberdudebivash.com
- **Issues:** https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/issues
- **Email:** support@cyberdudebivash.com

---

*CYBERDUDEBIVASH® SENTINEL APEX v26.0 "Phoenix"*  
*(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.*
