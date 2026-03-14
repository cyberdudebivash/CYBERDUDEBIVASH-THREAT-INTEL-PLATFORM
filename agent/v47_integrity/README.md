# CYBERDUDEBIVASH® SENTINEL APEX v47.0 — INTEGRITY GUARD

## Deployment Instructions (Zero-Regression)

### What This Fixes

| ID | Type | Description |
|-----|------|-------------|
| SEC-01 | SECURITY | Removes hardcoded JWT secret from config.py |
| BUG-04 | BUG FIX | EPSS/CVSS batch enrichment with local cache (fixes null scores) |
| BUG-03 | DETECTION | Manifest integrity validator catches cross-contamination |
| GAP-07 | FEATURE | Dashboard staleness detector with automated alerts |
| DEDUP-L4 | FEATURE | Content fingerprint deduplication (SimHash-based) |

### Deployment Steps

```bash
# 1. Copy v47 module into the repository
cp -r v47_integrity/ agent/v47_integrity/

# 2. Apply SEC-01 security patch (removes hardcoded JWT)
python agent/v47_integrity/config_security_patch.py

# 3. Add INTEGRITY GUARD stage to GitHub Actions workflow
# Follow instructions in WORKFLOW_PATCH.yml
# Insert the stage block AFTER "Force Update Sync Timestamp"

# 4. Verify no existing tests break
python -m pytest tests/ -v --tb=short

# 5. Commit and push
git add agent/v47_integrity/
git add agent/config.py  # SEC-01 patch
git commit -m "v47.0 INTEGRITY GUARD: SEC-01 fix + EPSS batch + content dedup + staleness detector"
git push origin main
```

### Integration with sentinel_blogger.py (Optional)

To enable content fingerprint dedup (Layer 4) in the main pipeline,
add this import to sentinel_blogger.py at the top (non-breaking):

```python
# v47.0 INTEGRITY GUARD: Content fingerprint dedup Layer 4
try:
    from agent.v47_integrity.integrity_guard import integrity_guard as _integrity
    _INTEGRITY_OK = True
except ImportError:
    _integrity = None
    _INTEGRITY_OK = False
```

And add this check in process_entry() before STEP 8:

```python
# v47.0: Content fingerprint dedup check (Layer 4)
if _INTEGRITY_OK and _integrity:
    try:
        if _integrity.content_dedup.is_duplicate_content(
            enriched_content, headline
        ):
            logger.info(f"  ⏭ SKIP (content fingerprint): {headline[:60]}")
            dedup_engine.mark_processed(headline, entry.get('link', ''))
            return False
        _integrity.content_dedup.register_content(enriched_content, headline)
    except Exception as _ig_e:
        logger.debug(f"Content dedup skipped (non-critical): {_ig_e}")
```

### Architecture

```
agent/v47_integrity/
├── __init__.py
├── integrity_guard.py      # Main orchestrator + all engines
├── config_security_patch.py # SEC-01 one-time fix script
├── WORKFLOW_PATCH.yml       # GitHub Actions integration instructions
└── README.md               # This file
```

### Zero-Regression Guarantees

- ✅ All code in isolated agent/v47_integrity/ directory
- ✅ All imports wrapped in try/except with graceful fallback
- ✅ GitHub Actions stage uses continue-on-error: true
- ✅ No modification of existing versioned modules (v26-v46)
- ✅ No modification of sentinel_blogger.py (optional integration)
- ✅ Config patch only changes the JWT secret default (single line)
- ✅ All data written to data/enrichment/ (no STIX directory conflicts)
