# CYBERDUDEBIVASH Sentinel APEX — v24.0 ULTRA Changelog

**Release Date:** 2026-02-27  
**Security Classification:** Production Release  
**Upgrade Priority:** CRITICAL (security fixes included)

---

## 🔴 Critical Security Fixes

### [CVE-CDB-2024-001] XSS via Inline onclick + JSON.stringify
**Severity:** HIGH | **CVSS:** 7.4 (Stored XSS vector)  
**Fixed:** 4 injection points patched

- `renderCards()` card title onclick → replaced with `data-stix-id` attribute
- `renderCards()` DETAILS button onclick → replaced with `data-stix-id` attribute
- MITRE heatmap trend bar onclick → replaced with `data-stix-id` attribute
- Modal "Copy JSON" button → `copyCurrentModalJson()` with `_activeModalItem` ref

**Architecture:** Threat Registry pattern (`Map<stix_id, ThreatObject>`) + event delegation
eliminates all `innerHTML`-adjacent `JSON.stringify` injection vectors.

### [CVE-CDB-2024-002] Session-Scoped Watchlist Data Loss
**Severity:** MEDIUM | Data persistence failure  
**Fixed:** `sessionStorage` → `localStorage` for `cdb_watchlist`

Watchlist now persists across browser restarts, tab closes, and session resets.

---

## 🟢 New Features

### Progressive Web App (PWA) Support
- `manifest.json` — Full W3C Web App Manifest v2 compliant
- `service-worker.js` — Versioned cache strategies:
  - `Cache-First` for static assets (CSS, JS, fonts)
  - `Network-First` for intel feeds with 5-minute TTL fallback
  - Offline fallback page with retry mechanism
- 8 icon sizes generated: 72×72 → 512×512
- App shortcuts: Live Feed, Watchlist
- Installable on Android, iOS, Windows, macOS, Linux

### Enhanced SEO & Structured Data
- Canonical URL `<link rel="canonical">`
- JSON-LD `WebApplication` + `Organization` schemas (Google Rich Results eligible)
- `twitter:site` + `twitter:creator` (@cyberbivash)
- Removed duplicate `og:type` meta tag
- `theme-color` meta for browser chrome branding

### Content Security Policy
```
default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; 
connect-src 'self' https://api.cyberdudebivash.com https://api.first.org https://cve.circl.lu;
img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; 
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net
```

---

## 📦 File Manifest

| File | Status | Notes |
|------|--------|-------|
| `index.html` | Modified | XSS fixes, meta improvements, SW registration |
| `manifest.json` | New | PWA Web App Manifest |
| `service-worker.js` | New | Offline-capable cache engine |
| `assets/icons/icon-*.png` | New | 8 PWA icon sizes (72–512px) |

---

## 🔧 Migration Notes

No breaking changes. Drop-in upgrade. No configuration changes required.

For self-hosted deployments serving the SW from a subdirectory:
Update `scope` in SW registration and `start_url` in manifest.json accordingly.

---

## ✅ Validation

All 22 automated deployment checks passed. See `DEPLOYMENT_VALIDATION_v24.log`.
