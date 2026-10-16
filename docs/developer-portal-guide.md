# SENTINEL APEX Developer Portal & API Experience — Guide (PR-8)

`developer-portal.html` is the technical entry point for developers —
the fourth page in the `enterprise-*`/portal family
(`enterprise-homepage.html` PR-5, `enterprise-pricing.html` PR-6,
`enterprise-compliance.html` PR-7), consuming `css/tokens.css` (PR-2)
and `css/components.css` (PR-4) only. Same guide structure as the
three prior guides, with one addition specific to this PR: a full,
line-cited **Evidence Matrix** (§3) for every documentation
inconsistency disclosed on the page itself.

**Status:** new, standalone page, now linked from
`enterprise-homepage.html`'s, `enterprise-pricing.html`'s, and
`enterprise-compliance.html`'s nav ("Developers") in place of the
previous generic `/api/` link.

---

## 0. Repository discovery performed before writing any content

Per this PR's own "mandatory first step" instruction, the repository
was searched for existing developer-facing material before a single
line of new content was written. Everything found is reused by
reference below; nothing was rewritten or re-hosted.

| Searched for | Found | Notes |
|---|---|---|
| OpenAPI / Swagger spec | Yes — `apex_openapi_v3.yaml` (1073 lines, OpenAPI 3.1) | Full schema, `/auth/login`, `/api/feed`, `/api/intel/{id}` and more |
| API reference page | Yes — `api-docs.html` (577 lines, tagged "v185.0") | Quick start, auth, rate limits, errors, per-endpoint docs, SIEM guides |
| Quick-start guide | Yes — `docs/quickstart.html` | curl/Python/JS examples |
| Auth guide | Yes — `docs/api-auth-guide.md` | curl/Python/Go examples, key format, support contact |
| Python SDK | Yes — **two independent packages** | `scripts/sentinel_apex_sdk.py` (single file, `__version__ = "1.0.0"`) and `sdk/sentinel_sdk/` (multi-module package; see §3 for its own internal version split) |
| Onboarding / key-provisioning pages | Yes — `onboarding.html`, `get-api-key.html` | Real, substantial pages, linked not duplicated |
| Deployed backend source | Yes — `workers/intel-gateway/src/index.js` (4300+ lines) | Read for reference only, never modified. 239 distinct `/api/*` route strings — the single most authoritative "what's actually live" evidence available |
| FAQ | Yes — `docs/faq.html` | Reused a distinct set of Q&As from the ones PR-7 already used |
| Compliance FAQ / trust content | Reused, not re-read in depth | Already verified in PR-7; `enterprise-compliance.html` linked, not duplicated |

**Why one new hub page, not an edit to any existing one:** the same
reasoning as PR-6/PR-7 — several real pages already exist
(`api-docs.html`, `docs/quickstart.html`, `onboarding.html`), none of
which is a single unifying "start here" developer entry point, and
none of which is edited by this PR. This page composes and links to
all of them; it re-documents none of their full depth.

---

## 1. Architecture Guide

### 1.1 Layering

```
css/tokens.css (PR-2) → css/components.css (PR-4) → developer-portal.html (PR-8)
```

`css/hero.css` is not linked (content/reference page, not the landing
hero) — verified by
`tests/test_developer_portal.py::test_hero_css_not_used`.

### 1.2 Developer journey (12 sections, in page order)

```
Hero (value prop + 3 CTAs)
   -> Quick Start (5-step Understand/Authenticate/Explore/Test/Integrate)
   -> Authentication (both disclosed conventions, side by side)
   -> API Overview (8 verified capability cards + Coming Soon note)
   -> Developer Workflow (6-step diagram, PR-5/PR-6 numbered-badge pattern)
   -> Example Requests (real curl for both auth conventions + real JSON)
   -> Integration Guides (Python/JS/cURL/Go real; Postman/Terraform/SOAR Coming Soon)
   -> Rate Limits (real api-docs.html table, cross-file caveat)
   -> Error Handling (real api-docs.html table)
   -> Documentation Index (8 links to real, existing docs)
   -> Developer FAQ (4 Q&As reused from docs/faq.html)
   -> Documentation Consistency Notice (the drift disclosure, id="drift-notice")
   -> Support (real, verified channels)
```

### 1.3 Page-scoped CSS additions (this page's own `<style>` block only)

`.pr8-page-intro`, `.pr8-hero-ctas` (a plain flex CTA row — no
existing shared component covers "hero CTA row with wrap + gap" for a
page that does not load `css/hero.css`, so this is page-scoped rather
than reusing `css/hero.css`'s `.sapx-hero-ctas`, which is intentionally
not loaded here per §1.1), `.pr8-workflow-step` /
`.pr8-workflow-step-num` (the numbered-badge-plus-connector-arrow
pattern PR-5/PR-6 each used, this page's own copy), `.pr8-code-label` /
`.pr8-code-block` (an accessible, keyboard-focusable code sample
block), `.pr8-drift-note` (a left-border callout for the two disclosed
auth-convention cards). All values resolve through `var(--sapx-*)`.
Guarded by
`tests/test_developer_portal.py::test_page_style_does_not_redefine_existing_components`.

No new shared component was added to `css/components.css` in this PR
— `.sapx-table` / `.sapx-table-wrap` (added in PR-7) is reused
unchanged for the Rate Limits and Error Handling tables.

---

## 2. Component Usage Map

Reused: `.sapx-container` / `-narrow` / `-wide`, `.sapx-section` /
`-alt` / `-lg`, `.sapx-grid-4` / `-5` / `-6`, site header/nav/footer
(identical markup and mobile-toggle script to PR-5/6/7),
`.sapx-feature-card`, `.sapx-card` / `-title` / `-desc`, `.sapx-badge`
(`-success` for "Observed", `-neutral` for "Coming Soon" and
field-level nuance), `.sapx-table` / `-table-wrap` (PR-7), `.sapx-cta-banner`
/ `-heading` / `-copy` / `-actions`, `.sapx-announcement-bar` (reused
for the drift-notice pointer banner), button system
(`sapx-btn-primary` / `-secondary` / `-ghost`).

Zero existing component selectors redefined in this page's own
`<style>` block — guarded by
`test_page_style_does_not_redefine_existing_components`.

---

## 3. Evidence Matrix — every disclosed inconsistency, with exact citations

This is the centerpiece deliverable of this PR, per its explicit
"Special Validation" instruction: conflicting endpoint documentation,
conflicting authentication documentation, and repository drift must be
**reported, not silently resolved**. Every row below is a direct
citation — file path and line number — verified by re-reading each
source file during this PR, not carried over from memory.

### 3.1 Authentication header convention

| Source | File : Line | Convention |
|---|---|---|
| Quick start | `docs/quickstart.html:95` | `Authorization: Bearer YOUR_KEY` |
| Auth guide | `docs/api-auth-guide.md:34` | `Authorization: Bearer sa_YOUR_API_KEY_HERE` |
| FAQ | `docs/faq.html:105` | `Authorization: Bearer SA-PRO-ABC123` |
| API reference | `api-docs.html:143` | `Authentication via X-API-Key header is required for all endpoints` |
| API reference errors table | `api-docs.html:292` | `401 ... Check X-API-Key header` |

**Disclosed on page as:** Convention A (Bearer) vs. Convention B
(X-API-Key) — §3 "Authentication" section, both shown, neither chosen.

### 3.2 API key format

| Source | File : Line | Format |
|---|---|---|
| Auth guide | `docs/api-auth-guide.md:34` | `sa_<key>` |
| Python SDK (package) | `sdk/sentinel_sdk/client.py:65` | `sa_live_xxxx` (docstring example) |
| Quick start | `docs/quickstart.html` (curl examples reference `SA-PRO-` style keys per FAQ, below) | `SA-PRO-<hex>` |
| FAQ | `docs/faq.html:105` | `SA-PRO-ABC123` |
| Security policy | `SECURITY.md:57` | `cdb_pro_<40 hex>` or `cdb_ent_<40 hex>` |

**Disclosed on page as:** three distinct formats across four files —
§3 "Authentication" section and §drift-notice table, row "API key
format."

### 3.3 JWT signing algorithm

| Source | File : Line | Claim |
|---|---|---|
| Security policy | `SECURITY.md:50` | `JWT HS256 — all access tokens are HMAC-SHA256 signed` |
| Trust Center (existing page, PR-7 evidence, reused here) | `trust-center.html:287` | `RS256 JWT tokens with configurable expiry` |

Two internal planning documents
(`SENTINEL_APEX_ENTERPRISE_TRANSFORMATION_BLUEPRINT_v153.md`,
not a developer-facing doc) separately propose an HS256-to-RS256
migration as future work — that document describes a *plan*, not a
second live claim, and is out of scope for this customer-facing
Evidence Matrix, which is limited to developer/customer-facing
documentation and source code. It is noted here only for completeness,
not as a tenth disclosed conflict.

**Disclosed on page as:** "JWT signing algorithm: HS256 (SECURITY.md)
vs. RS256 (trust-center.html)" — §drift-notice table. Neither is
asserted as correct.

### 3.4 JWT lifetime

| Source | File : Line | Claim |
|---|---|---|
| Security policy | `SECURITY.md` (same JWT statement, `:50`) + `API_PROVISIONING_CERTIFICATION.md:31` | 24-hour expiry |
| OpenAPI spec | `apex_openapi_v3.yaml:76`, `:106` | `JWT obtained from POST /auth/login. 30-day lifetime.` |

**Disclosed on page as:** "JWT lifetime: 24 hours (SECURITY.md) vs. 30
days (apex_openapi_v3.yaml)" — §drift-notice table.

### 3.5 Rate limits

| Source | File : Line | Free | Pro | Enterprise | MSSP |
|---|---|---|---|---|---|
| API reference (canonical technical table) | `api-docs.html:282-285` | 100/day, 10/min | 5,000/day, 100/min | Unlimited/day, 500/min | Unlimited/day, 1,000/min |
| API reference marketing copy (same file, different section) | `api-docs.html:529` | 100/day | 5,000/day | **10,000/day** (contradicts its own table above) | unlimited tenant provisioning |

The page's Rate Limits section (developer-portal.html) reproduces the
canonical technical table (`api-docs.html:282-285`) verbatim, since it
is the single most complete structured reference found. The same
file's own marketing paragraph at line 529 states a different
Enterprise figure — an intra-file inconsistency, not introduced by
this PR, additionally noted here for full transparency though not
separately called out on the page itself (the page already states
"SECURITY.md, docs/api-auth-guide.md, and apex_openapi_v3.yaml each
document different per-minute figures for the same tiers," which
remains accurate).

### 3.6 Base API domain

| Source | File : Line | Domain |
|---|---|---|
| Majority of pages / OpenAPI servers block | `apex_openapi_v3.yaml:40` | `https://intel.cyberdudebivash.com` |
| Auth guide | `docs/api-auth-guide.md:5` | `https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM` |
| `scripts/sentinel_apex_sdk.py` | `scripts/sentinel_apex_sdk.py:59,65` | `https://cyberdudebivash.github.io` |
| `sdk/sentinel_sdk/client.py` | `sdk/sentinel_sdk/client.py:48` | `https://api.sentinelapex.cyberdudebivash.com` |

**Disclosed on page as:** "Base API domain: intel.cyberdudebivash.com
(majority), cyberdudebivash.github.io/… (docs/api-auth-guide.md, SDK
script), api.sentinelapex.cyberdudebivash.com (sdk/sentinel_sdk
package)" — §drift-notice table.

### 3.7 Support email

| Source | File : Line | Address |
|---|---|---|
| Security policy | `SECURITY.md:5,24` | `security@cyberdudebivash.com` |
| Enterprise pages (PR-5/6/7 established) | — | `contact@cyberdudebivash.in` |
| OpenAPI contact block | `apex_openapi_v3.yaml:33` | `bivash@cyberdudebivash.com` |
| Auth guide | `docs/api-auth-guide.md:43,82` | `bivashnayak.ai007@gmail.com` |
| SDK packaging metadata | `sdk/setup.py:21` | `api@cyberdudebivash.com` |

**Disclosed on page as:** five distinct addresses across five sources
— §drift-notice table, row "Support email."

### 3.8 Python SDK

| Package | File | Stated version | Where |
|---|---|---|---|
| `scripts/sentinel_apex_sdk.py` | single file | `1.0.0` | `scripts/sentinel_apex_sdk.py:52` (`__version__`) |
| `sdk/sentinel_sdk/` | multi-module package | `134.0` (module docstring) vs. `100.0.0` (`__version__` constant, matches `sdk/setup.py:19`) | `sdk/sentinel_sdk/__init__.py:2` vs. `:56`; `sdk/sentinel_sdk/client.py:2` (same docstring claim) |

The second package has an internal split between its own docstring
("v134.0") and its own `__version__`/`setup.py` value ("100.0.0") —
this PR's page cites the docstring figure specifically ("v134.0 per
its own docstring," HTML comment, and "v134.0" in the Integration
Guides card), not as the package's unqualified version, precisely
because the two disagree even within one package.

**Disclosed on page as:** "Two independent, non-identical
implementations" — §7 "Integration Guides" and §drift-notice table.

### 3.9 Endpoint paths

| Source | File : Line | Route named |
|---|---|---|
| Deployed worker (most authoritative — actual live routing) | `workers/intel-gateway/src/index.js:3626` | `/api/feed` (and `/api/feed.json`) |
| Deployed worker | `workers/intel-gateway/src/index.js:4197,4276` | `/api/cves` |
| Deployed worker | `workers/intel-gateway/src/index.js:4200` | `/api/intel/correlate` (not a bare collection route) |
| OpenAPI spec | `apex_openapi_v3.yaml:615` | `/api/feed` (matches deployed worker) |
| OpenAPI spec | `apex_openapi_v3.yaml:684` | `/api/intel/{id}` (single-resource, not a filterable collection) |
| Quick start (flagship example) | `docs/quickstart.html:96,108,124,206` | `GET /api/intel?severity=critical&limit=5` — **a bare, filterable `/api/intel` collection route that does not appear anywhere in the deployed worker source** |
| API reference | `api-docs.html:299-301` | `GET /api/feed` (matches deployed worker) |

This is the single most concrete finding in this Evidence Matrix:
`docs/quickstart.html`'s primary, repeated example endpoint
(`/api/intel?severity=...`) has no matching route in the actual
deployed Cloudflare Worker. The Example Requests section on this page
reuses the quickstart example verbatim (labeled as such) rather than
silently substituting a "corrected" endpoint, per this PR's explicit
instruction not to choose a side — but this specific gap is flagged
here in the strongest terms of any finding in this matrix, since a
developer copy-pasting the quickstart example as-is may receive a 404
against the live backend.

**Disclosed on page as:** "Endpoint paths: apex_openapi_v3.yaml,
docs/quickstart.html, api-docs.html, and the actual deployed worker
source each name similar resources differently (e.g. /api/intel vs
/api/feed vs /api/cves)" — §drift-notice table, and repeated as a
caveat directly under the Example Requests code blocks.

---

## 4. Developer Notes

- New page follows the exact site-wide header/nav/footer conventions
  established in PR-5/6/7: same skip-link pattern, same mobile-nav-toggle
  script, same metadata block shape.
- The "API Overview" section deliberately separates **customer-facing**
  capabilities (feed, IOC search, STIX/TAXII, detections, SIEM,
  search/NLQ, analytics) from the **internal P16–P38 observability/
  certification routes** that also exist in
  `workers/intel-gateway/src/index.js` — the latter are real, but are
  platform-internal infrastructure, not part of the customer developer
  surface, and are intentionally excluded from this portal.
- GraphQL and a general-purpose webhook-push API are explicitly labeled
  "Coming Soon" because no evidence of either exists anywhere in the
  repository; the two real webhook routes found
  (`/api/webhooks/gumroad`, `/api/webhooks/razorpay`) are payment-processor
  callbacks, not a threat-intel push mechanism, and are named as such
  rather than counted toward the GraphQL/webhook claim.
- Postman Collection, Terraform, and SOAR integrations are each labeled
  "Coming Soon" for the same reason — not found anywhere in this
  repository. An Azure ARM template exists for detection content
  (`api/detections/apex-sentinel-arm-template.json`) but is not a
  Terraform provider, and is named precisely as an ARM template, not
  miscounted as Terraform support.

---

## 5. Accessibility Report

Verified in real headless Chromium via Playwright
(`render-test/verify_developer_portal.js`) plus static analysis
(`tests/test_developer_portal.py`):

| Check | Method | Result |
|---|---|---|
| Exactly one `<h1>`, no skipped heading levels | Static + real rendered DOM | PASS |
| Skip link is the first keyboard Tab stop | Real keyboard event | PASS |
| No duplicate `id` attributes | Static | PASS |
| Required landmarks present | Static | PASS |
| All code blocks (`.pr8-code-block`) are keyboard-focusable (`tabindex="0"`) and scrollable via keyboard | Static + real keyboard event | PASS |
| Both real data tables (Rate Limits, Error Handling) render with actual rows, wrapped for horizontal-scroll safety | Real computed DOM | PASS |
| No horizontal overflow at 375px / 768px / 1440px | Real Chromium | PASS (box-sizing fix from PR-5 already covers this page) |
| No console/page errors on load | Real Chromium | PASS |
| Every internal link resolves to a real file in the repository | Static, filesystem-checked | PASS |
| Both JWT algorithms (HS256, RS256) present — no silent pick | Static | PASS |
| Every unevidenced integration labeled "Coming Soon" within visual proximity | Static | PASS |

---

## 6. Known Limitations

- **This Evidence Matrix is scoped to developer/customer-facing
  documentation and source code** — internal strategy, blueprint, and
  playbook documents (e.g.
  `SENTINEL_APEX_ENTERPRISE_TRANSFORMATION_BLUEPRINT_v153.md`,
  `REVENUE_OPERATIONS_PLAYBOOK.md`, versioned `CHANGELOG_v*.md` files)
  were not incorporated as disclosed conflicts, since they describe
  internal planning and roadmap state, not live developer-facing
  claims. A human with access to which of these documents (if any)
  reflects current production reality should reconcile them; this PR
  cannot determine that from the repository alone.
- **None of the nine disclosed inconsistencies in §3 is resolved** —
  by design, per this PR's explicit "document the inconsistency, do
  not choose a side" instruction. A human with access to the actual
  running Cloudflare Worker configuration and its environment
  variables is required to determine which claim is currently correct
  in each case.
- **The Example Requests section may not work as literally shown**
  against the live API, specifically the `docs/quickstart.html`-sourced
  `/api/intel?severity=critical` example — see §3.9. This is disclosed
  directly beneath the code block on the page itself, not just in this
  guide.
- **No automated cross-file consistency test asserts the Evidence
  Matrix's file:line citations stay accurate over time** — if any
  cited source file changes, this table (and the corresponding page
  content) should be re-verified by hand. `tests/test_developer_portal.py`
  guards that the *page* discloses both sides of the JWT algorithm
  conflict and covers all nine major drift topics, but does not
  byte-for-byte diff against the cited source files.
- **`.md` files render as raw source on this site** (root `.nojekyll`,
  same finding as PR-7) — the Documentation Index and Auth Guide links
  to `docs/api-auth-guide.md` and this file itself
  (`docs/developer-portal-guide.md`) will render as unformatted plain
  text in a browser. Not specially labeled "(plain text)" on this page
  the way PR-7 labeled its DPA link, since this page's Documentation
  Index already lists several `.md` links side by side with the same
  implicit expectation; flagged here for awareness.
- **No automated pixel-diff visual regression harness** — same
  disclosed limitation as PR-5/6/7.
- **Playwright is not a project dependency** — same as PR-5/6/7;
  requires the globally-installed Chromium and the
  `PLAYWRIGHT_BROWSERS_PATH` / `NODE_PATH` environment variables
  documented in those PRs' guides.

---

## 7. Deployment Guide

Same mechanism as PR-5/6/7: this repo serves
`intel.cyberdudebivash.com` via GitHub Pages (`CNAME` file at root);
merging to `main` is the deploy step. No database migration,
environment variable, Cloudflare Worker change, or CI/CD workflow
change is required — `workers/intel-gateway/src/index.js` was read for
reference only and is untouched.

---

## 8. Rollback Guide

1. `git revert` this PR's commit, or delete `developer-portal.html`,
   `tests/test_developer_portal.py`,
   `render-test/verify_developer_portal.js`, and this guide.
2. Revert the nav/footer "Developers" link change (6 edits total: 2
   occurrences each across `enterprise-homepage.html`,
   `enterprise-pricing.html`, `enterprise-compliance.html`) back to the
   prior `/api/` link.
3. No existing page's own content, styling, or behavior was modified —
   `css/components.css` and `css/hero.css` are both untouched by this
   PR (PR-7's `.sapx-table` addition is reused, not altered).
4. `apex_openapi_v3.yaml`, `api-docs.html`, `docs/quickstart.html`,
   `docs/api-auth-guide.md`, `docs/faq.html`, `SECURITY.md`,
   `trust-center.html`, both SDK packages, and
   `workers/intel-gateway/src/index.js` were all read-only references
   — none was modified, so none needs rollback.

---

## 9. Regression checklist (for this PR)

- [x] `developer-portal.html` added; zero existing page's rendered
      output changed except the nav/footer "Developers" link (6 href
      + label changes across 3 existing pages).
- [x] Zero hardcoded colors/spacing/typography in the page's own
      `<style>` block, outside `var(--sapx-*)`.
- [x] Zero classes referenced that aren't defined anywhere.
- [x] Zero component selectors redefined in the page's own `<style>`
      block.
- [x] `css/components.css` and `css/hero.css` untouched by this PR.
- [x] Both JWT signing algorithms (HS256, RS256) disclosed; neither
      silently chosen.
- [x] Every one of the 9 major drift topics (auth header, key format,
      JWT algorithm, JWT lifetime, rate limits, base domain, support
      email, Python SDK, endpoint paths) covered in the drift notice.
- [x] Postman Collection, Terraform, and SOAR each labeled "Coming
      Soon" in close visual proximity to the claim.
- [x] GraphQL not claimed as shipped.
- [x] Exactly one `<h1>`, no skipped heading levels, no duplicate
      `id`s, all required landmarks present.
- [x] Every internal link resolves to a real file in the repository.
- [x] All code blocks keyboard-focusable (`tabindex="0"`).
- [x] No horizontal overflow at 375px / 768px / 1440px.
- [x] Full existing regression suite (`test_components_css.py`,
      `test_patch_landing_hero.py`, `test_patch_homepage_metadata.py`,
      `test_enterprise_homepage.py`, `test_enterprise_pricing.py`,
      `test_enterprise_compliance.py`) re-run after every change —
      0 regressions.
