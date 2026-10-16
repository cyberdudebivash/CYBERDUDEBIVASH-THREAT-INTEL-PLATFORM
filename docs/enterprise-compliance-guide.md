# SENTINEL APEX Enterprise Trust Center & Compliance Experience — Guide (PR-7)

`enterprise-compliance.html` is the Trust Center hub — the third page
in the `enterprise-*` family (`enterprise-homepage.html` PR-5,
`enterprise-pricing.html` PR-6), consuming `css/tokens.css` (PR-2) and
`css/components.css` (PR-4). Same guide structure as the two prior
guides.

**Status:** new, standalone page, now linked from `enterprise-homepage.html`'s
and `enterprise-pricing.html`'s nav and footer ("Trust Center" now
points here instead of the legacy `trust-center.html`).

---

## 0. Read this first: a filename collision this PR caught before it happened

Following this PR's own "verify existing repository" instruction, the
natural filename for this page — matching the established
`enterprise-homepage.html` / `enterprise-pricing.html` convention —
would have been `enterprise-trust-center.html`. That exact filename
**already existed**. It is not a marketing or compliance page at all:
it is a live, **API-key-gated internal operations dashboard** (titled
"ENTERPRISE TRUST CENTER — P29.8") that authenticates against
`/api/health` and then fetches real data from
`/api/v1/p29/observability`, `/api/v1/p29/release-assurance`, and
`/api/v1/p29/customer-value` to render the P25–P29 certification
chain, release go/no-go gates, and platform health — a genuine
P-layer backend tool, squarely inside this repository's "do not
modify Dashboard/Backend/API implementation" protection.

The Write tool's read-before-overwrite safety check blocked the write
before any content was lost, because that file already existed and
had not been read in this session. It was then read in full,
confirmed as unrelated, and left completely untouched. The page in
this PR was renamed to `enterprise-compliance.html` instead — a
name deliberately chosen to share no distinctive leading word with the
existing file, to avoid the same confusion for future readers.

Two automated tests guard this specifically (`tests/test_enterprise_compliance.py`):
`test_does_not_reference_the_unrelated_internal_dashboard` (no link on
the new page may ever target the old file) and
`test_unrelated_internal_dashboard_still_untouched` (fails the build
if `enterprise-trust-center.html` ever stops looking like the P29
dashboard it was before this PR — i.e., if anything ever modifies it).

**Practical lesson applied for the rest of this PR:** every further
candidate filename was checked for existence with a plain shell
command *before* writing, not inferred from the naming convention
alone.

---

## 1. Architecture Guide

### 1.1 Layering

```
css/tokens.css (PR-2) → css/components.css (PR-4, +.sapx-table from this PR) → enterprise-compliance.html (PR-7)
```

`css/hero.css` is not linked (content page, not the hero placement) —
verified by `tests/test_enterprise_compliance.py::test_hero_css_not_used`.

### 1.2 Repository verification performed (per this PR's own instruction)

Before writing any content, the repository was searched for every
item this PR's brief named. Results:

| Searched for | Found | What it contains |
|---|---|---|
| `trust-center.html` | Yes (553 lines) | Compliance cards, DPA highlights, SLA, MSSP architecture |
| Security policy / `SECURITY.md` | Yes (153 lines) | Vulnerability reporting process, response SLA, security controls, rate limits, security headers |
| Privacy policy | Yes — `privacy.html` | |
| Terms | Yes — `terms.html` *and* `eula.html` (two distinct documents) | |
| Responsible disclosure / VDP | Yes — `.well-known/security.txt` and `SECURITY.md` | |
| Incident response | Yes — `docs/SLA.md` §5 and `security-compliance.html` | Severity classification, response-time tables |
| Status page | Yes — `status.html` | |
| AI policy | **No** — `ai-security-ops-hub.html` is an operational SOC dashboard, not a governance document | Marked "Coming Soon" (§1.3) |
| API documentation | Yes — `api/index.html`, `docs/quickstart.html`, `docs/api-auth-guide.md` | |
| Support contacts | Yes — `security@`, `contact@cyberdudebivash.in`, WhatsApp | |
| Legal pages | Yes — `terms.html`, `eula.html`, `privacy.html` | |

Additionally found, not named in the brief but directly relevant:
`security-compliance.html` (compliance dashboard, SOC 2/ISO 27001
progress, NIST CSF mapping), `enterprise-security-pack.html` and
`security-questionnaire-pack.html` (gated procurement resources),
`docs/DPA_TEMPLATE.md` (full GDPR-style DPA).

### 1.3 Why one new hub page, not an edit to any existing one

Six real pages already cover this ground, with no single one
authoritative for everything and some overlap between them (both
`trust-center.html` and `security-compliance.html` independently cover
security architecture and compliance framing, for instance). Per the
precedent already established and approved in PR-5/PR-6 — build a
new, design-system-consistent presentation layer, reuse real facts,
link to the real source rather than duplicate or rewrite it — this PR
adds one unifying hub rather than picking one of the six to edit in
place (an arbitrary choice among six, given none is uniquely
authoritative) or duplicating all six into one new file (real content
duplication, not presentation reuse).

**AI Governance:** not found anywhere in the repository. Per this PR's
explicit instruction ("if it does not exist, create a placeholder
clearly labelled Planned or Coming Soon"), a small, honestly-labeled
"Coming Soon" card is included in the Security Overview section — not
a fabricated policy.

---

## 2. Component Usage Map

Reused: `.sapx-container` / `-narrow`, `.sapx-section` / `-alt` /
`-lg`, `.sapx-grid-2` / `-4`, site header/nav/footer, `.sapx-feature-card`,
`.sapx-badge` (including a new-to-this-page `sapx-badge-neutral`
"Coming Soon" use), `.sapx-cta-banner`, button system.

**New shared component this PR adds:** `.sapx-table` / `.sapx-table-wrap`
in `css/components.css`. PR-6 first solved the "render tabular data"
need as a page-local `.pr6-compare-table` inside
`enterprise-pricing.html`'s own `<style>` block. This page needed the
identical pattern for four different tables (API rate limits, uptime
SLA, incident severity, vulnerability response SLA) — the second
distinct page with the same need — so per Level 4 (Reuse Before
Build) it graduates into the shared library instead of being
copy-pasted a third time. `enterprise-pricing.html`'s already-shipped,
already-tested page-local copy is untouched; there is no defect there
to justify touching it.

Page-scoped addition (this page's own `<style>` block only):
`.pr7-page-intro` (a `max-width` wrapper, trivial). Guarded by
`tests/test_enterprise_compliance.py::test_page_style_does_not_redefine_existing_components`.

---

## 3. Security Content Guide

Every factual claim on this page traces to one of the sources in
§1.2's table. Two editorial decisions are worth stating explicitly:

- **Certification language.** `SOC 2` and `ISO 27001` are described as
  "not yet certified... aligned/in progress," matching the honest
  framing already used by both `trust-center.html` ("SOC 2 Type II
  Readiness... IN PROGRESS", "ISO 27001 Alignment... ROADMAP") and
  `security-compliance.html` ("ISO 27001:2022 IN PROGRESS", "SOC 2
  Type II Progress"). Enforced by
  `test_no_unqualified_certification_claims`.
- **"Sovereign India Certified Design."** This is `trust-center.html`'s
  own exact phrase for its India-operated, no-foreign-dependency
  positioning. This page deliberately does not repeat the word
  "certified" for that claim — no named certifying body evidences an
  actual certification, and introducing that word as new, first-party
  copy on this PR's own page would be asserting a certification this
  PR has no evidence for, distinct from accurately citing that the
  *existing* page uses that phrase. Enforced by
  `test_sovereign_india_paraphrase_avoids_certified_wording`.

### The disclosed, unresolved discrepancy: JWT signing algorithm

`SECURITY.md` states JWT tokens are **HS256**-signed (HMAC, symmetric).
`trust-center.html` states **RS256** (RSA, asymmetric). These are
different, mutually incompatible signing algorithms — a genuine
pre-existing inconsistency between two live pages, discovered while
verifying facts for this PR, not introduced by it. This PR has no
authority to know which is actually correct in the running Cloudflare
Worker, so it does not silently pick one. The Authentication section
on this page describes JWT/API-key behavior (tokens, expiry,
revocation, scoped API keys, brute-force lockout) without asserting
either specific signing algorithm — true under both existing claims.

**This is worth a human reconciling at the source** (whichever of
`SECURITY.md` / `trust-center.html` is stale should be corrected) —
flagged here rather than fixed unilaterally, since correcting it
requires knowing the actual production configuration, which this PR
cannot verify from the repository alone.

---

## 4. Developer Notes

- New page follows the exact `enterprise-*` family conventions
  established in PR-5/PR-6: same header/footer markup, same skip-link
  pattern, same mobile-nav-toggle script, same metadata block shape.
- `.sapx-table` is now available to any future page needing tabular
  data — see `css/components.css`'s own comment block for usage.
- Every dollar/percentage/time figure on this page was cross-checked
  by hand against its source file during development (`SECURITY.md`,
  `docs/SLA.md`, `security-compliance.html`) — there is no automated
  byte-for-byte consistency test against those files the way PR-6 has
  for pricing, because none of the source files here are itself a
  single well-formed number system PR-6's regex approach could target
  cleanly (the pricing figures were all `$`-prefixed; these are mixed
  percentages, time durations, and named tiers). This is a manual,
  not automated, consistency guarantee — flagged in §6.

---

## 5. Accessibility Report

Verified in real headless Chromium via Playwright
(`render-test/verify_enterprise_compliance.js`) plus static analysis
(`tests/test_enterprise_compliance.py`):

| Check | Method | Result |
|---|---|---|
| Exactly one `<h1>`, no skipped heading levels | Static + real rendered DOM | PASS |
| Skip link is the first keyboard Tab stop | Real keyboard event | PASS |
| No duplicate `id` attributes | Static | PASS |
| Required landmarks present | Static | PASS |
| All 4 real data tables render with actual rows, each wrapped for horizontal-scroll safety | Real computed DOM | PASS |
| No horizontal overflow at 375px / 768px / 1440px | Real Chromium | PASS (no new component fixes needed — PR-5's box-sizing fix already covers `.sapx-table`) |
| `prefers-reduced-motion` collapses the status-dot pulse | Real `emulateMedia` | PASS |
| No console/page errors on load | Real Chromium | PASS |
| Final CTA button contrast >= 4.5:1, both themes | Real computed style | PASS (11.80:1, same already-fixed token as PR-5/6) |

---

## 6. Known Limitations

- **`.md` files render as raw source on this site, not formatted
  documents.** This repository has a root `.nojekyll` file, so GitHub
  Pages serves every file as-is with no Markdown-to-HTML conversion.
  Found during a post-build stability audit: the Privacy section's
  link to `docs/DPA_TEMPLATE.md` would otherwise open to unrendered
  plain text (literal `#`/`**` markers) despite being a real, accurate
  link. Fixed by labeling it "(plain text)" so the expectation is set
  correctly rather than implying a polished document view. The same
  convention does not apply to `.well-known/security.txt`, which is
  plain text by standard (RFC 9116) and expected to read that way.

- **No automated cross-file consistency test for every figure** (unlike
  PR-6's pricing-figure guard). The figures here span multiple source
  documents in different formats (Markdown tables, HTML compliance
  cards) rather than one consistent `$`-prefixed number system, so an
  automated regex-based consistency check was judged lower-value
  relative to its complexity for this PR. Figures were manually
  cross-checked once during development; if any source document's
  numbers change, this page must be updated by hand.
- **JWT signing-algorithm discrepancy is disclosed, not resolved** —
  see §3. A human with access to the actual production Worker
  configuration should reconcile `SECURITY.md` and `trust-center.html`.
- **AI Governance is a placeholder** ("Coming Soon") — no real policy
  exists in this repository to cite.
- **Not yet linked from `index.html`, `trust-center.html`, or
  `security-compliance.html` themselves** — only from
  `enterprise-homepage.html` and `enterprise-pricing.html`. Those
  three legacy pages, and whether/how to cross-link them to this new
  hub, are left for a future decision.
- **No automated pixel-diff visual regression harness** — same
  disclosed limitation as PR-5/PR-6, same reasoning.
- **Playwright is not a project dependency** — same as PR-5/PR-6.

---

## 7. Deployment Guide

Same mechanism as PR-5/PR-6: this repo serves `intel.cyberdudebivash.com`
via GitHub Pages (`CNAME` file at root); merging to `main` is the
deploy step. No database migration, environment variable, Cloudflare
Worker change, or CI/CD workflow change is required.

---

## 8. Rollback Guide

1. `git revert` this PR's commit, or delete
   `enterprise-compliance.html`, `tests/test_enterprise_compliance.py`,
   `render-test/verify_enterprise_compliance.js`, and this guide;
   revert the `.sapx-table` addition in `css/components.css`; revert
   the 3 href changes across `enterprise-homepage.html` and
   `enterprise-pricing.html`.
2. `enterprise-trust-center.html` (the unrelated internal dashboard)
   was never touched, so there is nothing to roll back there.
3. No other page references `enterprise-compliance.html` yet except
   the two `enterprise-*` pages' nav/footer, so reverting carries zero
   risk to any other page.

---

## 9. Regression checklist (for this PR)

- [x] `enterprise-compliance.html` added; zero existing page's rendered
      output changed except 3 href values across `enterprise-homepage.html`
      and `enterprise-pricing.html`.
- [x] `enterprise-trust-center.html` (the unrelated P29 dashboard),
      `trust-center.html`, `SECURITY.md`, `security-compliance.html`,
      `docs/SLA.md`, `docs/DPA_TEMPLATE.md`, `privacy.html`,
      `terms.html`, `eula.html`, `status.html` — all untouched, all
      guarded by tests where the collision risk was real.
- [x] Zero hardcoded colors/spacing/typography in the page's own
      `<style>` block, outside `var(--sapx-*)`.
- [x] Zero classes referenced that aren't defined anywhere.
- [x] Zero component selectors redefined in the page's own `<style>`
      block.
- [x] `.sapx-table` added to `css/components.css` additively; existing
      `test_components_css.py` suite re-run and passing (no duplicate
      selectors, no hardcoded values).
- [x] No unqualified SOC 2 / ISO 27001 certification claims; no fresh
      "certified" wording for the Sovereign India positioning claim.
- [x] Exactly one `<h1>`, no skipped heading levels, no duplicate
      `id`s, all required landmarks present.
- [x] Every internal link resolves to a real file in the repository.
- [x] No horizontal overflow at 375px / 768px / 1440px; all 4 data
      tables render with real rows and horizontal-scroll safety.
- [x] Full existing regression suite (`test_components_css.py`,
      `test_patch_landing_hero.py`, `test_patch_homepage_metadata.py`,
      `test_enterprise_homepage.py`, `test_enterprise_pricing.py`)
      re-run after every change — 102/102 passing, 0 regressions.
