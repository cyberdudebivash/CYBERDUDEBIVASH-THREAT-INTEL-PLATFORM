# SENTINEL APEX Enterprise Pricing, API Platform & Onboarding — Guide (PR-6)

`enterprise-pricing.html` is the commercial-conversion counterpart to
`enterprise-homepage.html` (PR-5): a new page consuming
`css/tokens.css` (PR-2) and `css/components.css` (PR-4), presenting
real, live pricing and a customer-journey map. Same guide structure as
`docs/enterprise-homepage-guide.md` (PR-5) and `docs/component-system-guide.md`
(PR-4).

**Status:** new, standalone page, now linked from `enterprise-homepage.html`'s
nav and footer ("Pricing" now points here instead of the legacy
`pricing.html`). Not yet linked from `index.html` or `pricing.html`
themselves — those stay untouched, see §1.2.

---

## 1. Architecture Guide

### 1.1 Layering

```
css/tokens.css (PR-2) → css/components.css (PR-4) → enterprise-pricing.html (PR-6)
```

`css/hero.css` (PR-3) is deliberately **not** linked — it is documented
as scoped to the landing-page hero placement specifically, and this is
a content/conversion page, not a second hero. Verified by
`tests/test_enterprise_pricing.py::test_hero_css_not_used`.

### 1.2 Why real pricing, not placeholders — and why a new page, not a rewrite

The task brief's own instruction ("do not invent pricing... use
placeholders such as TBD... whenever repository evidence is
unavailable") is explicitly conditional. Investigating before writing
any code found that evidence is *not* unavailable: `pricing.html` (616
lines) and `upgrade.html` (1,533 lines) already ship real, live,
specific pricing —

| Tier | Monthly | Annual | API limit |
|---|---|---|---|
| Community | $0 | $0 | 100 calls/day |
| PRO | $49 | $39/mo ($470/yr) | 5,000 calls/day |
| Enterprise | $499 | $399/mo ($4,788/yr) | 50,000 calls/day |
| MSSP | $1,999 | $1,599/mo ($19,188/yr) | Unlimited clients |

— with a live, working Razorpay + Gumroad checkout, automated GST
invoicing, and instant API-key provisioning already in `upgrade.html`.
Per the task's own conditional logic, real evidence beats a weaker
placeholder, so every figure on `enterprise-pricing.html` is the real
number, cross-checked against those two files by
`tests/test_enterprise_pricing.py`'s pricing-consistency tests (§4).

This raised the same fork PR-5 resolved for `enterprise.html`: rebuild
the existing pricing/checkout pages in place, or build new alongside
them? Applying the same, now-established precedent — new page, real
data reused, existing functional pages left untouched — avoids
duplicating live payment logic (`Razorpay`/`Gumroad` integration,
currency toggling, plan-selection JS all stay exclusively in
`upgrade.html`, which is also "Backend/API implementation"-adjacent
and explicitly out of scope) while still delivering a design-system-
consistent presentation layer. `enterprise-pricing.html` is therefore a
**presentation layer**: it shows the real numbers attractively and
drives every actual transaction (checkout, full comparison, full FAQ,
API docs) to the real page that already owns that logic — the same
split already used for `trust-center.html` and `mssp.html` in PR-5.

### 1.3 Section-by-section provenance

| # | Section | Source |
|---|---|---|
| 1 | Pricing Page intro | New copy |
| 2 | Pricing tiers | Real figures from `pricing.html`/`upgrade.html`; feature highlights are a subset of the real 20-row comparison table |
| 3 | API Plans | Real per-tier rate limits from `pricing.html`'s comparison table |
| 4 | Feature Comparison Table | Condensed real subset (8 of 20 rows); links to `pricing.html` for the full table |
| 5 | Customer Journey | New 7-step diagram; every step links to where that step actually happens on the real site |
| 6 | Ways to Engage (Demo/Contact/Partner/Telegram) | Links to real `demo.html`, real `mailto:contact@cyberdudebivash.in`, real `mssp.html`, real Telegram channel (`t.me/cyberdudebivashSentinelApex`, already used on `index.html`) |
| 7 | FAQ | Condensed real excerpt (5 of 9+ real Q&As across `pricing.html` and `docs/faq.html`); links to both full FAQs |
| 8 | Final CTA | New; links to real `upgrade.html`, `demo.html`, `mailto:` |

**Newsletter Signup** (named as a possible section in the brief) was
deliberately not built as a form: `components/newsletter.html` is
explicitly disclosed as "markup + styling only — no submission handler
wired up," and no real newsletter backend is evidenced anywhere in
this repository. Shipping a non-functional form would itself be
fabricating functionality. The real, working, already-public
engagement mechanism (the Telegram channel) is used instead.

---

## 2. Component Usage Map

Reused from `css/components.css`: `.sapx-container` / `-wide` / `-narrow`,
`.sapx-section` / `-alt` / `-lg`, `.sapx-grid-4` / `-2`, site
header/nav/footer, `.sapx-pricing-card` (all 4 tiers, including the
`-featured` badge variant), `.sapx-metric-card`, `.sapx-feature-card`,
`.sapx-cta-banner`, `.sapx-badge`, button system. Not used: hero,
integration-grid, announcement-card (inline variant), testimonial card
— none of this page's sections called for them.

Page-scoped additions (this page's own `<style>` block only):
`.pr6-compare-table` (components.css defines no table styles yet —
confirmed by grep before adding this, not a duplicate) and
`.pr6-journey-step` / `.pr6-journey-grid` (a 7-column grid; no existing
`.sapx-grid-*` modifier covers 7 columns, and a single-use count wasn't
added to the shared library for one page). Both guarded by
`tests/test_enterprise_pricing.py::test_page_style_does_not_redefine_existing_components`.

---

## 3. Migration Guide

Not applicable — new page. The one migration performed: `enterprise-homepage.html`'s
"Pricing" nav and footer links were repointed from `/pricing.html` to
`/enterprise-pricing.html` (2 href values changed, nothing else) now
that a design-system-consistent pricing page exists to send that
traffic to.

---

## 4. Accessibility Report

Verified in real headless Chromium via Playwright
(`render-test/verify_enterprise_pricing.js`) plus static analysis
(`tests/test_enterprise_pricing.py`):

| Check | Method | Result |
|---|---|---|
| Exactly one `<h1>`, no skipped heading levels | Static + real rendered DOM | PASS |
| Skip link is the first keyboard Tab stop | Real keyboard event | PASS |
| No duplicate `id` attributes | Static | PASS |
| Required landmarks present | Static | PASS |
| Comparison table wrapper scrolls horizontally rather than clipping content | Real computed style | PASS |
| Customer-journey grid: 7 cols (desktop) / 2 (tablet) / 1 (mobile) | Real computed `grid-template-columns` | PASS |
| No horizontal overflow at 375px / 768px / 1440px | Real Chromium | PASS (no new defects — PR-5's box-sizing/header fixes already cover this page) |
| `prefers-reduced-motion` collapses the status-dot pulse | Real `emulateMedia` | PASS |
| No console/page errors on load | Real Chromium | PASS |

### Computed WCAG contrast

| Pairing | Light theme | Dark theme |
|---|---|---|
| Featured plan's `.sapx-btn-primary` on brand-teal | 11.80:1 | 11.80:1 |

Same figure as PR-5's hero CTA — expected, since both reuse the same
already-fixed token, not a new calculation.

---

## 5. Performance Report

- **Zero new JavaScript** beyond the same ~10-line mobile nav toggle
  already shipped in `enterprise-homepage.html`/`components/header.html`.
- **Zero new images/fonts.**
- **No layout-shift risk**: same reduced-motion-gated status-dot pulse
  as PR-5, unchanged.
- **No CSS/component fixes required this round** — PR-5's box-sizing
  and header-collapse fixes in `css/components.css` already cover this
  page's layout primitives; all 15 Playwright checks and 14 static
  checks passed on the first run.
- **Page-added CSS is small**: ~90 lines, all token-driven except
  structural sizing (28px step-number badges, matching the identical,
  already-accepted precedent from PR-5's workflow diagram and
  components.css's own `.sapx-integration-card-mark`).

---

## 6. Known Limitations

- **Real pricing is duplicated in presentation, not logic.** The
  dollar figures and API limits are intentionally repeated (in a
  nicer, on-brand layout) from `pricing.html`; this is presentation
  reuse of the same real facts, not a second source of truth for
  computing them — guarded by
  `tests/test_enterprise_pricing.py`'s consistency tests, which fail
  the build if this page's numbers ever diverge from the real pages.
  If `pricing.html`'s prices change, this page's copy must be updated
  by hand to match (there is no shared data source to update once) —
  a known, accepted maintenance cost of the presentation/transaction
  split, flagged here rather than silently assumed away.
- **Feature comparison and FAQ are condensed subsets**, not full
  replicas (8 of 20 comparison rows; 5 of 9+ FAQ items). Both link to
  the full versions rather than reproducing them entirely, to avoid
  genuine content duplication.
- **No newsletter signup form** — see §1.3; no real backend is
  evidenced, so a non-functional form was not shipped.
- **Not yet linked from `index.html` or the legacy `pricing.html`/`upgrade.html`**
  themselves — only from `enterprise-homepage.html`. Wiring the legacy
  pages' own nav to point here (or not) is a product decision left for
  a future PR, not assumed in this one.
- **No automated pixel-diff visual regression harness** — same
  disclosed limitation as PR-5, same reasoning (no baseline-image
  convention or pixel-diff library in this repository to extend).
  `render-test/verify_enterprise_pricing.js` captures a full-page
  screenshot on every run as a manual QA aid.
- **Playwright is not a project dependency** — same as PR-5; runs
  against this environment's globally-installed `playwright` via
  `NODE_PATH`/`PLAYWRIGHT_BROWSERS_PATH`.

---

## 7. Repository Integration Guide

- **New files:** `enterprise-pricing.html`,
  `tests/test_enterprise_pricing.py`,
  `render-test/verify_enterprise_pricing.js`, this guide.
- **Modified files:** `enterprise-homepage.html` (2 href values only —
  "Pricing" nav/footer links repointed). No other file changed; unlike
  PR-5, no fix to `css/components.css`/`css/hero.css` was needed this
  round.
- **Never touched:** `pricing.html`, `upgrade.html`, `docs/faq.html`,
  `mssp.html`, `index.html`, `enterprise.html`, dashboard rendering,
  the API, Cloudflare Workers, CI/CD workflow definitions.
- **Idempotent by construction:** no patch script, no anchor-matching
  — re-applying this PR is "these files exist with this content."

---

## 8. Deployment Guide

1. Merge to the branch this repository deploys from `main` via GitHub
   Pages (`CNAME` → `intel.cyberdudebivash.com`) — same mechanism
   confirmed and used for PR-5.
2. Confirm `enterprise-pricing.html` resolves at
   `https://intel.cyberdudebivash.com/enterprise-pricing.html` after
   the next Pages rebuild.
3. No database migration, environment variable, Cloudflare Worker
   change, or CI/CD workflow change required — static HTML/CSS/test/doc
   files only, none of which touch `platform/**` or `src/**`/`wrangler.toml`
   (the only two paths that trigger this repo's build/deploy workflows).

---

## 9. Rollback Guide

1. `git revert` this PR's commit, or delete the 3 new files (page,
   test, render-test script) and this guide, and revert the 2-href
   change in `enterprise-homepage.html`.
2. No other page references `enterprise-pricing.html` yet except
   `enterprise-homepage.html`'s nav/footer, so reverting carries zero
   risk to any other page.
3. No data migration or cache invalidation needed beyond a normal
   static-asset redeploy.

---

## 10. Regression checklist (for this PR)

- [x] `enterprise-pricing.html` added; zero existing page's rendered
      output changed except `enterprise-homepage.html`'s 2 Pricing
      href values.
- [x] `pricing.html`, `upgrade.html`, `docs/faq.html`, `mssp.html`,
      `index.html`, `enterprise.html` — all untouched.
- [x] Zero hardcoded colors/spacing/typography in the page's own
      `<style>` block, outside `var(--sapx-*)`.
- [x] Zero classes referenced that aren't defined anywhere.
- [x] Zero component selectors redefined in the page's own `<style>`
      block.
- [x] `css/hero.css` not linked (content page, not a second hero).
- [x] Exactly one `<h1>`, no skipped heading levels, no duplicate
      `id`s, all required landmarks present.
- [x] Every internal link resolves to a real file in the repository.
- [x] Every dollar figure and API rate limit on this page matches
      `pricing.html`/`upgrade.html` exactly — automated, not manual.
- [x] No horizontal overflow at 375px / 768px / 1440px; customer-
      journey grid collapses correctly at both breakpoints.
- [x] Full existing regression suite (`test_components_css.py`,
      `test_patch_landing_hero.py`, `test_patch_homepage_metadata.py`,
      `test_enterprise_homepage.py`) re-run after every change — 85/85
      passing, 0 regressions.
