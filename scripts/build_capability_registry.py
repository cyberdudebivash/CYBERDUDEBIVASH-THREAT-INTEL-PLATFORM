#!/usr/bin/env python3
"""Generates data/quality/frontend_capability_registry.json.

Build script for data/quality/frontend_capability_registry.json, the
canonical frontend capability registry (CLAUDE.md Section 3 / mission item 3
of the sentinel-apex-transformation-8x3y26 session).

Not a CI-invoked script -- scripts/capability_registry_gate.py (added
alongside this file) is what CI runs against the JSON this writes; this
generator is kept in the repo so a future classification pass can
regenerate the mechanical baseline (dynamic vs. allowlisted-static, pulled
fresh from frontend_api_coverage_report.json) instead of hand-editing JSON,
then extend the CLASSIFICATIONS dict below for any newly-added page before
re-running.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_REPORT = REPO_ROOT / "data/quality/frontend_api_coverage_report.json"
OUTPUT = REPO_ROOT / "data/quality/frontend_capability_registry.json"

# Evidence-based classification for the 47 pages the mechanical dynamic/static
# heuristic cannot resolve on its own (data/quality/frontend_static_page_allowlist.json
# only covers the zero-<form>/zero-fetch( subset). Derived from a full-file read
# of every page below during the sentinel-apex-transformation-8x3y26 session
# (2026-09-03), independently spot-verified (see session notes / final report),
# not name-guessed.
#
# category: CUSTOMER_UI | API_ONLY | ADMIN | INTERNAL | DEPRECATED
# status (CUSTOMER_UI only): live | orphan | form_only | static_content | interactive_docs
CLASSIFICATIONS = {
    # -- Fixed this session --
    "sentinel-onboarding.html": ("CUSTOMER_UI", "form_only",
        "Fixed this session: removed fabricated org/tenant/API-key credentials and the false "
        "'account activated' / 'credentials emailed' claims from step 5. Now honestly states "
        "activation is manual. No route wires a real self-serve paid-tier provisioning flow yet "
        "(payment step is decorative -- simulatePaypal() just opens paypal.com); building one is "
        "explicitly out of scope here (CLAUDE.md: payment/billing logic is frozen)."),
    "support-center.html": ("CUSTOMER_UI", "live",
        "Fixed 2026-09-28: showed five invented tickets with live-looking SLA countdowns and 'created' randomly generated ticket IDs "
        "that were never sent anywhere (no ticketing backend exists). Rebuilt as the real support page: contracted support per "
        "plan (verbatim from config/commercial-contract.json, test-pinned), real contact addresses, live status from /api/watchdog/health."),
    # -- Genuine CUSTOMER_UI orphans: real customer surfaces showing hardcoded/placeholder data,
    #    not yet wired this session. best-fit route(s) noted for the next pass. --
    "ai-runtime-defense.html": ("CUSTOMER_UI", "live",
                                "Fixed 2026-09-27: random counters and fake blocked-attack log removed; states the hosted "
                                "runtime service is not offered and lists AI-security advisories from /api/feed.json "
                                "(js/feed-topic-view.js)."),
    "ai-security-ops-hub.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /ai-runtime-defense.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "api-management-center.html": ("DEPRECATED", None,
        "Already a redirect to /api-key-manager.html (hardcoded mockup replaced earlier); registry entry corrected 2026-09-28."),
    "api-reference-card.html": ("CUSTOMER_UI", "live",
        "Fixed 2026-09-28: hardcoded '77+ Live Advisories', 'v184.0', a pulsing LIVE badge and per-endpoint '200 Live', plus "
        "unmeasured '<80ms P95' and '55+ Intel Sources'. Count, version and freshness now read from /api/watchdog/health; "
        "unmeasured facts removed; endpoint status shown as the documented '200 OK'."),
    "billing-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /subscription-management.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "customer-dashboard.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /soc-operations-center.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "cyber-kits.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release pricing sweep): sold one-time kits (\"$149 one-time\") whose buy links re-priced "
        "upgrade.html from ?amount= while checkout created the recurring subscription for the mapped tier at its "
        "contracted price; no one-time checkout or kit delivery exists. Replaced by a redirect to /store.html "
        "(same pattern as customer-portal.html); upgrade.html ignores ?kit and ?amount."),
    "customer-portal.html": ("DEPRECATED", None,
        "Already a redirect to /api-key-manager.html (hardcoded mockup replaced earlier); registry entry corrected 2026-09-28."),
    "daily-operations-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /soc-operations-center.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "dashboard.html": ("CUSTOMER_UI", "orphan",
        "Investigated this session, deliberately NOT fixed: its fetch() calls target /auth/login "
        "and /auth/keys (missing /api/ prefix AND /api/auth/keys does not exist as a route at all -- "
        "only /api/admin/keys [admin-scoped] and /api/keys/free [free-tier signup] exist). This is an "
        "auth-model mismatch, not a URL typo -- see login.html note. Also references stale element IDs "
        "('login-screen'/'dashboard-screen') that don't match its own DOM ('auth-gate'/'dashboard'). "
        "Needs an auth-model decision before any fix, not a frontend-only patch."),
    "dependency-platform.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /api-key-manager.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "evidence-threat-map.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /enterprise-knowledge-graph.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "executive-reporting-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /enterprise-cyber-intelligence-os.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "malware-intel-hub.html": ("CUSTOMER_UI", "live",
        "Fixed 2026-09-27: rebuilt on /api/feed.json (malware-related advisories, counts and feed "
        "time read at load) plus the /api/v1/export/* detection downloads. Removed the Math.random() "
        "'sandbox detonation' stream (invented hashes and 'C2' IPs, one a real public address), the "
        "fixed sample/YARA/family counts and a 'C2 infrastructure registry' naming real ASNs."),
    "mssp-console.html": ("CUSTOMER_UI", "orphan", "1785-line MSSP console, fully hardcoded, zero fetch. Fits /api/mssp, /api/mssp/feed, /api/mssp/tenants/{id}/feed."),
    "mssp-customer-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /mssp-tenant-dashboard.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "mssp-partner-portal.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /mssp-tenant-dashboard.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "my-exposure-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /cyber-watchdog.html#watches (same pattern as customer-portal.html); kept so existing links still resolve."),
    "payment-confirmation.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /payment-status-dashboard.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "soc-operations-center.html": ("CUSTOMER_UI", "live",
        "Fixed 2026-09-28: rebuilt on /api/v1/intel/latest.json (KPIs, 24h intake, advisory stream, "
        "sources, ATT&CK tactics counted by js/soc-ops-model.js), /api/watchdog/brief (priority queue) "
        "and /api/watchdog/health (freshness: figures withheld unless FRESH, or STALE <= 48h labelled "
        "NOT LIVE). Removed the Math.random() event stream, heatmap and source counts, the fixed "
        "IOC/sensor/replay/coverage figures and the invented graph, AI gauges, malware and honeynet panels."),
    "soc-workspace.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /enterprise-cyber-intelligence-os.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "subscription-billing-center.html": ("CUSTOMER_UI", "orphan", "Hardcoded MRR/usage figures; every action button alert()s a nonexistent route. Partial fit /api/payment/status."),
    "telemetry-embedding.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /observability.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "telemetry-visibility-ops.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /observability.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "unified-ops-hub.html": ("DEPRECATED", None,
        "2026-09-27: static mockup with invented/random \"live\" data and zero API calls, replaced by a "
        "redirect to /enterprise-cyber-intelligence-os.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "value-center.html": ("DEPRECATED", None,
        "2026-09-28 (pre-release fabrication sweep): hardcoded/invented \"live\" data and zero API calls, replaced by a "
        "redirect to /roi-calculator.html (same pattern as customer-portal.html); kept so existing links still resolve."),
    "trial-center.html": ("CUSTOMER_UI", "static_content",
        "Plan overview. 2026-09-28: its only API call was the free-key modal (POST /api/apikeys/request-free); "
        "the Free tier is keyless (commercial-contract.json FREE api_keys 0) and that route answers 410, so the "
        "modal was removed and the Community card links to the keyless start on /get-api-key.html."),
    "login.html": ("CUSTOMER_UI", "orphan",
        "Investigated this session, deliberately NOT fixed: fetch() calls are missing the /api/ "
        "prefix (/auth/login, /auth/signup), but the deeper issue is an auth-MODEL mismatch, not a "
        "URL typo -- POST /api/auth/login expects {api_key}, not {email,password} (this platform has "
        "no password-based account system), and POST /api/auth/register unconditionally returns 422 "
        "'Email registration is not available.' A shallow /api/ prefix fix would still be broken and "
        "would look fixed when it isn't; CLAUDE.md freezes auth-logic changes outright. Needs a product "
        "decision (build real email/password auth, or redesign this page around API-key issuance) before "
        "any code changes here. 2026-09-28: the Free tier is keyless (commercial-contract.json FREE "
        "api_keys 0; /api/keys/free answers 410), so the sign-up panel now links to the API docs and Pro "
        "checkout; sign-in with an API key is unchanged."),
    # -- ADMIN: internal ops tools, not customer-facing --
    "admin.html": ("ADMIN", None, "Password-gated internal admin control panel."),
    "conversion-analytics.html": ("ADMIN", None, "CDB-internal sales-funnel analytics."),
    "customer-health-platform.html": ("ADMIN", None, "CDB-internal customer health/churn scoring tool."),
    "customer-intelligence.html": ("ADMIN", None, "CDB-internal customer health-scoring engine."),
    "customer-ops-center.html": ("ADMIN", None, "CDB-internal 'Global Ops' command center."),
    "customer-success-center.html": ("ADMIN", None, "CDB-internal CS team tool."),
    "demo-conversion-center.html": ("ADMIN", None, "CDB-internal demo-to-customer sales pipeline tracker."),
    "lead-intelligence.html": ("ADMIN", None, "CDB-internal lead-scoring engine."),
    "monetization-ops.html": ("ADMIN", None, "CDB-internal revenue/monetization ops dashboard."),
    "revenue-intelligence.html": ("ADMIN", None, "CDB-internal revenue-ops engine; own code comment says data is 'seeded...in production fetched from revenue registry API'."),
    "sentinel-master-ops-center.html": ("ADMIN", None, "CDB-internal master operations command center."),
    # -- CUSTOMER_UI form-only: real customer surface, only function is a form/CTA --
    "contact-enterprise.html": ("CUSTOMER_UI", "form_only", "Enterprise sales contact form."),
    "demo.html": ("CUSTOMER_UI", "live",
        "2026-10-04: booking page now includes a real read-only Investigation Workbench. Public replay calls "
        "/api/v1/demo/replay and is explicitly synthetic; authenticated PRO+/MSSP mode calls "
        "/api/v1/investigation/item. The legacy API sandbox remains explicitly labelled static sample data."),
    "enterprise-demo.html": ("CUSTOMER_UI", "form_only", "Enterprise-tier 'Book a Demo' page."),
    "executive-briefing.html": ("CUSTOMER_UI", "form_only", "CISO/board briefing-pack marketing page; ROI cites a real external IBM breach-cost report."),
    "lead-capture.html": ("CUSTOMER_UI", "form_only", "Paywall-unlock lead-gen form."),
    "partner.html": ("CUSTOMER_UI", "form_only", "Partner/reseller program marketing page."),
    # -- INTERNAL: one-off report artifact, not a live product surface --
    "GODMODE-REVENUE-AUDIT-REPORT.html": ("INTERNAL", None, "One-off internal audit report artifact (added to the static allowlist -- zero real form/fetch; its 'fetch(' matches are prose describing suggested code, not executable JS)."),
    # -- INTERNAL: same class as GODMODE-REVENUE-AUDIT-REPORT.html above --
    # found by scripts/capability_runtime_auditor.py (P0 Dynamic Capability
    # Runtime Convergence session): all 4 were misclassified CUSTOMER_UI/
    # static_content with the generic "marketing/legal/informational"
    # note, but are actually internal engineering/business audit reports
    # (zero <script> tags; content includes commit-referencing defect
    # tables, P0 gate IDs, and -- SENTINEL_APEX_ENTERPRISE_AUDIT_v145.html
    # specifically -- live sales-pipeline figures like "3 incoming
    # enterprise inquiry emails" and unresolved revenue-blocking gaps).
    # frontend_api_coverage_gate.py's own docstring already independently
    # described v145 as "a prose audit report" when documenting an
    # unrelated false-positive fix -- this classification fix is the first
    # place that finding is actually acted on. Reclassifying only changes
    # P41 capability-discovery visibility (never advertised as a customer
    # capability, never appears in /api/v1/p41/capabilities); it does not
    # change or add any HTTP access control to the file itself, which is
    # unchanged and out of scope for this fix (see this session's own
    # report for that distinction).
    "SENTINEL-APEX-CEO-CTO-CISO-EXECUTIVE-AUDIT-REPORT-v161.html": ("INTERNAL", None, "Internal engineering audit report (ISSUE ID/ROOT CAUSE/FIX/COMMIT defect table), not customer-facing content. Zero <script> tags."),
    "SENTINEL-APEX-SOVEREIGN-MASTER-REPORT-2026.html": ("INTERNAL", None, "Internal engineering/revenue audit report (\"REVENUE BLOCKED -- 5 FIXES REQUIRED\", per-tier enforcement-gap notes), not customer-facing content. Zero <script> tags."),
    "SENTINEL_APEX_ENTERPRISE_AUDIT_v145.html": ("INTERNAL", None, "Internal production audit report discussing live sales-pipeline figures and unresolved P0 revenue-blocking gaps, not customer-facing content. Zero <script> tags. Already independently described as 'a prose audit report' in frontend_api_coverage_gate.py's own docstring (an unrelated false-positive fix) prior to this classification correction."),
    "SENTINEL_APEX_P0_AUDIT_REPORT.html": ("INTERNAL", None, "Internal full-system audit report, not customer-facing content. Zero <script> tags."),
    # -- CUSTOMER_UI, correctly excluded from the strict static allowlist --
    "api-docs.html": ("CUSTOMER_UI", "interactive_docs", "Has real interactive 'try it' fetch() calls (an embedded API console), not a placeholder-data page -- intentionally not in the zero-fetch static allowlist."),
    "intelligence-archive.html": ("CUSTOMER_UI", "live_non_gateway", "Genuinely fetches live JSON from /data/intelligence_repository/*.json -- a real data source outside the /api/ gateway, so the coverage gate's /api/-only regex permanently misses it (by design, not a bug in that gate -- see its own docstring's scope note). Deliberately NOT status='live': that status feeds capability_registry_gate.py's placeholder-regression check against frontend_api_coverage_report.json's dynamic_pages list, which this page can never appear in. Not a defect; not added to the static allowlist because it IS dynamic."),
}

STATUS_NOTE = {
    "orphan": "Static/placeholder data on a real customer surface -- tracked defect, needs live API wiring.",
    "form_only": "Customer-facing; its only function is a form/CTA, no live-data surface required.",
    "static_content": "Legitimately static marketing/legal/informational content.",
    "interactive_docs": "Static reference content with a live interactive example widget.",
    "live": "Wired to a live backend API.",
    "live_non_gateway": "Wired to genuinely live data from a source outside the /api/ gateway (e.g. static archived JSON); excluded from status='live' so it is never checked against the /api/-only coverage heuristic.",
}


def main():
    if not COVERAGE_REPORT.exists():
        raise SystemExit(
            f"[FATAL] {COVERAGE_REPORT.relative_to(REPO_ROOT)} does not exist. "
            f"Run scripts/frontend_api_coverage_gate.py first (STAGE 3.92b runs "
            f"before this step in sentinel-apex.yml)."
        )
    try:
        report = json.loads(COVERAGE_REPORT.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"[FATAL] {COVERAGE_REPORT.relative_to(REPO_ROOT)} is not valid JSON ({e}). "
            f"Re-run scripts/frontend_api_coverage_gate.py to regenerate it."
        )
    entries = []

    for p in report["dynamic_pages"]:
        entries.append({
            "id": p["file"], "frontend_route": "/" + p["file"],
            "category": "CUSTOMER_UI", "status": "live",
            "notes": STATUS_NOTE["live"] + " (" + p["reason"] + ")",
        })

    for p in report["static_pages"]:
        fname = p["file"]
        if fname in CLASSIFICATIONS:
            category, status, notes = CLASSIFICATIONS[fname]
            entry = {"id": fname, "frontend_route": "/" + fname, "category": category, "notes": notes}
            if status:
                entry["status"] = status
            entries.append(entry)
        elif p.get("allowlisted"):
            entries.append({
                "id": fname, "frontend_route": "/" + fname,
                "category": "CUSTOMER_UI", "status": "static_content",
                "notes": STATUS_NOTE["static_content"],
            })
        else:
            raise SystemExit(f"UNCLASSIFIED page with no registry entry: {fname} -- add it to CLASSIFICATIONS before regenerating")

    entries.sort(key=lambda e: e["id"])

    by_category = {}
    for e in entries:
        by_category[e["category"]] = by_category.get(e["category"], 0) + 1
    orphan_count = sum(1 for e in entries if e.get("status") == "orphan")

    registry = {
        "schema_version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/build_capability_registry.py (one-time build; hand-maintained CLASSIFICATIONS dict thereafter)",
        "scope": "top-level *.html (repo root) -- see CLAUDE.md's P-layer table and scripts/capability_coverage_audit.py for the /api/v1/pXX/* backend route -> handler registry (a distinct, complementary artifact; this file classifies FRONTEND pages, not backend routes)",
        "taxonomy": ["CUSTOMER_UI", "API_ONLY", "ADMIN", "INTERNAL", "DEPRECATED"],
        "total_pages": len(entries),
        "by_category": by_category,
        "customer_ui_orphan_count": orphan_count,
        "unclassified_count": 0,
        "note": (
            "unclassified_count is the mission-tracked metric (target: 0). A page's presence in "
            "this file's `entries` array with a category from `taxonomy` IS its classification -- "
            "there is no separate UNCLASSIFIED bucket by construction (see scripts/capability_registry_gate.py, "
            "which fails CI if a top-level *.html page exists with no entry here). customer_ui_orphan_count "
            "tracks a SEPARATE, non-blocking metric: CUSTOMER_UI pages that are correctly classified but "
            "still show static/placeholder data pending a live-API wiring fix -- see each entry's `notes`."
        ),
        "access_navigation_audit_status": (
            "NOT YET DONE for most entries. The mission's requested `access` (public/api_key_required/admin) "
            "and `navigation` (which nav menus link to this page) fields were audited and are accurate ONLY "
            "for the 9 pages this session touched directly (see the P21-P40 dashboard family and the git log "
            "for claude/sentinel-apex-transformation-8x3y26). Populating them accurately for the other 140 "
            "pages requires reading each page's own auth-wall markup and cross-referencing every nav/header "
            "partial across the site -- exactly the 'Unified Application Shell' audit (mission item 4) this "
            "session did not have room for. Recommended as the next P0: a dedicated navigation-shell audit "
            "pass, not a guess encoded into this file."
        ),
        "entries": entries,
    }

    OUTPUT.write_text(json.dumps(registry, indent=2) + "\n")
    print(f"Wrote {OUTPUT} -- {len(entries)} pages classified, by_category={by_category}, orphans={orphan_count}")


if __name__ == "__main__":
    main()
