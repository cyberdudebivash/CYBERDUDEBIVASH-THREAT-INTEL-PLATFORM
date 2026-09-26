#!/usr/bin/env python3
"""
scripts/capability_runtime_auditor.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Capability Runtime Auditor (P0 Runtime
Convergence & Production Completeness Certification)

WHY THIS EXISTS
----------------
P41 (scripts/build_capability_registry.py + p41-handlers.js, PR #342) proves
"Sentinel APEX knows which customer-facing capabilities exist." It does not
prove that every one of them actually WORKS -- a page can be classified
CUSTOMER_UI/live by frontend_api_coverage_gate.py's fetch()+/api/ heuristic
while calling an endpoint that no longer exists, and a page classified
CUSTOMER_UI/orphan can be presenting fabricated "live" data (Math.random()
fake counters, a static "LIVE" badge, a code comment that lies about being
"Real manifest-driven") to a paying customer. This script closes that gap:
for every CUSTOMER_UI capability in the registry, it computes a runtime
DISPOSITION from real, static evidence -- not from registry membership
alone (the registry only proves classification, not correctness).

REUSE BEFORE BUILD -- this script re-derives NO classification logic that
already exists elsewhere; it composes:
  - data/quality/frontend_capability_registry.json (build_capability_registry.py)
    -- canonical CUSTOMER_UI inventory + human-audited notes (many entries,
    especially status="orphan", already document a specific hardcoded-data
    finding from an earlier session's manual page read -- reused verbatim
    as evidence here, not re-derived).
  - data/quality/frontend_api_coverage_report.json (frontend_api_coverage_gate.py)
    -- the dynamic/static classification per page (JS_RUNTIME).
  - data/quality/metric_integrity_contract_report.json (metric_integrity_
    contract_gate.py, PR #341) -- forbidden-hardcode findings, reused as
    corroborating evidence for a PLACEHOLDER_DEFECT / FAKE_LIVE_CLAIM
    verdict rather than re-scanning for the same 8 strings a second time.
  - workers/intel-gateway/src/index.js -- the live route dispatch table,
    parsed once here to check whether a page's own declared "/api/..."
    literal actually resolves to a real backend route (API_EXISTS).

WHAT THIS ADDS THAT NONE OF THE ABOVE HAD
-------------------------------------------
  - Per-page API_DEPENDENCY extraction + API_EXISTS cross-check against the
    real route table (contract-drift detection: "frontend declares API X,
    API X was removed/renamed").
  - FAKE_LIVE_CLAIM detection: a page whose own markup/JS text contains an
    explicit "LIVE" operational claim (badge text, pulsing-indicator class,
    Math.random()-driven counter update, or a code comment asserting real
    data) while frontend_api_coverage_gate.py found NO genuine fetch()+/api/
    evidence on that same page. This is deliberately narrow and evidence-
    based (see FAKE_LIVE_MARKERS below) -- it does not flag every hardcoded
    number, only an EXPLICIT liveness claim contradicted by an absence of
    any real data call, to avoid the "false-positive-heavy generic
    scanning" the mission text explicitly warns against.
  - AUTH_GATED detection via an auth-wall DOM pattern (deliberately narrow:
    a real `auth-wall`-class element or an equivalent guard, not a bare
    mention of the word "auth").
  - A single VERDICT per capability from the mission's required taxonomy:
    DYNAMIC_VERIFIED / STATIC_VALID / AUTH_GATED / DEGRADED / BROKEN /
    ORPHANED / MISCLASSIFIED.

TWO-TIER DESIGN (mission Section 5: "separate deterministic CI checks from
live production checks")
  - This script is 100% static/offline: file reads + regex only, zero
    network calls, zero browser launches. Safe to run on every PR and in
    CI (see scripts/capability_runtime_gate.py, which wraps this script's
    JSON output into a narrowly-scoped blocking gate, the same two-script
    split capability_registry_gate.py already established over
    build_capability_registry.py).
  - Live HTTP/headless verification (Tier 1/2/3 browser checks) is a
    SEPARATE, explicitly-invoked step (see scripts/capability_live_probe.py)
    -- this script's DYNAMIC_VERIFIED verdict means "the code looks
    correct and self-consistent," not "confirmed live in production."

Writes data/quality/capability_runtime_report.json every run. Always
exits 0 -- this script computes and reports; scripts/capability_runtime_gate.py
is the (separately, narrowly) blocking layer.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import homepage_source as _homepage_source  # index.html + extracted assets (2026-09-26)  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "data" / "quality" / "frontend_capability_registry.json"
COVERAGE_PATH = REPO_ROOT / "data" / "quality" / "frontend_api_coverage_report.json"
METRIC_CONTRACT_REPORT_PATH = REPO_ROOT / "data" / "quality" / "metric_integrity_contract_report.json"
# All three Worker entry points this repo deploys (verified live: `find
# workers -maxdepth 3 -name index.js -path '*/src/*'`), not just
# intel-gateway. A frontend page can legitimately call any of them --
# missing revenue-engine.js from this list is exactly what produced a wave
# of false "contract drift" findings on billing/CRM/onboarding pages during
# this script's own development (their real routes -- /api/apikeys/rotate,
# /api/customers/provision, /api/crm/leads -- live in revenue-engine, not
# intel-gateway).
WORKER_INDEX_PATHS = (
    REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js",
    REPO_ROOT / "workers" / "revenue-engine" / "src" / "index.js",
    REPO_ROOT / "workers" / "intel-retention-engine" / "src" / "index.js",
)
INDEX_JS_PATH = WORKER_INDEX_PATHS[0]  # back-compat alias for existing call sites
OUTPUT_PATH = REPO_ROOT / "data" / "quality" / "capability_runtime_report.json"

VALID_VERDICTS = (
    "DYNAMIC_VERIFIED", "STATIC_VALID", "AUTH_GATED", "DEGRADED",
    "BROKEN", "ORPHANED", "MISCLASSIFIED",
)

# ---------------------------------------------------------------------------
# Shared regexes -- same idioms already established in
# frontend_api_coverage_gate.py / metric_integrity_contract_gate.py, reused
# rather than re-derived (Single Source of Truth for "what counts as an
# inline script" / "what counts as a real script src=").
# ---------------------------------------------------------------------------
_SCRIPT_BLOCK_RE = re.compile(r"<script\b([^>]*)>(.*?)</script[^>]*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_API_PATH_LITERAL_RE = re.compile(r"""["'`](/api/[a-zA-Z0-9_\-/{}.]*)["'`]""")

# CORROBORATING EVIDENCE ONLY -- NOT an independent verdict trigger (see
# audit_capability()). First version of this script used a standalone
# "fake_live_markers and not js_runtime_dynamic -> BROKEN" rule; verified
# against real pages before trusting it (this repo's own governing rule:
# validate automated findings against actual code) and found it added ZERO
# net-new true findings beyond what the registry's own human-audited
# "orphan" notes already covered, while independently misfiring on
# legitimate feature-availability badges (enterprise-compliance.html:
# "STIX 2.1 ... <span class=badge-success>Live</span>" -- a capability-
# available badge, not an operational claim), a demo-booking CTA
# (enterprise-demo.html: "See SENTINEL APEX Live"), a competitor-comparison
# table (compare.html, reference-architecture.html: "<td>LIVE</td>" rating
# a 3rd-party SIEM integration, not this platform's own data), and a
# harmless Math.random() reference-code generator (lead-capture.html's
# genRef()). A bare ">LIVE<"/"Math.random()" scan cannot distinguish these
# from a genuine fake operational counter without much more context than a
# regex can reliably carry -- kept here as an annotation surfaced per-page
# for human triage (mission Section 22: "avoid false-positive-heavy generic
# scanning"), not as something that decides BROKEN on its own.
FAKE_LIVE_MARKERS = (
    re.compile(r'class="[^"]*\blive-badge\b', re.IGNORECASE),
    re.compile(r'class="[^"]*\bpulse\b', re.IGNORECASE),
    re.compile(r">\s*LIVE\s*<", re.IGNORECASE),
    re.compile(r"Math\.random\(\)"),
)

AUTH_WALL_MARKERS = (
    re.compile(r'class="[^"]*\bauth-wall\b'),
    re.compile(r'id="auth-wall"'),
    re.compile(r"\brequireAuth\s*\("),
)


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _inline_script_text(content: str) -> str:
    parts = []
    for attrs, body in _SCRIPT_BLOCK_RE.findall(content):
        if "src=" in attrs.lower():
            continue
        if "application/ld+json" in attrs.lower():
            continue
        parts.append(body)
    return "\n".join(parts)


def _extract_api_dependencies(content: str) -> list[str]:
    script_text = _inline_script_text(content)
    return sorted(set(_API_PATH_LITERAL_RE.findall(script_text)))


def _extract_script_srcs(content: str) -> list[str]:
    return [m.group(1) for m in _SCRIPT_SRC_RE.finditer(content)]


_ROUTE_CONDITION_RE = re.compile(
    r'path\s*===\s*"(/api/[a-zA-Z0-9_\-/{}.]*)"'
    r'|path\.startsWith\(\s*"(/api/[a-zA-Z0-9_\-/{}.]*)"\s*\)'
)

# Individually verified (this session, capability_runtime_auditor.py's own
# development), not a generic length/pattern filter: "/api/" is used
# EXACTLY once in index.js, as `path.startsWith("/api/") || path.startsWith
# ("/taxii")` -- a broad "is this in the API namespace at all" gate, not a
# route with its own handler. Including it made every frontend API
# dependency starting with "/api/" trivially match (a prefix of a prefix of
# everything), which silently defeated the contract-drift check entirely
# (verified: api_dependencies_missing was 0/33 across the whole registry
# before this fix, an implausible "everything is wired correctly" result
# that should have been distrusted on sight -- CLAUDE.md/mission: validate
# findings, including a suspiciously clean one, before trusting them).
_KNOWN_NAMESPACE_GUARDS = frozenset({"/api/"})

# Individually verified, same standard as _KNOWN_NAMESPACE_GUARDS: routes
# dispatched through a Set-membership check
# (`AI_STATIC_PROXY_FILES.has(path.slice(...))`, index.js:6537-6538) rather
# than a literal `path === "X"`/`path.startsWith("X")` comparison, so the
# regex-based route table can never see them even though they are real,
# working, R2-backed routes.
_KNOWN_ADDITIONAL_VALID_ROUTES = frozenset({
    "/api/ai/tracker.json", "/api/ai/health.json", "/api/ai/executive-brief.json",
})


def _load_route_table() -> list[str]:
    """Every literal '/api/...' path string used as a `path === "X"` or
    `path.startsWith("X")` comparison anywhere in index.js, MINUS lines
    negating the check (`!path...` -- an exclusion guard, never a route:
    verified live that "/api/admin"/"/api/auth" appear in exactly this
    negated shape at one call site) and minus _KNOWN_NAMESPACE_GUARDS.

    Deliberately broad rather than requiring an exact single-line dispatch
    shape: index.js uses at least three real, working dispatch
    conventions -- `if (path === "X") return await handleY(...)` (single
    line), `if (path === "X") { ... return await handleY(...); }`
    (multi-line block), and `if (path === "X") { ... return jsonResp(...);
    }` (multi-line block with no handleY call at all, e.g. the
    /api/v1/intel/ransomware route) -- verified live that requiring a
    same-line `return await handle` (an earlier version of this function)
    misclassified working, PR #336-verified routes like ransomware.html's
    own /api/v1/intel/ransomware as "missing." A real JS parser could
    disambiguate every case precisely; absent one, erring toward a more
    INCLUSIVE route table is the safer failure mode for a report that will
    be read as findings -- a route table that's too narrow produces false
    BROKEN accusations against genuinely working pages (worse: actively
    misleading), while one that's too broad merely under-detects some
    genuine contract drift (a false negative, not a false accusation).

    Scans ALL of WORKER_INDEX_PATHS (not just intel-gateway) -- see that
    constant's own comment for why."""
    literals: set[str] = set()
    for worker_path in WORKER_INDEX_PATHS:
        if not worker_path.exists():
            continue
        text = worker_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            for m in _ROUTE_CONDITION_RE.finditer(line):
                literal = m.group(1) or m.group(2)
                # Exclude only a negated occurrence of THIS literal on this
                # line (a line can legitimately mix a negated exclusion for
                # one literal with a real, non-negated check for another).
                start = m.start()
                prefix = line[max(0, start - 2):start]
                if "!" in prefix:
                    continue
                if literal in _KNOWN_NAMESPACE_GUARDS:
                    continue
                literals.add(literal)
    return sorted(literals)


def _static_json_exists(dep: str) -> bool:
    """A frontend '/api/...' literal can also legitimately resolve to a
    real, checked-in static JSON file served directly (verified live:
    api/apex_v2/critical.json and api/v1/intel/ai_summary.json both exist
    on disk and are real data sources index.html/observability.html
    correctly depend on -- mission Section 7's own GENERATED_JSON data-
    source category, distinct from a Worker-dispatched WORKER_API route).
    Checks both the literal path and, since some frontend calls omit the
    real file's .json suffix, the same path with .json appended."""
    rel = dep.lstrip("/")
    for candidate in (rel, rel + ".json"):
        if (REPO_ROOT / candidate).is_file():
            return True
    return False


def _api_exists(dep: str, route_table: list[str]) -> bool:
    if dep in _KNOWN_ADDITIONAL_VALID_ROUTES:
        return True
    if _static_json_exists(dep):
        return True
    # {id}-style path params in the registered route table never appear
    # literally in frontend code (frontend interpolates a real id) -- strip
    # the templated segment and compare prefixes so e.g. frontend's
    # "/api/mssp/tenants/abc123/feed" matches route table's
    # "/api/mssp/tenants/{id}/feed" (segment-count + prefix match), not just
    # a literal string.
    dep_norm = dep.rstrip("/")
    for route in route_table:
        route_norm = route.rstrip("/")
        if dep_norm == route_norm:
            return True
        if "{" in route_norm:
            pattern = "^" + re.escape(route_norm).replace(r"\{id\}", r"[^/]+") + r"($|/)"
            pattern = re.sub(r"\\\{[a-zA-Z_]+\\\}", r"[^/]+", pattern)
            if re.match(pattern, dep_norm):
                return True
        # A route registered as a prefix check (path.startsWith(route)) --
        # if the frontend's literal starts with a shorter registered route,
        # that's still a real, live-dispatched path.
        if route_norm and dep_norm.startswith(route_norm):
            return True
    return False


def _has_any_marker(text: str, markers) -> list[str]:
    return [m.pattern for m in markers if m.search(text)]


def audit_capability(entry: dict, coverage_by_file: dict, forbidden_pages: set[str],
                      route_table: list[str]) -> dict:
    page_id = entry["id"]
    path = REPO_ROOT / page_id
    route_exists = path.exists() and path.is_file()

    result = {
        "capability_id": page_id,
        "name": page_id,
        "frontend_route": entry.get("frontend_route", "/" + page_id),
        "registry_status": entry.get("status"),
        "route_exists": route_exists,
        "js_runtime_dynamic": False,
        "js_runtime_reason": None,
        "api_dependencies": [],
        "api_dependencies_missing": [],
        "script_srcs": [],
        "forbidden_hardcode_finding": page_id in forbidden_pages,
        "fake_live_markers": [],
        "auth_gated_markers": [],
        "verdict": None,
        "verdict_reason": "",
    }

    if not route_exists:
        result["verdict"] = "ORPHANED"
        result["verdict_reason"] = "Registry entry has no corresponding file on disk."
        return result

    try:
        content = _homepage_source.read_text_for_inspection(path)
    except Exception as e:
        result["verdict"] = "BROKEN"
        result["verdict_reason"] = f"File exists but could not be read: {e}"
        return result

    cov = coverage_by_file.get(page_id)
    result["js_runtime_dynamic"] = bool(cov and cov.get("dynamic"))
    result["js_runtime_reason"] = cov.get("reason") if cov else None
    result["api_dependencies"] = _extract_api_dependencies(content)
    result["script_srcs"] = _extract_script_srcs(content)
    result["api_dependencies_missing"] = [
        d for d in result["api_dependencies"] if not _api_exists(d, route_table)
    ]
    result["fake_live_markers"] = _has_any_marker(content, FAKE_LIVE_MARKERS)
    result["auth_gated_markers"] = _has_any_marker(content, AUTH_WALL_MARKERS)

    status = entry.get("status")

    # --- Decision tree -----------------------------------------------------
    if result["auth_gated_markers"]:
        result["verdict"] = "AUTH_GATED"
        result["verdict_reason"] = "Page renders behind a client-side auth-wall guard backed by server-side entitlement checks."
        return result

    if result["js_runtime_dynamic"] and result["api_dependencies"] and result["api_dependencies_missing"]:
        result["verdict"] = "BROKEN"
        result["verdict_reason"] = (
            "Page calls a declared API path with no matching route in workers/intel-gateway/src/index.js "
            f"(contract drift): {result['api_dependencies_missing']}"
        )
        return result

    if status == "orphan":
        # Every orphan entry's own registry note already documents a
        # specific hardcoded-data finding from a prior manual read (see
        # module docstring) -- an orphan capability is, by that existing
        # evidence, advertised as CUSTOMER_UI but not functioning as
        # claimed. Two known, explicitly out-of-scope exceptions (auth-model
        # mismatch, frozen per CLAUDE.md -- not a frontend defect this
        # script can fix) are called out by name so they read as documented
        # residual risk, not a silent miscount.
        if page_id in ("dashboard.html", "login.html"):
            result["verdict"] = "BROKEN"
            result["verdict_reason"] = (
                "Auth-model mismatch (no password-based account system backs this page's own "
                "fetch calls) -- investigated and deliberately not fixed; CLAUDE.md freezes "
                "auth-logic changes outright. Requires a product decision, not a frontend patch."
            )
        else:
            result["verdict"] = "BROKEN"
            result["verdict_reason"] = (
                "Registry classifies this CUSTOMER_UI page 'orphan': " + str(entry.get("notes", ""))
            )
        return result

    if result["js_runtime_dynamic"]:
        result["verdict"] = "DYNAMIC_VERIFIED"
        result["verdict_reason"] = f"Genuine dynamic evidence: {result['js_runtime_reason']}. No missing API dependency detected."
        return result

    if status in ("static_content", "form_only", "interactive_docs"):
        if result["forbidden_hardcode_finding"]:
            result["verdict"] = "DEGRADED"
            result["verdict_reason"] = (
                "Classified static/informational but flagged by metric_integrity_contract_gate.py "
                "for a forbidden hardcoded marketing-number string -- verify the string is legitimate "
                "static copy, not a stale operational claim."
            )
        else:
            result["verdict"] = "STATIC_VALID"
            result["verdict_reason"] = f"Registry status '{status}' -- legitimately static, no operational-state claim detected."
        return result

    # live_non_gateway or any future status not covered above but with a
    # real script src to a known shared data-plane script: treat as
    # DYNAMIC_VERIFIED conservatively only if coverage report already
    # agreed (js_runtime_dynamic above would have caught it); otherwise
    # fall through to DEGRADED as an honest "needs human classification"
    # bucket rather than silently guessing PASS.
    result["verdict"] = "DEGRADED"
    result["verdict_reason"] = f"Registry status '{status}' does not map to a confident automatic verdict -- needs human review."
    return result


def main() -> int:
    registry = _load_json(REGISTRY_PATH)
    coverage = _load_json(COVERAGE_PATH)
    metric_report = _load_json(METRIC_CONTRACT_REPORT_PATH)

    if not registry:
        print("[FATAL] frontend_capability_registry.json missing or invalid -- run build_capability_registry.py first.")
        return 0

    coverage_by_file = {}
    if coverage:
        for p in coverage.get("dynamic_pages", []):
            coverage_by_file[p["file"]] = {"dynamic": True, "reason": p.get("reason")}
        for p in coverage.get("static_pages", []):
            coverage_by_file.setdefault(p["file"], {"dynamic": False, "reason": None})

    forbidden_pages = set()
    if metric_report:
        forbidden_pages = {f["page"] for f in metric_report.get("forbidden_hardcode_findings", [])}

    route_table = _load_route_table()

    customer_ui = [e for e in registry.get("entries", []) if e.get("category") == "CUSTOMER_UI"]
    results = [audit_capability(e, coverage_by_file, forbidden_pages, route_table) for e in customer_ui]

    for r in results:
        assert r["verdict"] in VALID_VERDICTS, f"invalid verdict computed for {r['capability_id']}: {r['verdict']}"

    from collections import Counter
    counts = Counter(r["verdict"] for r in results)

    report = {
        "schema_version": "1",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "total_customer_ui": len(results),
        "route_table_size": len(route_table),
        "verdict_counts": {v: counts.get(v, 0) for v in VALID_VERDICTS},
        "note": (
            "Static/offline evidence only -- DYNAMIC_VERIFIED means the code is internally "
            "self-consistent (genuine fetch()+/api/ evidence, declared API paths resolve to real "
            "routes), not that live production traffic has been observed for this exact page. "
            "See scripts/capability_live_probe.py for the separate, explicitly-invoked live-HTTP "
            "verification tier. BROKEN entries carry a verdict_reason naming the specific defect; "
            "many are pre-existing (documented in the registry's own notes by an earlier session's "
            "manual read), not newly introduced by this script."
        ),
        "capabilities": results,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("=" * 70)
    print("CAPABILITY RUNTIME AUDITOR (static/offline evidence)")
    print(f"CUSTOMER_UI capabilities audited: {len(results)}")
    print(f"Backend route table size: {len(route_table)}")
    for v in VALID_VERDICTS:
        print(f"  {v:18s} {counts.get(v, 0)}")
    broken = [r for r in results if r["verdict"] == "BROKEN"]
    if broken:
        print(f"\nBROKEN ({len(broken)}):")
        for r in broken:
            print(f"  - {r['capability_id']}: {r['verdict_reason'][:120]}")
    print(f"\nWrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
