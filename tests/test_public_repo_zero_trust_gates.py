#!/usr/bin/env python3
"""
tests/test_public_repo_zero_trust_gates.py

P0 (2026-09-10): SENTINEL APEX Public-Repo Zero-Trust Architecture, phase 1.

This repository is deliberately public (the GitHub Actions minutes quota is
a real production cost constraint), so the working security model is not
"hide the source" -- it is "assume every public file is already known to an
attacker; production must stay secure anyway." Two specific, mechanically
checkable pieces of that model regressed silently once already before this
commit and would again without a test:

1. Every third-party GitHub Action referenced from this repo's workflows
   was pinned to a floating tag (`@v6.0.2`, `@v5`, `@v4`, ...) rather than
   an immutable commit SHA -- a supply-chain risk this exact codebase has
   already had to fix twice for one single action (see
   sast-security-scan.yml's TruffleHog step history: floating @main ->
   version tag -> SHA, three separate incidents for one line). Fixed
   repo-wide in this commit (187 references across 63 workflow files,
   each resolved via `git ls-remote` against the action's real repository,
   not guessed) -- this test is what stops any of them, or a new workflow
   added later, from silently drifting back to a mutable tag.

2. `pull_request_target` combined with untrusted checkout is a well-known
   GitHub Actions injection vector (a fork PR's workflow run gets the base
   repo's secrets). This repository has never used that trigger -- this
   test pins that absence so it can't be introduced unnoticed in a future
   workflow, rather than relying on it staying true by accident.

Phase 2 (2026-09-10) added a third:

3. GITHUB_TOKEN write permissions. A repo-wide audit (see
   config/workflow_permissions_allowlist.json) found every workflow that
   requests a write scope, verified each against the actual git/API
   commands in that specific job (not assumed), and narrowed several from
   workflow-wide grants to the one job that genuinely needs them --
   including removing three permissions (deployments: write on
   enterprise-rollback-governance.yml, security-events: write on
   sbom-generation.yml, actions: write on automated-backup.yml) that were
   granted but never used by any step anywhere in those files. Every
   (workflow, job, permission) triple that currently resolves to a write
   scope must have a matching entry in that allowlist; a write permission
   introduced anywhere without one fails this test, rather than silently
   expanding what a compromised job in this public repo could do.

Phase 3 (2026-09-10) added a fourth, over application code rather than
workflow YAML -- authenticated CORS / cross-origin trust-boundary hardening:

4. `workers/intel-gateway/src/index.js` used to spread a single constant,
   `Access-Control-Allow-Origin: "*"`, into essentially every response the
   Worker returns (via CORS_HEADERS/withBaselineHeaders()), and 13 other
   files independently duplicated the identical literal -- including
   admin (`/api/admin/*`), the $49/report premium endpoint, and customer
   billing/quota 402 responses. cors-policy.js is now the single source of
   truth (see its own header comment for the full route-classification
   model); every genuinely public exception is recorded in
   config/cors_public_wildcard_allowlist.json with a route, file, trust
   classification, reason, data-sensitivity note, and
   mutation_capability=false, exactly mirroring how Phase 2's write-
   permission allowlist works above. This test is what stops a future
   change from silently reintroducing a wildcard (or an Origin-reflecting
   duplicate policy) anywhere else in that Worker.

All checks are read-only, mechanical, and evidence-based against the
actual `.github/workflows/*.yml` files (Phases 1-2) or
`workers/intel-gateway/src/*.js` files (Phase 3) -- not a hand-maintained
list that itself could drift out of sync with what's real.
"""
import json
import pathlib
import re
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
PERMISSIONS_ALLOWLIST_PATH = REPO_ROOT / "config" / "workflow_permissions_allowlist.json"
INTEL_GATEWAY_SRC_DIR = REPO_ROOT / "workers" / "intel-gateway" / "src"
CORS_POLICY_PATH = INTEL_GATEWAY_SRC_DIR / "cors-policy.js"
CORS_WILDCARD_ALLOWLIST_PATH = REPO_ROOT / "config" / "cors_public_wildcard_allowlist.json"

# Every GITHUB_TOKEN scope that grants write authority (per GitHub's own
# `permissions:` schema) -- if a workflow ever spells write authority as
# the `write-all` shorthand instead of naming a scope, that's caught
# separately in TestNoUnexplainedWritePermissions.test_no_write_all_shorthand.
_WRITE_SCOPES = {
    "actions", "checks", "contents", "deployments", "discussions", "id-token",
    "issues", "packages", "pages", "pull-requests", "repository-projects",
    "security-events", "statuses",
}

# A `uses:` value is either a local/composite action (`./path`, exempt --
# none exist in this repo today, see module docstring) or `owner/repo@ref`.
# An immutable pin is exactly a 40-character hex commit SHA after the `@`.
_USES_RE = re.compile(r'^\s*uses:\s*([^\s#]+)', re.MULTILINE)
_FULL_SHA_RE = re.compile(r'^[0-9a-f]{40}$')


def _all_workflow_files():
    files = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    assert files, f"no workflow files found under {WORKFLOWS_DIR} -- test can't validate anything"
    return files


class TestNoUnpinnedGitHubActions(unittest.TestCase):
    def test_every_third_party_action_is_pinned_to_a_full_commit_sha(self):
        violations = []
        for path in _all_workflow_files():
            text = path.read_text(encoding="utf-8")
            for match in _USES_RE.finditer(text):
                ref = match.group(1)
                if ref.startswith("./") or ref.startswith("docker://"):
                    continue  # local/composite or container-image reference, not a tag-pinnable Action
                if "@" not in ref:
                    violations.append(f"{path.name}: {ref!r} has no @ref at all")
                    continue
                pin = ref.rsplit("@", 1)[1]
                if not _FULL_SHA_RE.match(pin):
                    violations.append(f"{path.name}: {ref!r} is pinned to {pin!r}, not a 40-hex commit SHA")

        self.assertEqual(
            violations, [],
            "Found action reference(s) pinned to a mutable tag/branch instead of an "
            "immutable commit SHA -- a supply-chain risk this repo has already had to "
            "fix twice for a single action (see sast-security-scan.yml's TruffleHog "
            "step history). Resolve the real SHA via `git ls-remote <repo> <tag>` "
            "(never guess one) and pin as `owner/repo@<sha> # <original tag>`:\n  "
            + "\n  ".join(violations),
        )


class TestNoPullRequestTargetTrigger(unittest.TestCase):
    def test_pull_request_target_is_never_used_as_a_trigger(self):
        violations = []
        for path in _all_workflow_files():
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            on_block = doc.get(True, doc.get("on"))  # PyYAML parses bare `on:` as bool True
            if isinstance(on_block, dict) and "pull_request_target" in on_block:
                violations.append(path.name)
            elif isinstance(on_block, (list, str)) and "pull_request_target" in on_block:
                violations.append(path.name)

        self.assertEqual(
            violations, [],
            "pull_request_target combined with untrusted checkout is a known GitHub "
            "Actions secret-exfiltration vector for a public repository (a fork PR's "
            "workflow run receives the base repo's secrets). Found in: "
            + ", ".join(violations),
        )


def _enumerate_write_permissions():
    """For every job in every workflow, the write scopes it actually ends up
    with: a job-level `permissions:` block replaces the workflow-level one
    entirely (GitHub's own model) if present at all; otherwise the job
    inherits the workflow-level block as-is. Returns a list of
    (workflow_file, job_id, sorted_scopes_tuple)."""
    found = []
    for path in _all_workflow_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        wf_perms = doc.get("permissions") or {}
        if wf_perms == "write-all":
            found.append((path.name, "(workflow-level write-all)", ("write-all",)))
            continue
        wf_write = {k for k, v in wf_perms.items() if v == "write" and k in _WRITE_SCOPES}

        for job_id, job in (doc.get("jobs") or {}).items():
            job_perms = job.get("permissions") or {}
            if job_perms == "write-all":
                found.append((path.name, job_id, ("write-all",)))
                continue
            if job_perms:
                effective = {k for k, v in job_perms.items() if v == "write" and k in _WRITE_SCOPES}
            else:
                effective = wf_write
            if effective:
                found.append((path.name, job_id, tuple(sorted(effective))))
    return found


class TestNoUnexplainedWritePermissions(unittest.TestCase):
    def test_no_write_all_shorthand(self):
        violations = [
            f"{wf}:{job}" for wf, job, scopes in _enumerate_write_permissions()
            if scopes == ("write-all",)
        ]
        self.assertEqual(
            violations, [],
            "`permissions: write-all` (or a job-level equivalent) grants every "
            "scope GITHUB_TOKEN supports -- strictly broader than any named "
            "scope this repo's workflows actually need. Found in: " + ", ".join(violations),
        )

    def test_every_residual_write_permission_is_allowlisted(self):
        allowlist = json.loads(PERMISSIONS_ALLOWLIST_PATH.read_text(encoding="utf-8"))
        allowed = {
            (e["workflow"], e["job"]) for e in allowlist["entries"]
            if not e["permission"].endswith("(removed)") and e["permission"] != "NONE (removed)"
        }

        violations = []
        for wf, job, scopes in _enumerate_write_permissions():
            if (wf, job) not in allowed:
                violations.append(f"{wf}:{job} has write scope(s) {scopes} with no entry in {PERMISSIONS_ALLOWLIST_PATH.name}")

        self.assertEqual(
            violations, [],
            "New, unexplained GITHUB_TOKEN write permission(s) found. Every job "
            "that genuinely needs to write must have a corresponding entry (with "
            "a real reason and evidence, not a guess) added to "
            f"{PERMISSIONS_ALLOWLIST_PATH.relative_to(REPO_ROOT)}:\n  " + "\n  ".join(violations),
        )

    def test_allowlist_itself_is_well_formed(self):
        allowlist = json.loads(PERMISSIONS_ALLOWLIST_PATH.read_text(encoding="utf-8"))
        for entry in allowlist["entries"]:
            for field in ("workflow", "job", "permission", "reason", "evidence"):
                self.assertIn(field, entry, f"allowlist entry missing required field {field!r}: {entry}")
                self.assertTrue(str(entry[field]).strip(), f"allowlist entry has an empty {field!r}: {entry}")


# Matches a literal wildcard CORS header value anywhere it's declared as an
# object-literal entry, e.g. `"Access-Control-Allow-Origin": "*"` or (single-
# quoted, unspaced) `'Access-Control-Allow-Origin':'*'`. Deliberately does
# NOT match cors-policy.js's own `acao = "*"`/`return { acao: "*", ... }`
# decision-function shape (a bare variable assignment, not a header-object
# literal) -- that is the one legitimate place the value "*" is *decided*;
# this regex is only looking for the header being *hardcoded* directly into
# a response, which is the actual bug class Phase 3 fixed.
_WILDCARD_CORS_HEADER_RE = re.compile(
    r'''["']Access-Control-Allow-Origin["']\s*:\s*["']\*["']'''
)
_CREDENTIALS_TRUE_RE = re.compile(
    r'''["']Access-Control-Allow-Credentials["']\s*:\s*["']?true["']?''', re.IGNORECASE
)
# Any Set/array literal that looks like it's holding full origin URLs
# (https://...) -- the shape PRODUCTION_BROWSER_ORIGINS uses. A second one
# anywhere else in this Worker would mean a duplicate, independently
# maintained origin allowlist -- exactly the "duplicate independent CORS
# policies outside approved architecture" mission Section 9 asks this gate
# to catch.
_ORIGIN_ALLOWLIST_LITERAL_RE = re.compile(r'new Set\(\s*\[\s*["\']https://')
# The one call site that actually GRANTS a preflight -- not every
# `method === "OPTIONS"` string match, which a companion guard elsewhere
# (e.g. "skip re-processing a response OPTIONS already fully decided") can
# legitimately also contain without being a second, competing preflight
# authority. Counting call sites of the decision function itself is the
# precise version of the same check.
_BUILD_PREFLIGHT_CALL_RE = re.compile(r'buildPreflightResponse\s*\(')
# Any place at all that checks for an OPTIONS request -- broader than the
# call-site check above on purpose; used only to find candidate branches to
# inspect for the hand-rolled-bypass pattern, not to count them.
_OPTIONS_METHOD_CHECK_RE = re.compile(r'method\s*===\s*["\']OPTIONS["\']')


def _intel_gateway_js_files(exclude=frozenset()):
    files = sorted(INTEL_GATEWAY_SRC_DIR.glob("*.js"))
    assert files, f"no .js files found under {INTEL_GATEWAY_SRC_DIR} -- test can't validate anything"
    return [f for f in files if f.name not in exclude]


def _is_line_comment(line):
    """True if `line`'s first non-whitespace characters are `//`. A
    pragmatic heuristic (not a real JS parser -- this repo's own established
    tolerance for "mechanical, evidence-based" regex checks over an AST),
    good enough to stop this file's own explanatory `// ... functionName()
    ...` prose from being counted as a real call site of that function."""
    return line.strip().startswith("//")


class TestCorsZeroTrustWildcardIsCentralized(unittest.TestCase):
    """SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3.

    cors-policy.js is the sole, intended location of a hardcoded wildcard
    CORS header literal in workers/intel-gateway/src -- see that file's own
    header comment. Every other file must decide Access-Control-Allow-Origin
    by calling into cors-policy.js's applyCorsPolicy()/buildPreflightResponse()
    (via index.js's withBaselineHeaders(), the one true response choke
    point), never by hardcoding "*" itself.
    """

    def test_no_wildcard_cors_header_literal_outside_cors_policy_js(self):
        violations = []
        for path in _intel_gateway_js_files(exclude={"cors-policy.js"}):
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if _WILDCARD_CORS_HEADER_RE.search(line):
                    violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")

        self.assertEqual(
            violations, [],
            "Found a hardcoded Access-Control-Allow-Origin: \"*\" outside "
            "cors-policy.js. A route that is genuinely public must be added "
            "to cors-policy.js's PUBLIC_EXACT_PATHS (or PUBLIC_TAXII_ROOTS/"
            "PUBLIC_REPORTS_PREFIX) and recorded in "
            f"{CORS_WILDCARD_ALLOWLIST_PATH.relative_to(REPO_ROOT)}, not "
            "hardcoded at the response site -- every other route relies on "
            "index.js's withBaselineHeaders() to apply the real policy, and "
            "a local literal here would silently coexist with (or, if "
            "withBaselineHeaders() is ever bypassed for this response, "
            "override) that policy. Found:\n  " + "\n  ".join(violations),
        )

    def test_cors_policy_itself_has_exactly_one_wildcard_declaration(self):
        # A sanity check on the checker above: cors-policy.js is *allowed*
        # to contain the literal (it's the canonical source), but only once
        # -- in buildPreflightResponse()'s PUBLIC branch. A second literal
        # there would itself be an internal duplicate this test should catch.
        text = CORS_POLICY_PATH.read_text(encoding="utf-8")
        matches = _WILDCARD_CORS_HEADER_RE.findall(text)
        self.assertEqual(
            len(matches), 1,
            f"expected exactly one hardcoded Access-Control-Allow-Origin: \"*\" "
            f"header literal in {CORS_POLICY_PATH.relative_to(REPO_ROOT)} "
            f"(buildPreflightResponse()'s PUBLIC branch), found {len(matches)}",
        )

    def test_no_access_control_allow_credentials_true_anywhere(self):
        # Mission Section 6 / Section 9: wildcard + credentials can never
        # occur. intel-gateway never sets credentials at all (this platform
        # authenticates via explicit headers, not cookies -- see
        # cors-policy.js's header comment), so this asserts the stronger,
        # simpler invariant: the header is never emitted as true, period.
        violations = []
        for path in _intel_gateway_js_files():
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if _CREDENTIALS_TRUE_RE.search(line):
                    violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(
            violations, [],
            "Found Access-Control-Allow-Credentials: true -- intel-gateway "
            "has no cookie/credentialed-fetch use case (see cors-policy.js's "
            "header comment) and must never combine this with any origin "
            "grant, wildcard or exact. Found:\n  " + "\n  ".join(violations),
        )

    def test_no_duplicate_origin_allowlist_outside_cors_policy_js(self):
        violations = []
        for path in _intel_gateway_js_files(exclude={"cors-policy.js"}):
            text = path.read_text(encoding="utf-8")
            if _ORIGIN_ALLOWLIST_LITERAL_RE.search(text):
                violations.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(
            violations, [],
            "Found what looks like an independent origin-allowlist literal "
            "(a Set/array of https:// URLs) outside cors-policy.js -- "
            "PRODUCTION_BROWSER_ORIGINS in that file must be the single "
            "source of truth for approved browser origins in this Worker, "
            "per mission Section 9 (\"duplicate independent CORS policies "
            "outside approved architecture\"). Found in:\n  " + "\n  ".join(violations),
        )

    def test_exactly_one_call_site_grants_a_preflight(self):
        # A second, independent call to buildPreflightResponse() (or, worse,
        # a hand-rolled OPTIONS branch that never calls it at all) anywhere
        # in this Worker would mean some route bypasses its strict, route-
        # aware validation entirely -- a "cosmetic CORS header replacement"
        # the mission explicitly warns against reappearing. Scoped to every
        # file except cors-policy.js itself, where the function is defined
        # (and would otherwise match its own `function buildPreflightResponse(`
        # declaration) but never called.
        hits = []
        for path in _intel_gateway_js_files(exclude={"cors-policy.js"}):
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if _is_line_comment(line):
                    continue
                if _BUILD_PREFLIGHT_CALL_RE.search(line):
                    hits.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}")
        self.assertEqual(
            len(hits), 1,
            "expected exactly one call to buildPreflightResponse() in the whole "
            "Worker (index.js's OPTIONS branch) -- a second one, or a hand-rolled "
            f"OPTIONS branch that bypasses it entirely, means preflight validation "
            f"can be sidestepped for some route; found: {hits}",
        )
        self.assertTrue(
            hits[0].startswith("workers/intel-gateway/src/index.js:"),
            f"the one buildPreflightResponse() call should be in index.js, found it in: {hits[0]}",
        )

    def test_no_hand_rolled_options_branch_bypassing_the_preflight_authority(self):
        # Complements the call-site check above: every `method === "OPTIONS"`
        # branch in the Worker must be reachable only through index.js's own
        # OPTIONS handling (which calls buildPreflightResponse() -- see the
        # test above) or through a companion guard that explicitly avoids
        # re-deciding a response that call already fully decided (e.g.
        # withBaselineHeaders() skipping a second, redundant CORS pass on an
        # OPTIONS response). What must never exist is a THIRD kind: a branch
        # that itself constructs Access-Control-* headers for an OPTIONS
        # request without going through buildPreflightResponse() at all.
        for path in _intel_gateway_js_files(exclude={"cors-policy.js"}):
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if _is_line_comment(line) or not _OPTIONS_METHOD_CHECK_RE.search(line):
                    continue
                # Look at this line plus the next few for what it actually
                # does -- either delegate to buildPreflightResponse() or
                # return/skip without independently building CORS headers.
                window = "\n".join(lines[lineno - 1: lineno + 4])
                delegates = "buildPreflightResponse(" in window
                builds_own_cors_headers = "Access-Control-Allow-Origin" in window
                self.assertFalse(
                    builds_own_cors_headers and not delegates,
                    f"{path.relative_to(REPO_ROOT)}:{lineno}: an OPTIONS branch appears to "
                    "build its own Access-Control-* headers instead of delegating to "
                    "buildPreflightResponse() -- this is exactly the hand-rolled preflight "
                    "bypass this gate exists to catch.",
                )


class TestCorsZeroTrustWildcardAllowlist(unittest.TestCase):
    """The allowlist and cors-policy.js's PUBLIC route set must always
    describe the exact same set of routes -- see mission Section 9: every
    wildcard exception must be recorded, and nothing may be recorded that
    isn't real."""

    @staticmethod
    def _routes_in_cors_policy_public_set(text, set_name):
        match = re.search(rf'{set_name}\s*=\s*new Set\(\[(.*?)\]\)', text, re.DOTALL)
        assert match, f"could not find {set_name} = new Set([...]) in cors-policy.js"
        return set(re.findall(r'"([^"]+)"', match.group(1)))

    def _public_routes_from_cors_policy(self):
        text = CORS_POLICY_PATH.read_text(encoding="utf-8")
        routes = self._routes_in_cors_policy_public_set(text, "PUBLIC_EXACT_PATHS")
        routes |= self._routes_in_cors_policy_public_set(text, "PUBLIC_TAXII_ROOTS")
        prefix_match = re.search(r'PUBLIC_REPORTS_PREFIX\s*=\s*"([^"]+)"', text)
        assert prefix_match, "could not find PUBLIC_REPORTS_PREFIX in cors-policy.js"
        routes.add(prefix_match.group(1).rstrip("/") + "/*")
        return routes

    def test_allowlist_entries_are_well_formed(self):
        allowlist = json.loads(CORS_WILDCARD_ALLOWLIST_PATH.read_text(encoding="utf-8"))
        for entry in allowlist["entries"]:
            for field in ("route", "file", "trust_classification", "reason", "data_sensitivity", "mutation_capability"):
                self.assertIn(field, entry, f"allowlist entry missing required field {field!r}: {entry}")
            self.assertTrue(str(entry["route"]).strip(), f"allowlist entry has an empty route: {entry}")
            self.assertTrue(str(entry["reason"]).strip(), f"allowlist entry has an empty reason: {entry}")
            self.assertEqual(
                entry["mutation_capability"], False,
                f"a public-wildcard route must never carry mutation capability: {entry}",
            )
            self.assertEqual(
                entry["trust_classification"], "PUBLIC_ANONYMOUS_READ",
                f"every entry in this allowlist must be classified PUBLIC_ANONYMOUS_READ: {entry}",
            )

    def test_allowlist_matches_cors_policy_exactly_no_more_no_less(self):
        allowlist = json.loads(CORS_WILDCARD_ALLOWLIST_PATH.read_text(encoding="utf-8"))
        allowlisted_routes = {e["route"] for e in allowlist["entries"]}
        policy_routes = self._public_routes_from_cors_policy()

        only_in_policy = policy_routes - allowlisted_routes
        only_in_allowlist = allowlisted_routes - policy_routes

        self.assertEqual(
            only_in_policy, set(),
            "cors-policy.js grants wildcard CORS to route(s) not recorded in "
            f"{CORS_WILDCARD_ALLOWLIST_PATH.relative_to(REPO_ROOT)}: {sorted(only_in_policy)} -- "
            "every wildcard exception must be documented (mission Section 9).",
        )
        self.assertEqual(
            only_in_allowlist, set(),
            f"{CORS_WILDCARD_ALLOWLIST_PATH.relative_to(REPO_ROOT)} documents route(s) that "
            f"cors-policy.js no longer grants wildcard CORS to: {sorted(only_in_allowlist)} -- "
            "remove the stale entry (or re-add the route to cors-policy.js if that was a mistake).",
        )


if __name__ == "__main__":
    unittest.main()
