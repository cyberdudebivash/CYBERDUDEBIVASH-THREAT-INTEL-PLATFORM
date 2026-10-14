#!/usr/bin/env python3
"""
scripts/tlp_public_boundary.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- last-mile TLP enforcement for anonymously served artifacts (P0 #721/#725)
==============================================================================================================
`tlp_policy.publication_decision()` is the single authority.  This module applies it to *finished bytes* at the
boundaries where producer-side filtering cannot be trusted to have run:

  * `sanitize_document()` / `sanitize_json_file()` -- JSON documents bound for R2 or GitHub Pages.
  * `sanitize_dist()`                              -- the Pages deploy artifact (dist/): sanitizes every JSON
                                                      document and removes report pages that are denied.
  * `inventory_tree()`                             -- READ-ONLY measurement; never writes or deletes.

Rules (fail closed; no bypass flag):
  * A record is any dict carrying a `tlp`/`tlp_label` key, or a `title` plus an advisory marker key.  A record the
    policy denies (restricted / missing / invalid / unmigrated-legacy label, restricted upstream evidence) is
    removed from the list that holds it.  Sibling `count`/`total` fields that matched the old length are updated.
  * A document whose own `classification`/`tlp` states a restricted TLP is withheld entirely and replaced by a
    tombstone (valid JSON, no content) so stale restricted bytes cannot keep being served.
  * Unparseable JSON cannot be verified: it is reported and never silently passed as "clean".
  * Rows returned/logged carry ids and reason codes only -- never report bodies or IOC values.

Residual limits (documented, not hidden):
  * A record without any label key and without advisory markers is not a "record" here and passes through.
  * Graph edges that reference a removed node id are not rewritten.
  * Cached copies already held by CDN/KV/browsers are outside this module (see the retraction runbook).
(c) 2026 CyberDudeBivash Pvt. Ltd.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import tlp_policy  # noqa: E402

log = logging.getLogger("sentinel.tlp_boundary")

REPO_ROOT = _SCRIPTS_DIR.parent
# Match the Worker publicTlpJsonVerified() advisory identity markers.
# An unlabeled {"id","title"} child cannot silently survive the Python
# writer and then make the Worker return a customer-facing HTTP 503.
ADVISORY_MARKERS = frozenset({"id", "advisory_id", "intel_id", "report_url", "internal_report_url", "cve_id", "stix_id", "cve_ids", "threat_id", "bundle_id"})
DOC_LABEL_KEYS = ("classification", "tlp", "tlp_label")
COUNT_KEYS = ("count", "total", "total_count", "advisory_count", "item_count")
MAX_DEPTH = 40
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,200}$")
HTML_HEAD_BYTES = 65536

DENY_RESTRICTED = frozenset({"RESTRICTED_LABEL", "RESTRICTED_UPSTREAM_LABEL", "INVALID_LABEL", "LEGACY_LABEL_UNMIGRATED",
                             "RESTRICTED_REPORT_PAGE"})


class BoundaryError(ValueError):
    """The document could not be verified (unparseable / unexpected shape)."""


def tombstone(reason_code: str) -> Dict[str, Any]:
    return {"tlp_boundary": {"withheld": True, "reason_code": reason_code,
                             "policy": "config/tlp_publication_policy.json"}}


def is_record(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    if "tlp" in obj or "tlp_label" in obj:
        return True
    return "title" in obj and bool(ADVISORY_MARKERS & obj.keys())


def _short_id(obj: Dict[str, Any]) -> Optional[str]:
    v = obj.get("id") or obj.get("intel_id") or obj.get("node_id")
    return str(v)[:120] if v is not None else None


def _judge_tokens(tokens: List[str], policy: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """None when the markings are one unambiguous publishable label; else (reason_code, reason).  The FIRST marking
    never decides: any restriction, unrecognised marking or disagreement between markings denies."""
    distinct = set(tokens)
    if distinct == {"TLP:CLEAR"}:
        return None
    if distinct == {"TLP:WHITE"} and policy.get("legacy_white_treated_as_clear"):
        return None
    if "INVALID" in distinct:
        return "INVALID_LABEL", "an unrecognised TLP marking is present"
    if len(distinct) > 1:
        return "CONFLICTING_CLASSIFICATION", "the document carries conflicting TLP markings"
    if distinct == {"TLP:WHITE"}:
        return "LEGACY_LABEL_UNMIGRATED", "TLP:WHITE (TLP v1) has not been migrated by the operator"
    return "RESTRICTED_DOCUMENT", "the document states a restricted TLP"


def document_level_denial(doc: Any, policy: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """(reason_code, reason) when a document declares its OWN restricted / invalid / conflicting classification."""
    if not isinstance(doc, dict):
        return None
    for key in DOC_LABEL_KEYS:
        val = doc.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            continue
        toks = tlp_policy.scan_tlp_tokens(val)
        if key == "classification":
            if not toks:
                continue  # a classification string that never mentions TLP is not a TLP declaration
        else:
            exact = tlp_policy.parse_label(val)  # tlp / tlp_label hold exactly one label, nothing else
            if exact["status"] == tlp_policy.VALID and exact["label"] == "TLP:CLEAR":
                continue
            if exact["status"] == tlp_policy.LEGACY and policy.get("legacy_white_treated_as_clear"):
                continue
            toks = toks or ["INVALID"]
        verdict = _judge_tokens(toks, policy)
        if verdict:
            return verdict[0], f"document {key}: {verdict[1]}"
    return None

def _decide(rec: Dict[str, Any], policy: Dict[str, Any], parents: Optional[Dict[str, Dict[str, Any]]],
            id_hint: Optional[str] = None) -> Dict[str, Any]:
    """Decision for one record.  A record with its OWN label key is judged on that label.  An unlabelled record
    (e.g. a per-advisory detection bundle) inherits the verified decision of the parent advisory with the same
    id -- it can never be MORE permissive than the parent; with no verified parent it stays MISSING_LABEL."""
    if parents:
        forced = parents.get(str(rec.get("id"))) if rec.get("id") is not None else None
        if forced and forced.get("force"):  # e.g. the published page contradicts the record's own label
            return forced
    if parents and "tlp" not in rec and "tlp_label" not in rec:
        for cand in (rec.get("id"), rec.get("intel_id"), id_hint):
            if cand is not None and str(cand) in parents:
                d = dict(parents[str(cand)])
                d["inherited_from_parent"] = True
                return d
    return tlp_policy.publication_decision(rec, policy)


def _walk(node: Any, path: str, policy: Dict[str, Any], removed: List[Dict[str, Any]], depth: int,
          parents: Optional[Dict[str, Dict[str, Any]]] = None) -> Any:
    if depth > MAX_DEPTH:
        raise BoundaryError("document nesting exceeds the verifiable depth; refusing to pass it as clean")
    if isinstance(node, list):
        out = []
        for i, el in enumerate(node):
            if is_record(el):
                d = _decide(el, policy, parents)
                if not d["allowed"]:
                    removed.append({"id": _short_id(el), "reason_code": d["reason_code"], "path": f"{path}[{i}]"})
                    continue
            out.append(_walk(el, f"{path}[{i}]", policy, removed, depth + 1, parents))
        return out
    if isinstance(node, dict):
        # P0 #725: a nested dict keyed by field name is just as capable of
        # carrying restricted content as a list element. Previously only
        # list elements and the document root were classified, allowing
        # {"report": {"tlp":"TLP:RED","title":"..."}} through unchanged.
        # Keep the root decision in sanitize_document() so callers receive
        # its existing withheld status; nested denied dicts become safe
        # tombstones with id/reason metadata, never their original bytes.
        if depth > 0:
            restriction = document_level_denial(node, policy)
            if restriction:
                removed.append({"id": _short_id(node), "reason_code": restriction[0], "path": path})
                return tombstone(restriction[0])
            if is_record(node):
                nested_decision = _decide(node, policy, parents)
                if not nested_decision["allowed"]:
                    removed.append({"id": _short_id(node), "reason_code": nested_decision["reason_code"], "path": path})
                    return tombstone(nested_decision["reason_code"])
        out_d: Dict[str, Any] = {}
        shrunk: Dict[str, Tuple[int, int]] = {}
        for k, v in node.items():
            nv = _walk(v, f"{path}.{k}", policy, removed, depth + 1, parents)
            if isinstance(v, list) and isinstance(nv, list) and len(nv) != len(v):
                shrunk[k] = (len(v), len(nv))
            out_d[k] = nv
        if shrunk:
            olds = {o for o, _n in shrunk.values()}
            news = {n for _o, n in shrunk.values()}
            if len(shrunk) == 1:
                (old, new), = shrunk.values()
                for ck in COUNT_KEYS:
                    if isinstance(out_d.get(ck), int) and not isinstance(out_d.get(ck), bool) and out_d[ck] == old:
                        out_d[ck] = new
            elif len(olds) == 1 and len(news) == 1:
                old, new = next(iter(olds)), next(iter(news))
                for ck in COUNT_KEYS:
                    if isinstance(out_d.get(ck), int) and out_d[ck] == old:
                        out_d[ck] = new
        return out_d
    return node


def sanitize_document(doc: Any, policy: Optional[Dict[str, Any]] = None,
                      parents: Optional[Dict[str, Dict[str, Any]]] = None, id_hint: Optional[str] = None
                      ) -> Tuple[Any, List[Dict[str, Any]], Optional[Tuple[str, str]]]:
    """Return (sanitized document, removed rows, withheld) -- `withheld` is (code, reason) when the whole document
    is denied, in which case the returned document is a tombstone."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    denial = document_level_denial(doc, pol)
    if denial:
        return tombstone(denial[0]), [], denial
    removed: List[Dict[str, Any]] = []
    if is_record(doc):  # a single top-level record
        d = _decide(doc, pol, parents, id_hint)
        if not d["allowed"]:
            removed.append({"id": _short_id(doc), "reason_code": d["reason_code"], "path": "$"})
            return tombstone(d["reason_code"]), removed, (d["reason_code"], d["reason"])
    return _walk(doc, "$", pol, removed, 0, parents), removed, None


def sanitize_json_file(src: Path, dst: Path, policy: Optional[Dict[str, Any]] = None,
                       parents: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Write a sanitized copy of `src` to `dst` (never modifies `src`). Raises BoundaryError if unverifiable."""
    try:
        doc = json.loads(Path(src).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BoundaryError(f"cannot verify {Path(src).name} for TLP publication") from exc
    out, removed, withheld = sanitize_document(doc, policy, parents, id_hint=Path(src).stem)
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return {"removed": removed, "withheld": withheld is not None,
            "withheld_reason_code": withheld[0] if withheld else None}


def build_parent_index(sources: Iterable[Path], policy: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Dict[str, Any]]:
    """id -> publication decision for every record in the given advisory feeds/manifests (unreadable ones skipped).
    When an id appears in several sources the MOST RESTRICTIVE outcome wins (a denial anywhere denies)."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    idx: Dict[str, Dict[str, Any]] = {}
    for src in sources:
        try:
            doc = json.loads(Path(src).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        items = doc if isinstance(doc, list) else (
            next((doc[k] for k in ("items", "advisories", "entries", "data") if isinstance(doc.get(k), list)), [])
            if isinstance(doc, dict) else [])
        for it in items:
            if not isinstance(it, dict) or it.get("id") is None:
                continue
            d = tlp_policy.publication_decision(it, pol)
            if not d["allowed"] and d["reason_code"] in DENY_RESTRICTED:
                d = dict(d, force=True)  # restricted anywhere -> restricted everywhere (see _decide)
            key = str(it["id"])
            if key not in idx or (idx[key]["allowed"] and not d["allowed"]) or (
                    not idx[key]["allowed"] and not idx[key].get("force") and d.get("force")):
                idx[key] = d
    return idx


# ── workspace (CI runner checkout, immediately before the Pages artifact is built) ─────────────────────────────
WORKSPACE_ROOT_FILES = ("feed.json", "latest.json", "manifest.json", "feed_manifest.json")
WORKSPACE_PARENT_FILES = ("api/feed.json", "data/feed_manifest.json", "data/stix/feed_manifest.json")


def sanitize_workspace(root: Path, policy: Optional[Dict[str, Any]] = None, dry_run: bool = False) -> Dict[str, Any]:
    """Sanitize, IN PLACE, the public JSON the Pages artifact is built from: api/**/*.json and the root-level feed
    files.  Run on a CI runner checkout right before dist/ is built so that every later consumer of the feed
    (report_url validation, dist verifier, regression T21, canaries) sees exactly the set that is published --
    publishing and verification can then never disagree about which reports must exist.  Not run on `data/`:
    internal manifests and state keep every record.  Returns counts and the ids of restricted records removed."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    root = Path(root)
    parents = build_parent_index([root / r for r in WORKSPACE_PARENT_FILES], pol)  # BEFORE any file is changed
    # A record the feed calls publishable whose OWN report page states a restricted TLP is contradictory: fail
    # closed (the record is removed and, below, the page never ships) rather than trusting either label.
    need = {i for i, d in parents.items() if d["allowed"]}
    if need and (root / "reports").is_dir():
        for dp, _dn, fns in os.walk(root / "reports"):
            for fn in fns:
                if fn.endswith(".html") and fn[:-5] in need and html_declares_restricted_tlp(Path(dp) / fn):
                    parents[fn[:-5]] = {"allowed": False, "state": "QUARANTINE", "label": "", "assignment": None,
                                        "reason_code": "RESTRICTED_REPORT_PAGE", "force": True,
                                        "reason": "the report page states a restricted TLP that contradicts the feed record"}
    targets = sorted((root / "api").rglob("*.json")) if (root / "api").is_dir() else []
    targets += [root / n for n in WORKSPACE_ROOT_FILES if (root / n).is_file()]
    rep: Dict[str, Any] = {"dry_run": dry_run, "files_scanned": 0, "files_modified": 0, "files_withheld": 0,
                           "records_removed": 0, "unverifiable_json": [], "denied_ids": [], "files": []}
    # Pass 1 -- most-restrictive-wins ACROSS documents: an advisory id that any public document labels restricted
    # (or whose page contradicts its label) is denied in every document, so one advisory can never be CLEAR in
    # the feed yet RESTRICTED in another writer's file.
    for jf in targets:
        if not jf.is_file():
            continue
        try:
            doc = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        _o, removed1, _w = sanitize_document(doc, pol, parents, id_hint=jf.stem)
        for row in removed1:
            if row.get("id") and row.get("reason_code") in DENY_RESTRICTED and row["id"] not in parents:
                parents[row["id"]] = {"allowed": False, "state": "QUARANTINE", "label": "", "assignment": None,
                                      "reason_code": "RESTRICTED_LABEL", "force": True,
                                      "reason": "labelled restricted in another public document"}
            elif row.get("id") and row.get("reason_code") in DENY_RESTRICTED and parents[row["id"]]["allowed"]:
                parents[row["id"]] = {"allowed": False, "state": "QUARANTINE", "label": "", "assignment": None,
                                      "reason_code": "RESTRICTED_LABEL", "force": True,
                                      "reason": "labelled restricted in another public document"}
    denied = set()
    for jf in targets:
        if not jf.is_file():
            continue
        rel = jf.relative_to(root).as_posix()
        rep["files_scanned"] += 1
        try:
            doc = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rep["unverifiable_json"].append(rel)
            continue
        out, removed, withheld = sanitize_document(doc, pol, parents, id_hint=jf.stem)
        if not removed and not withheld:
            continue
        for row in removed:
            if row.get("id") and row.get("reason_code") in DENY_RESTRICTED:
                denied.add(row["id"])
        rep["files_modified"] += 1
        rep["files_withheld"] += 1 if withheld else 0
        rep["records_removed"] += len(removed)
        rep["files"].append({"path": rel, "removed": len(removed), "withheld": bool(withheld),
                             "reason_codes": sorted({r["reason_code"] for r in removed} |
                                                    ({withheld[0]} if withheld else set()))})
        if not dry_run:
            jf.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    rep["denied_ids"] = sorted(denied)
    return rep


# ── dist/ (GitHub Pages artifact) ───────────────────────────────────────────────────────────────────────────────
def _report_paths_for_id(dist: Path, intel_id: str) -> List[Path]:
    """Paths of report HTML/PDF files for an id inside dist/reports/ -- id is validated, never joined raw."""
    if not _SAFE_ID_RE.match(intel_id):
        return []
    root = dist / "reports"
    if not root.is_dir():
        return []
    hits = [p for p in root.rglob(f"{intel_id}.html")] + [p for p in root.rglob(f"{intel_id}.pdf")]
    return [p for p in hits if root.resolve() in p.resolve().parents]


_ATTR_CLASS = re.compile(r"""class\s*=\s*(['"])(.*?)\1""", re.IGNORECASE | re.DOTALL)
_CLASS_LABEL = re.compile(r"\btlp[-_ ]{0,2}(clear|white|green|amber[-_ ]?strict|amber|red)\b", re.IGNORECASE)
_META_TAG = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_META_NAME = re.compile(r"""name\s*=\s*['"]?(tlp|tlp[-_]label|classification)\b""", re.IGNORECASE)
_META_CONTENT = re.compile(r"""content\s*=\s*(['"])(.*?)\1""", re.IGNORECASE | re.DOTALL)
_DATA_TLP = re.compile(r"""data-tlp\s*=\s*(['"])(.*?)\1""", re.IGNORECASE | re.DOTALL)
_TLP_ELEMENT = re.compile(r"""<(\w+)\b[^>]*class\s*=\s*['"][^'"]*\b(?:tlp|sev-chip)[^'"]*['"][^>]*>(.*?)</\1\s*>""",
                          re.IGNORECASE | re.DOTALL)
_KV_LABEL = re.compile(r"TLP\s*Label\s*</[^>]*>\s*<[^>]*>\s*([^<]*)", re.IGNORECASE)
_TITLE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_TAGS = re.compile(r"<[^>]+>")


def _canon_class_label(word: str) -> str:
    p = tlp_policy.parse_label("TLP:" + re.sub(r"[-_ ]", "", word.upper()).replace("AMBERSTRICT", "AMBER+STRICT"))
    return p["label"] if p["status"] in (tlp_policy.VALID, tlp_policy.LEGACY) else "INVALID"


def classify_html_head(head: str) -> Dict[str, Any]:
    """Assess the TLP a report page states.  `authoritative` = markings in metadata/badge contexts (class names,
    <meta>, data-tlp, the 'TLP Label' row, elements classed tlp-* / sev-chip, <title>); `prose` = markings anywhere
    else.  An explicit restricted marking is never cancelled by a CLEAR elsewhere:
      * any non-CLEAR authoritative marking            -> restricted (a CLEAR beside it is a CONFLICT, still restricted)
      * no authoritative marking found at all          -> any non-CLEAR marking anywhere restricts the page
      * authoritative markings all CLEAR               -> a restricted word in running prose is an incidental mention
    Unparseable / look-alike markings count as non-CLEAR."""
    import html as _html
    t = _html.unescape(tlp_policy.normalize_label_text(head))
    auth: List[str] = []
    for m in _ATTR_CLASS.finditer(t):
        auth += [_canon_class_label(x) for x in _CLASS_LABEL.findall(m.group(2))]
    for tag in _META_TAG.findall(t):
        if _META_NAME.search(tag):
            c = _META_CONTENT.search(tag)
            auth += (tlp_policy.scan_tlp_tokens(c.group(2)) or [_canon_class_label(c.group(2).strip())]) if c else ["INVALID"]
    for m in _DATA_TLP.finditer(t):
        auth += tlp_policy.scan_tlp_tokens(m.group(2)) or [_canon_class_label(m.group(2).strip())]
    for m in _TLP_ELEMENT.finditer(t):
        auth += tlp_policy.scan_tlp_tokens(_TAGS.sub(" ", m.group(2)))
    for m in _KV_LABEL.finditer(t):
        auth += tlp_policy.scan_tlp_tokens(m.group(1)) or ["INVALID"]
    for m in _TITLE.finditer(t):
        auth += tlp_policy.scan_tlp_tokens(_TAGS.sub(" ", m.group(1)))
    prose_src = re.sub(r"<(script|style)\b.*?</\1\s*>", " ", t, flags=re.IGNORECASE | re.DOTALL)  # CSS/JS are not claims
    anywhere = tlp_policy.scan_tlp_tokens(_TAGS.sub(" ", prose_src), lenient=True) + auth
    non_clear_auth = [x for x in auth if x != "TLP:CLEAR"]
    if non_clear_auth:
        restricted, labels = True, non_clear_auth
    elif not auth:
        labels = [x for x in anywhere if x != "TLP:CLEAR"]
        restricted = bool(labels)
    else:
        restricted, labels = False, []
    return {"restricted": restricted, "labels": labels, "authoritative": auth}


def _read_head(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            return fh.read(HTML_HEAD_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def html_declares_restricted_tlp(path: Path) -> bool:
    """True when a report page states a restricted/invalid/conflicting TLP (see classify_html_head)."""
    head = _read_head(path)
    return bool(head is not None and classify_html_head(head)["restricted"])


def sanitize_dist(dist: Path, policy: Optional[Dict[str, Any]] = None, dry_run: bool = False,
                  extra_denied_ids: Iterable[str] = (), parent_sources: Optional[Iterable[Path]] = None
                  ) -> Dict[str, Any]:
    """Make dist/ safe for anonymous GitHub Pages delivery. Operates on dist/ only -- never on repo sources."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    dist = Path(dist)
    report: Dict[str, Any] = {"dry_run": dry_run, "json_files_scanned": 0, "json_files_modified": 0,
                              "json_files_withheld": 0, "records_removed": 0, "unverifiable_json": [],
                              "report_files_removed": 0, "report_pages_scanned": 0, "files": []}
    denied_ids = {str(i) for i in extra_denied_ids}
    # parent advisories: dist's own feed (pre-sanitization) plus the working-tree manifests, when present
    srcs = [dist / "api" / "feed.json"] + list(parent_sources if parent_sources is not None else [
        REPO_ROOT / "data" / "feed_manifest.json", REPO_ROOT / "data" / "stix" / "feed_manifest.json"])
    parents = build_parent_index(srcs, pol)
    report["parent_index_size"] = len(parents)
    # Scope = the advisory-derived public data: api/** and the root feed files (same set as sanitize_workspace).
    # First-party static content elsewhere in dist/ (blog/, dashboard/, version.json, ...) is not advisory data
    # and must not carry advisory records; a new directory that does needs to be added here.
    scan = sorted((dist / "api").rglob("*.json")) if (dist / "api").is_dir() else []
    scan += [dist / n for n in WORKSPACE_ROOT_FILES if (dist / n).is_file()]
    for jf in scan:
        if not jf.is_file():
            continue
        rel = jf.relative_to(dist).as_posix()
        report["json_files_scanned"] += 1
        try:
            doc = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report["unverifiable_json"].append(rel)
            continue
        out, removed, withheld = sanitize_document(doc, pol, parents, id_hint=jf.stem)
        if not removed and not withheld:
            continue
        for row in removed:
            if row.get("id") and row.get("reason_code") in DENY_RESTRICTED:
                denied_ids.add(row["id"])
        report["records_removed"] += len(removed)
        report["json_files_modified"] += 1
        report["json_files_withheld"] += 1 if withheld else 0
        report["files"].append({"path": rel, "removed": len(removed), "withheld": bool(withheld),
                                "reason_codes": sorted({r["reason_code"] for r in removed} |
                                                       ({withheld[0]} if withheld else set()))})
        if not dry_run:
            jf.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    # report pages: denied ids first, then pages that declare a restricted TLP themselves
    removed_pages: List[Path] = []
    for iid in sorted(denied_ids):
        removed_pages.extend(_report_paths_for_id(dist, iid))
    reports_root = dist / "reports"
    if reports_root.is_dir():
        for page in reports_root.rglob("*.html"):
            report["report_pages_scanned"] += 1
            if html_declares_restricted_tlp(page):
                removed_pages.append(page)
    unique = sorted(set(removed_pages))
    report["report_files_removed"] = len(unique)
    report["denied_ids"] = len(denied_ids)
    if not dry_run:
        for p in unique:
            try:
                p.unlink()
            except OSError as exc:  # leaving a denied page in place must be loud, never silent
                raise BoundaryError(f"could not remove denied report from dist: {p.name}") from exc
    return report


def sanitize_tree(root: Path, policy: Optional[Dict[str, Any]] = None, dry_run: bool = False,
                  parent_sources: Optional[Iterable[Path]] = None) -> Dict[str, Any]:
    """Sanitize IN PLACE every *.json under `root` -- for a STAGED publish folder whose whole content is bound for an
    anonymous destination (e.g. a gh-pages `.publish/` directory). Unverifiable JSON is reported, never passed as clean."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    root = Path(root)
    srcs = list(parent_sources) if parent_sources is not None else [
        REPO_ROOT / r for r in WORKSPACE_PARENT_FILES]
    parents = build_parent_index(srcs, pol)
    rep: Dict[str, Any] = {"dry_run": dry_run, "files_scanned": 0, "files_modified": 0, "files_withheld": 0,
                           "records_removed": 0, "unverifiable_json": []}
    for jf in sorted(root.rglob("*.json")):
        if not jf.is_file():
            continue
        rep["files_scanned"] += 1
        try:
            doc = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rep["unverifiable_json"].append(jf.relative_to(root).as_posix())
            continue
        out, removed, withheld = sanitize_document(doc, pol, parents, id_hint=jf.stem)
        if not removed and not withheld:
            continue
        rep["files_modified"] += 1
        rep["files_withheld"] += 1 if withheld else 0
        rep["records_removed"] += len(removed)
        if not dry_run:
            jf.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return rep


# ── read-only inventory (Phase 4) ───────────────────────────────────────────────────────────────────────────────
def inventory_tree(root: Path, subdirs: Iterable[str] = ("api", "reports"), policy: Optional[Dict[str, Any]] = None
                   ) -> Dict[str, Any]:
    """Count (never read out) restricted material under `root`. Performs no write, delete or network call."""
    pol = policy if policy is not None else tlp_policy.load_policy()
    root = Path(root)
    inv: Dict[str, Any] = {"json": [], "report_pages": {"scanned": 0, "restricted_badge": 0, "by_label": {}}}
    for sd in subdirs:
        base = root / sd
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.json")):
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                inv["json"].append({"path": p.relative_to(root).as_posix(), "status": "UNVERIFIABLE"})
                continue
            _out, removed, withheld = sanitize_document(doc, pol)
            if removed or withheld:
                inv["json"].append({"path": p.relative_to(root).as_posix(), "status": "CONTAINS_DENIED",
                                    "records_denied": len(removed), "document_withheld": bool(withheld),
                                    "reason_codes": sorted({r["reason_code"] for r in removed} |
                                                           ({withheld[0]} if withheld else set()))})
        if sd == "reports":
            for page in base.rglob("*.html"):
                inv["report_pages"]["scanned"] += 1
                head = _read_head(page)
                if head is None:
                    continue
                verdict = classify_html_head(head)
                if verdict["restricted"]:
                    inv["report_pages"]["restricted_badge"] += 1
                    for lab in sorted(set(verdict["labels"])):
                        inv["report_pages"]["by_label"][lab] = inv["report_pages"]["by_label"].get(lab, 0) + 1
    return inv


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dist", type=Path, help="sanitize this dist/ directory in place")
    ap.add_argument("--inventory", type=Path, help="READ-ONLY inventory of a checkout/dist root")
    ap.add_argument("--workspace", type=Path, help="sanitize this checkout's public JSON IN PLACE (CI runner only)")
    ap.add_argument("--tree", type=Path, help="sanitize EVERY *.json under this staged publish folder IN PLACE")
    ap.add_argument("--sanitize-file", type=Path, help="write a sanitized copy of this JSON file to --out-file")
    ap.add_argument("--out-file", type=Path, help="destination for --sanitize-file")
    ap.add_argument("--dry-run", action="store_true", help="with --dist: report only, change nothing")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any JSON under api/ could not be verified")
    ap.add_argument("--out", type=Path, help="write the JSON report here (ids/reason codes only)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [tlp_boundary] %(levelname)s: %(message)s")
    if sum(bool(x) for x in (args.dist, args.inventory, args.workspace, args.tree, args.sanitize_file)) != 1:
        ap.error("exactly one of --dist / --inventory / --workspace / --tree / --sanitize-file is required")
    if args.sanitize_file:
        if not args.out_file:
            ap.error("--sanitize-file requires --out-file")
        try:
            res = sanitize_json_file(args.sanitize_file, args.out_file, parents=build_parent_index(
                [REPO_ROOT / r for r in WORKSPACE_PARENT_FILES]))
        except BoundaryError as exc:
            log.critical("%s", exc)
            return 1
        log.warning("TLP boundary: %s -> %s: %d record(s) removed%s", args.sanitize_file.name, args.out_file.name,
                    len(res["removed"]), ", document replaced by tombstone" if res["withheld"] else "")
        return 0
    if args.tree:
        rep = sanitize_tree(args.tree, dry_run=args.dry_run)
        rc = 1 if rep["unverifiable_json"] else 0  # a staged publish folder must be fully verifiable
        log.warning("TLP tree boundary: %d file(s) modified (%d withheld), %d record(s) removed, %d unverifiable%s",
                    rep["files_modified"], rep["files_withheld"], rep["records_removed"], len(rep["unverifiable_json"]),
                    " (dry-run)" if args.dry_run else "")
    elif args.workspace:
        rep = sanitize_workspace(args.workspace, dry_run=args.dry_run)
        bad = [p for p in rep["unverifiable_json"] if p.startswith("api/")]
        rc = 1 if (args.strict and bad) else 0
        log.warning("TLP workspace boundary: %d file(s) modified (%d withheld), %d record(s) removed, %d unverifiable%s",
                    rep["files_modified"], rep["files_withheld"], rep["records_removed"], len(rep["unverifiable_json"]),
                    " (dry-run)" if args.dry_run else "")
    elif args.inventory:
        rep = inventory_tree(args.inventory)
        rc = 0
    else:
        try:
            rep = sanitize_dist(args.dist, dry_run=args.dry_run)
        except BoundaryError as exc:
            log.critical("%s", exc)
            return 1
        bad = [p for p in rep["unverifiable_json"] if p.startswith("api/")]
        rc = 1 if (args.strict and bad) else 0
        log.warning("TLP boundary: %d JSON file(s) modified (%d withheld), %d record(s) removed, %d report file(s) removed, "
                    "%d unverifiable JSON%s", rep["json_files_modified"], rep["json_files_withheld"],
                    rep["records_removed"], rep["report_files_removed"], len(rep["unverifiable_json"]),
                    " (dry-run)" if args.dry_run else "")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(rep, indent=2, sort_keys=True), encoding="utf-8")
    else:
        print(json.dumps(rep, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    sys.exit(main())
