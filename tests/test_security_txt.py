"""
tests/test_security_txt.py

security.txt (RFC 9116), 2026-09-26. The homepage's "Security disclosure:
security.txt" link pointed at /security.txt, which 404'd: only
/.well-known/security.txt was published, and GitHub Pages cannot redirect.
The file's own comments also promised 72h/14-day response times while the
Policy it links to promises 2/7 business days.

Now:
- /.well-known/security.txt (canonical) and /security.txt (legacy copy,
  RFC 9116 section 3) are byte-identical and both ship in dist/;
- Canonical lists both served URLs; Policy points at the disclosure section;
- the comments defer to the Policy instead of restating commitments;
- scripts/security_txt_validator.py enforces RFC 9116 and flags an Expires
  date that is close, passed, or more than a year ahead.
"""
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from scripts import security_txt_validator as v

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 9, 26, tzinfo=UTC)

VALID = (
    "# comment\n"
    "Contact: mailto:security@example.com\n"
    "Expires: 2027-06-01T00:00:00.000Z\n"
    "Preferred-Languages: en\n"
    "Canonical: https://example.com/.well-known/security.txt\n"
    "Policy: https://example.com/policy\n"
)


# -- The published files ------------------------------------------------------
def test_published_security_txt_is_valid_and_not_about_to_expire():
    report = v.validate_repo(warn_days=30)
    assert report["errors"] == [], report["errors"]
    assert not [w for w in report["warnings"] if "Expires" in w], (
        "security.txt expires within 30 days: set Expires in .well-known/security.txt to a date "
        "under a year ahead, then copy the file to security.txt"
    )


def test_both_locations_are_identical_and_canonical_lists_both():
    canonical = (REPO / ".well-known" / "security.txt").read_bytes()
    assert (REPO / "security.txt").read_bytes() == canonical
    text = canonical.decode("utf-8")
    for url in v.SERVED_URLS:
        assert f"Canonical: {url}" in text


def test_comments_do_not_restate_response_commitments():
    """Response times live in the Policy page only (they conflicted before)."""
    text = (REPO / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert not re.search(r"\b\d+\s*(hours?|days?|business days?)\b", text, re.I)


def test_policy_url_anchor_exists():
    text = (REPO / ".well-known" / "security.txt").read_text(encoding="utf-8")
    policy = re.search(r"^Policy: (\S+)$", text, re.M).group(1)
    page, _, anchor = policy.partition("#")
    assert page == "https://intel.cyberdudebivash.com/security-compliance.html"
    html = (REPO / "security-compliance.html").read_text(encoding="utf-8")
    assert f'id="{anchor}"' in html
    assert "security@cyberdudebivash.com" in html, "policy page must name the same contact"


def test_contact_matches_the_published_policy():
    text = (REPO / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert "Contact: mailto:security@cyberdudebivash.com" in text
    assert "security@cyberdudebivash.com" in (REPO / "SECURITY.md").read_text(encoding="utf-8")


def test_site_links_resolve_to_a_published_location():
    published = {"/.well-known/security.txt", "/security.txt", ".well-known/security.txt"}
    offenders = []
    for page in REPO.glob("*.html"):
        for href in re.findall(r'href="([^"]*security\.txt)"', page.read_text(encoding="utf-8", errors="ignore")):
            target = href.replace("https://intel.cyberdudebivash.com", "")
            if target not in published:
                offenders.append(f"{page.name}: {href}")
    assert offenders == []
    home = (REPO / "index.html").read_text(encoding="utf-8")
    assert 'href="/.well-known/security.txt"' in home, "homepage links the canonical location"


def test_dist_ships_both_locations():
    build = (REPO / "scripts" / "build_dist_artifact.py").read_text(encoding="utf-8")
    singles = build[build.index("include_singles = ["):]
    singles = singles[:singles.index("]")]
    assert '"security.txt"' in singles, "root security.txt must be in include_singles (root *.txt is excluded)"
    assert '".well-known"' in build


def test_regression_gate_runs_this_suite_on_security_txt_changes():
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "intel-gateway-regression-gate.yml").read_text(encoding="utf-8"))
    on = wf.get("on") or wf.get(True)
    for event in ("pull_request", "push"):
        paths = on[event]["paths"]
        for p in ("security.txt", ".well-known/**", "scripts/security_txt_validator.py"):
            assert p in paths, f"{event} paths must include {p}"
    assert "tests/test_security_txt.py" in (REPO / ".github" / "workflows" / "intel-gateway-regression-gate.yml").read_text(encoding="utf-8")


# -- The validator -------------------------------------------------------------
def _errors(text, now=NOW):
    return v.validate_text(text, now=now)["errors"]


def test_validator_accepts_a_valid_file():
    assert _errors(VALID) == []


def test_validator_requires_contact():
    assert any("Contact" in e for e in _errors(VALID.replace("Contact: mailto:security@example.com\n", "")))


def test_validator_rejects_bad_contact_scheme():
    assert any("Contact" in e for e in _errors(VALID.replace("mailto:security@example.com", "security@example.com")))


def test_validator_requires_exactly_one_expires():
    assert any("exactly once" in e for e in _errors(VALID.replace("Expires: 2027-06-01T00:00:00.000Z\n", "")))
    doubled = VALID + "Expires: 2027-05-01T00:00:00Z\n"
    assert any("exactly once" in e for e in _errors(doubled))


def test_validator_rejects_expired_and_far_future():
    assert any("has passed" in e for e in _errors(VALID, now=datetime(2027, 6, 2, tzinfo=UTC)))
    assert any("more than a year" in e for e in _errors(VALID, now=datetime(2026, 1, 1, tzinfo=UTC)))
    assert any("RFC 3339" in e for e in _errors(VALID.replace("2027-06-01T00:00:00.000Z", "June 2027")))


def test_validator_warns_before_expiry():
    r = v.validate_text(VALID, now=datetime(2027, 5, 1, tzinfo=UTC), warn_days=45)
    assert r["errors"] == []
    assert any("day(s) away" in w for w in r["warnings"])


def test_validator_requires_https_for_uri_fields():
    assert any("https" in e for e in _errors(VALID.replace("https://example.com/policy", "http://example.com/policy")))


def test_validator_rejects_malformed_lines():
    assert any("not a 'Field-Name: value' line" in e for e in _errors(VALID + "this is not a field\n"))


def test_repo_check_catches_a_drifted_legacy_copy(tmp_path):
    (tmp_path / ".well-known").mkdir()
    good = (REPO / ".well-known" / "security.txt").read_bytes()
    (tmp_path / ".well-known" / "security.txt").write_bytes(good)
    (tmp_path / "security.txt").write_bytes(good + b"# drift\n")
    report = v.validate_repo(tmp_path, now=NOW)
    assert any("differs" in e for e in report["errors"])
    (tmp_path / "security.txt").unlink()
    report = v.validate_repo(tmp_path, now=NOW)
    assert any("would 404" in e for e in report["errors"])


def test_cli_exit_codes(monkeypatch):
    original = v.validate_repo
    assert v.main([]) == 0
    expires = datetime.fromisoformat(original()["files"][v.CANONICAL_PATH]["expires"])
    monkeypatch.setattr(v, "validate_repo", lambda **kw: original(now=expires - timedelta(days=10), **kw))
    assert v.main([]) == 2, "valid but expiring soon -> exit 2"
    monkeypatch.setattr(v, "validate_repo", lambda **kw: original(now=expires + timedelta(days=1), **kw))
    assert v.main([]) == 1, "expired -> exit 1"
