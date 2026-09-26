"""
tests/test_site_links_resolve.py

Site-wide internal link check (2026-09-26). A live crawl of every internal
href/src in the published pages found 404s customers hit:
  - /favicon.ico, referenced by 53 pages: the file never existed;
  - /blog/ (5 pages' nav) and the 11 /blog/ posts sitemap-programmatic.xml
    advertises: blog/ existed but was not in build_dist_artifact.py's
    INCLUDE_DIRS;
  - /threat/, /reports/, /intel: no such published page;
  - 41 *.md docs linked from the Knowledge Center, developer portal, pricing
    and compliance pages: dist/ never ships *.md (they now link to the
    rendered file in the public GitHub repo);
  - two hardcoded /reports/2026/05/... dossiers on methodology.html, retired
    by the 24h report retention.

This test resolves every internal link statically against what
build_dist_artifact.py actually ships (root *.html, INCLUDE_DIRS,
include_singles), so a new broken link fails CI instead of reaching
customers.
"""
import ast
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

REPO = Path(__file__).resolve().parent.parent
SITE = "https://intel.cyberdudebivash.com"
BUILD = REPO / "scripts" / "build_dist_artifact.py"

# Served by the Cloudflare Worker / R2 or by Cloudflare itself, not by files.
DYNAMIC_PREFIXES = ("/api/", "/auth/", "/cdn-cgi/", "/taxii/", "/v1/")
REPORT_RE = re.compile(r"^/reports/\d{4}/\d{2}/[^/]+\.html$")
# href/src attributes only (not data-src, data-href, ...), static values only.
ATTR_RE = re.compile(r'(?<![\w-])(href|src)\s*=\s*"([^"]+)"')


def _dist_rules():
    tree = ast.parse(BUILD.read_text(encoding="utf-8"))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("INCLUDE_DIRS", "include_singles", "DOCS_HTML_WHITELIST"):
                found[node.targets[0].id] = set(ast.literal_eval(node.value))
    assert len(found) == 3, f"build_dist_artifact.py rules not found: {sorted(found)}"
    return found["INCLUDE_DIRS"], found["include_singles"], found["DOCS_HTML_WHITELIST"]


INCLUDE_DIRS, INCLUDE_SINGLES, DOCS_WHITELIST = _dist_rules()


def _published_pages():
    pages = sorted(REPO.glob("*.html"))
    for d in INCLUDE_DIRS:
        if d != "reports":
            pages += sorted((REPO / d).rglob("*.html"))
    return pages


def _internal_links(page: Path):
    text = re.sub(r"<!--.*?-->", "", page.read_text(encoding="utf-8", errors="ignore"), flags=re.S)
    base = f"{SITE}/{page.relative_to(REPO).as_posix()}"
    for _attr, raw in ATTR_RE.findall(text):
        url = raw.strip().replace("&amp;", "&")
        if url.startswith(("#", "mailto:", "tel:", "javascript:", "data:")) or any(c in url for c in "{}$'+` "):
            continue
        u = urlparse(urljoin(base, url))
        if u.netloc == urlparse(SITE).netloc:
            yield u.path


def _shipped_file(rel: str) -> bool:
    if not (REPO / rel).is_file():
        return False
    if "/" not in rel:
        return rel.endswith(".html") or rel in INCLUDE_SINGLES
    top, rest = rel.split("/", 1)
    if top == "docs":
        return rest in DOCS_WHITELIST
    return top in INCLUDE_DIRS


def _is_shipped(path: str) -> bool:
    """Mirrors GitHub Pages: /dir/ -> dir/index.html; /name -> name.html."""
    rel = path.lstrip("/")
    if rel == "" or rel.endswith("/"):
        return _shipped_file(rel + "index.html")
    if _shipped_file(rel):
        return True
    return "." not in rel.rsplit("/", 1)[-1] and (_shipped_file(rel + ".html") or _shipped_file(rel + "/index.html"))


def test_every_internal_link_resolves_to_a_shipped_file():
    broken = {}
    for page in _published_pages():
        for path in _internal_links(page):
            if path.startswith(DYNAMIC_PREFIXES) or REPORT_RE.match(path):
                continue
            if not _is_shipped(path):
                broken.setdefault(path, set()).add(page.relative_to(REPO).as_posix())
    assert not broken, "internal links that 404 on the live site:\n" + "\n".join(
        f"  {p}  <- {', '.join(sorted(v)[:4])}" for p, v in sorted(broken.items())
    )


def test_static_pages_do_not_hardcode_individual_reports():
    """Reports are retired after the rolling window (24h), so a hardcoded
    /reports/YYYY/MM/<id>.html link on a static page eventually 404s."""
    offenders = [
        f"{page.relative_to(REPO)}: {path}"
        for page in _published_pages()
        for path in _internal_links(page)
        if REPORT_RE.match(path)
    ]
    assert offenders == []


def test_favicon_exists_and_ships():
    assert (REPO / "favicon.ico").is_file()
    assert "favicon.ico" in INCLUDE_SINGLES
    assert (REPO / "favicon.ico").read_bytes()[:4] == b"\x00\x00\x01\x00", "favicon.ico must be an ICO file"


def test_sitemap_urls_resolve_to_shipped_files():
    broken = []
    for sm in sorted(REPO.glob("sitemap*.xml")):
        for loc in re.findall(r"<loc>([^<]+)</loc>", sm.read_text(encoding="utf-8")):
            u = urlparse(loc.strip())
            if u.netloc != urlparse(SITE).netloc:
                continue
            if u.path.endswith(".xml"):
                continue
            if u.path.startswith("/reports/"):
                broken.append(f"{sm.name}: {loc.strip()} (reports retire after 24h; not for a static sitemap)")
            elif not _is_shipped(u.path):
                broken.append(f"{sm.name}: {loc.strip()}")
    assert broken == [], "sitemap URLs that 404:\n" + "\n".join(broken[:40])
