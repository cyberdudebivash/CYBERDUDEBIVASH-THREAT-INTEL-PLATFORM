"""Every published root page is a complete document.

admin.html shipped truncated mid-statement (`setTimeout(() => { t.style.`)
with no closing </script>, </body> or </html>: its whole script was a syntax
error, so no admin control worked, and nothing noticed. Each root *.html
must end with </html>, and every inline <script> must be closed.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGES = sorted(REPO.glob("*.html"))


def _strip_comments(src: str) -> str:
    # <script> mentioned inside HTML or JS comments is not a tag.
    src = re.sub(r"<!--.*?-->", " ", src, flags=re.S)
    src = re.sub(r"(?m)^\s*//.*$", " ", src)
    return src


def test_pages_exist():
    assert len(PAGES) > 50


def test_every_root_page_ends_with_closing_html_tag():
    bad = [p.name for p in PAGES if not p.read_text(encoding="utf-8", errors="replace").rstrip().lower().endswith("</html>")]
    assert not bad, "truncated or unterminated pages: " + ", ".join(bad)


def test_every_inline_script_is_closed():
    bad = []
    for p in PAGES:
        s = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        opened = len(re.findall(r"<script\b[^>]*>", s, flags=re.I))
        closed = len(re.findall(r"</script\s*>", s, flags=re.I))
        if opened != closed:
            bad.append(f"{p.name} (open={opened} close={closed})")
    assert not bad, "unclosed <script> blocks: " + ", ".join(bad)
