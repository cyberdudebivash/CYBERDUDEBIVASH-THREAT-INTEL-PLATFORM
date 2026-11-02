#!/usr/bin/env python3
"""Static release gate for the dedicated privacy-safe 9:16 OBS showcase page.

This complements, but never substitutes for, an actual OBS rehearsal and a
browser test against live production evidence.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "instagram-live-studio.html"
EXPECTED_SCENES = {
    "scene-intro",
    "scene-status",
    "scene-intel",
    "scene-workflow",
    "scene-commercial",
}
FORBIDDEN = (
    "navigator.mediaDevices",
    "getDisplayMedia",
    "getUserMedia",
    "localStorage",
    "document.cookie",
    "innerHTML",
    "setInterval(",
    "new WebSocket(",
    "RTCPeerConnection",
    "document.write(",
)


class Outline(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scene_ids = set()
        self.sources = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "section" and a.get("id", "").startswith("scene-"):
            self.scene_ids.add(a["id"])
        if tag in ("iframe", "video", "audio"):
            self.sources.append(tag)
        if tag == "script":
            self.scripts += 1
            if a.get("src"):
                self.sources.append("remote-script")


def main():
    source = PAGE.read_text(encoding="utf-8")
    parser = Outline()
    parser.feed(source)
    errors = []
    if parser.scene_ids != EXPECTED_SCENES:
        errors.append(f"scene mismatch: {sorted(parser.scene_ids)}")
    if parser.sources:
        errors.append(f"forbidden capture/external media: {parser.sources}")
    if parser.scripts != 1:
        errors.append(f"expected one inline controller script, found {parser.scripts}")
    for item in FORBIDDEN:
        if item in source:
            errors.append(f"privacy/control violation: {item}")
    for endpoint in ("/api/health", "/api/preview/"):
        if endpoint not in source:
            errors.append(f"missing public endpoint {endpoint}")
    if 'credentials:"omit"' not in source:
        errors.append("fetch must omit credentials")
    if 'params.get("autoplay") === "1"' not in source:
        errors.append("autoplay must be opt-in")
    if "No example intelligence is being substituted" not in source:
        errors.append("missing fail-closed intelligence disclaimer")
    if "textContent" not in source:
        errors.append("untrusted intelligence must use text-only DOM updates")
    if re.search(r"https?://", source):
        errors.append("showcase page embeds an absolute external URL")
    if errors:
        print("FAIL: " + "; ".join(errors))
        return 1
    print("STATIC PASS: expected scenes, two same-origin data sources, no external media/capture/polling; runtime/release unverified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
