#!/usr/bin/env python3
"""Bounded read-only SENTINEL APEX ecosystem demo preflight.

One GET per public URL; no credentials, automation loops, deployments, writes to
production, or destructive actions.  Never treats HTML accessibility as proof
that interactive workflows, purchases, or OBS broadcast work.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


TARGETS = (
    ("intel_home", "https://intel.cyberdudebivash.com/", "html"),
    ("intel_health", "https://intel.cyberdudebivash.com/api/health", "health"),
    ("intel_demo", "https://intel.cyberdudebivash.com/demo.html", "html"),
    ("intel_api_docs", "https://intel.cyberdudebivash.com/api-docs.html", "html"),
    ("ai_hub", "https://cyberdudebivash.in/", "html"),
    ("ai_hub_health", "https://cyberdudebivash.in/api/health", "json"),
    ("soc", "https://soc.cyberdudebivash.in/", "html"),
    ("academy", "https://academy.cyberdudebivash.com/", "html"),
    ("labs", "https://labs.cyberdudebivash.in/", "html"),
    ("tools", "https://tools.cyberdudebivash.com/", "html"),
    ("corporate", "https://www.cyberdudebivash.com/", "html"),
)
ALLOWED_HOSTS = frozenset(urlsplit(url).hostname for _, url, _ in TARGETS)
MAX_BYTES = 131072
FRESHNESS_LIMIT_SECONDS = 6 * 3600


class HostRestrictedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
            raise ValueError("redirect outside approved HTTPS demo origins")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def health_age_seconds(data, now):
    """Return nonnegative feed age, or None if contract has no usable timestamp."""
    intel = data.get("intelligence") if isinstance(data.get("intelligence"), dict) else {}
    age = intel.get("age_seconds", data.get("age_seconds"))
    if isinstance(age, (int, float)) and not isinstance(age, bool) and 0 <= age < 1e12:
        return int(age)
    for raw in (intel.get("generated_at"), data.get("generated_at")):
        ts = _timestamp(raw)
        if ts is not None:
            delta = (now - ts).total_seconds()
            return int(delta) if delta >= -600 else None
    return None


def assess_health(data, now):
    if not isinstance(data, dict):
        return "FAIL", "health response is not a JSON object"
    if str(data.get("status", "")).lower() in ("error", "down", "failed", "unhealthy"):
        return "FAIL", "health endpoint reports unhealthy state"
    age = health_age_seconds(data, now)
    if age is None:
        return "UNVERIFIED", "feed freshness timestamp absent or unusable"
    if age > FRESHNESS_LIMIT_SECONDS:
        return "FAIL", f"feed age {age}s exceeds 21600s freshness contract"
    return "PASS", f"feed age {age}s is within 21600s contract"


def check_one(opener, name, url, expected, timeout, now):
    result = {"name": name, "url": url, "status": "UNVERIFIED", "http_status": None, "detail": ""}
    request = Request(url, method="GET", headers={
        "User-Agent": "SENTINEL-APEX-Demo-Preflight/1.0",
        "Accept": "application/json, text/html;q=0.9, */*;q=0.5",
        "Cache-Control": "no-cache",
    })
    try:
        with opener.open(request, timeout=timeout) as response:
            result["http_status"] = response.status
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
                raise ValueError("response redirected outside approved origins")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                result.update(status="UNVERIFIED", detail="body exceeds 128 KiB inspection limit")
                return result
            if not body.strip():
                result.update(status="FAIL", detail="empty response")
                return result
            if expected == "html":
                if b"<html" not in body.lower() and b"<!doctype" not in body.lower():
                    result.update(status="UNVERIFIED", detail="HTTP success but HTML structure unconfirmed")
                else:
                    result.update(status="PASS", detail="public HTML response; UI operation still unverified")
                return result
            try:
                data = json.loads(body.decode("utf-8"))
            except (UnicodeError, ValueError):
                result.update(status="FAIL", detail="invalid JSON")
                return result
            if expected == "health":
                result["status"], result["detail"] = assess_health(data, now)
            elif isinstance(data, (dict, list)):
                result.update(status="PASS", detail="public JSON response; business workflow unverified")
            else:
                result.update(status="FAIL", detail="unexpected JSON scalar response")
    except HTTPError as exc:
        result["http_status"] = exc.code
        if exc.code in (401, 403, 429):
            result.update(status="UNVERIFIED", detail=f"HTTP {exc.code}: authorization, anti-bot or rate limit; not proof of outage")
        else:
            result.update(status="FAIL", detail=f"HTTP {exc.code}")
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        # A failed HTTP client request alone cannot prove a platform is down.
        result.update(status="UNVERIFIED", detail=f"retrieval error: {type(exc).__name__}: {str(exc)[:160]}")
    return result


def self_test():
    now = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
    assert assess_health({"status": "ok", "intelligence": {"age_seconds": 120}}, now)[0] == "PASS"
    assert assess_health({"status": "ok", "intelligence": {"age_seconds": 21601}}, now)[0] == "FAIL"
    assert assess_health({"status": "ok"}, now)[0] == "UNVERIFIED"
    assert assess_health({"status": "failed", "age_seconds": 10}, now)[0] == "FAIL"
    assert assess_health({"generated_at": "2026-11-02T11:00:00Z"}, now)[0] == "PASS"
    assert assess_health({"generated_at": "2026-11-01T00:00:00Z"}, now)[0] == "FAIL"
    assert len(TARGETS) <= 12 and len(ALLOWED_HOSTS) <= 10
    print("SELF-TEST PASS: classification, date parsing, bounded target list")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sentinel_apex_demo_preflight.json")
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not (2 <= args.timeout <= 30):
        parser.error("--timeout must be between 2 and 30 seconds")
    now = datetime.now(timezone.utc)
    opener = build_opener(HostRestrictedRedirect())
    rows = []
    for name, url, expected in TARGETS:
        record = check_one(opener, name, url, expected, args.timeout, now)
        rows.append(record)
        print(f"{record['status']:<11} {name:<18} {record['detail']}")
    verdict = "BLOCKED" if any(r["status"] == "FAIL" for r in rows) else (
        "REQUIRES_VERIFICATION" if any(r["status"] == "UNVERIFIED" for r in rows)
        else "HTTP_PREFLIGHT_ONLY"
    )
    report = {
        "title": "SENTINEL APEX Sunday Instagram demo public-surface preflight",
        "checked_at_utc": now.isoformat(),
        "verdict": verdict,
        "release_approved": False,
        "bounds": "one read-only GET per URL; no retries or authenticated endpoints",
        "mandatory_manual_gates": [
            "real feature execution, feed provenance, and safe synthetic replay label",
            "Razorpay payment + fulfillment + correct verified seller identity",
            "OBS 9:16 Browser Source ONLY, no desktops, tabs, webcam or microphones",
            "stable 30-minute local rehearsal, captions readable at phone size",
            "Instagram private preview, rotated stream key and final human approval",
        ],
        "results": rows,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Verdict: {verdict}. Not a GO authorization. JSON: {output}")
    return 2 if verdict == "BLOCKED" else 1 if verdict == "REQUIRES_VERIFICATION" else 0


if __name__ == "__main__":
    sys.exit(main())
