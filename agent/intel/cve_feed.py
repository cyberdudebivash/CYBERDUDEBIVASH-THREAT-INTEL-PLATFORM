"""
CVE Intelligence Feed
Sources:
- NVD (CVEs + CVSS)
- FIRST EPSS (Exploit probability)

Enhancements:
- EPSS trend delta (7 days)
- EPSS acceleration (24 hours)
"""

import requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"


def _format_time(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fetch_epss(cve_ids, date=None):
    """
    Fetch EPSS scores for a list of CVEs.
    Optionally supports historical date queries.
    """
    if not cve_ids:
        return {}

    params = {"cve": ",".join(cve_ids)}
    if date:
        params["date"] = date

    scores = {}

    try:
        r = requests.get(EPSS_API, params=params, timeout=30)
        if r.status_code != 200:
            return scores

        for item in r.json().get("data", []):
            scores[item["cve"]] = float(item.get("epss", 0.0))

    except requests.RequestException:
        pass

    return scores


def fetch_recent_cves(hours=24, max_results=5):
    """
    Fetch recent CVEs and enrich with:
    - CVSS
    - EPSS (current)
    - EPSS trend (7d)
    - EPSS acceleration (24h)
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    params = {
        "pubStartDate": _format_time(start_time),
        "pubEndDate": _format_time(end_time),
        "resultsPerPage": max_results,
    }

    try:
        r = requests.get(NVD_API, params=params, timeout=30)
        if r.status_code != 200:
            print("⚠️ NVD API unavailable")
            return []

        data = r.json()

    except requests.RequestException as e:
        print(f"⚠️ CVE fetch failed: {e}")
        return []

    cves = []
    cve_ids = []

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        cve_ids.append(cve_id)

        metrics = cve.get("metrics", {})
        cvss = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break

        cves.append({
            "id": cve_id,
            "description": cve.get("descriptions", [{}])[0].get("value", ""),
            "published": cve.get("published"),
            "cvss": cvss,
            "epss": 0.0,
            "epss_delta_7d": 0.0,
            "epss_delta_24h": 0.0,
            "epss_trend": "STABLE",
            "epss_acceleration": "STABLE",
        })

    # ---- EPSS enrichment ----
    epss_now = _fetch_epss(cve_ids)
    epss_7d = _fetch_epss(cve_ids, date=(end_time - timedelta(days=7)).date().isoformat())
    epss_24h = _fetch_epss(cve_ids, date=(end_time - timedelta(days=1)).date().isoformat())

    for cve in cves:
        now = epss_now.get(cve["id"], 0.0)
        prev_7d = epss_7d.get(cve["id"], now)
        prev_24h = epss_24h.get(cve["id"], now)

        delta_7d = round(now - prev_7d, 3)
        delta_24h = round(now - prev_24h, 3)

        # Trend (7-day)
        trend = "STABLE"
        if delta_7d >= 0.40:
            trend = "SHARPLY RISING"
        elif delta_7d >= 0.20:
            trend = "RISING"

        # Acceleration (24-hour)
        accel = "STABLE"
        if delta_24h >= 0.15:
            accel = "RAPID ACCELERATION"
        elif delta_24h >= 0.07:
            accel = "ACCELERATING"

        cve.update({
            "epss": now,
            "epss_delta_7d": delta_7d,
            "epss_delta_24h": delta_24h,
            "epss_trend": trend,
            "epss_acceleration": accel,
        })

    return cves
