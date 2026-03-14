"""
CYBERDUDEBIVASH SENTINEL APEX v52 — Premium Report Engine
Generates enterprise threat intelligence reports in HTML and STIX formats.

Output Formats:
    - HTML: Branded, print-ready threat intelligence reports
    - STIX 2.1: Machine-readable intelligence bundles
    - JSON: Structured report data

Reports:
    - Executive Threat Briefing
    - Tactical IOC Report
    - Campaign Analysis
    - Vulnerability Intelligence
    - Weekly Threat Landscape
"""

import json
import hashlib
import html
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
STIX_DIR = DATA_DIR / "stix"
INTEL_DIR = DATA_DIR / "intelligence"
REPORTS_DIR = INTEL_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [REPORT-ENGINE] %(levelname)s %(message)s")
logger = logging.getLogger("report_engine")

# ---------------------------------------------------------------------------
# Report Styling
# ---------------------------------------------------------------------------

REPORT_CSS = """
:root {
    --cdb-bg: #0a0e17;
    --cdb-surface: #111827;
    --cdb-border: #1e293b;
    --cdb-text: #e2e8f0;
    --cdb-text-dim: #94a3b8;
    --cdb-accent: #06b6d4;
    --cdb-accent-glow: rgba(6, 182, 212, 0.15);
    --cdb-critical: #ef4444;
    --cdb-high: #f97316;
    --cdb-medium: #eab308;
    --cdb-low: #22c55e;
    --cdb-gradient: linear-gradient(135deg, #06b6d4, #8b5cf6);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--cdb-bg);
    color: var(--cdb-text);
    line-height: 1.7;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 30px;
}

.report-header {
    border-bottom: 2px solid var(--cdb-accent);
    padding-bottom: 30px;
    margin-bottom: 40px;
}

.report-header h1 {
    font-size: 2em;
    background: var(--cdb-gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
}

.report-header .subtitle {
    color: var(--cdb-text-dim);
    font-size: 0.95em;
}

.report-header .meta-strip {
    display: flex;
    gap: 24px;
    margin-top: 16px;
    flex-wrap: wrap;
}

.meta-badge {
    background: var(--cdb-surface);
    border: 1px solid var(--cdb-border);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 0.85em;
}

.section {
    background: var(--cdb-surface);
    border: 1px solid var(--cdb-border);
    border-radius: 10px;
    padding: 28px;
    margin-bottom: 24px;
}

.section h2 {
    color: var(--cdb-accent);
    font-size: 1.3em;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--cdb-border);
}

.section h3 {
    color: var(--cdb-text);
    font-size: 1.05em;
    margin: 16px 0 8px;
}

.section p, .section li {
    color: var(--cdb-text-dim);
    margin-bottom: 8px;
}

.severity-critical { color: var(--cdb-critical); font-weight: 700; }
.severity-high { color: var(--cdb-high); font-weight: 700; }
.severity-medium { color: var(--cdb-medium); font-weight: 600; }
.severity-low { color: var(--cdb-low); }

.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin: 16px 0;
}

.stat-card {
    background: var(--cdb-bg);
    border: 1px solid var(--cdb-border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}

.stat-card .value {
    font-size: 2em;
    font-weight: 700;
    color: var(--cdb-accent);
}

.stat-card .label {
    font-size: 0.8em;
    color: var(--cdb-text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
}

th, td {
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--cdb-border);
    font-size: 0.9em;
}

th {
    background: var(--cdb-bg);
    color: var(--cdb-accent);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.8em;
    letter-spacing: 0.5px;
}

.ioc-tag {
    display: inline-block;
    background: var(--cdb-accent-glow);
    color: var(--cdb-accent);
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 0.85em;
    margin: 2px;
}

.mitre-tag {
    display: inline-block;
    background: rgba(139, 92, 246, 0.15);
    color: #a78bfa;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    margin: 2px;
}

.footer {
    text-align: center;
    color: var(--cdb-text-dim);
    font-size: 0.8em;
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--cdb-border);
}

@media print {
    body { background: #fff; color: #1a1a1a; }
    .section { border: 1px solid #ddd; background: #fff; }
    .section h2 { color: #0891b2; }
    .stat-card { background: #f8f8f8; }
    .stat-card .value { color: #0891b2; }
    th { background: #f0f0f0; color: #0891b2; }
}
"""

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ReportConfig:
    report_type: str = "executive_briefing"  # executive_briefing, tactical_ioc, campaign, vulnerability, weekly
    title: Optional[str] = None
    time_range_days: int = 7
    include_iocs: bool = True
    include_mitre: bool = True
    include_detection: bool = True
    include_recommendations: bool = True
    classification: str = "TLP:AMBER"
    org_name: str = "CYBERDUDEBIVASH Pvt. Ltd."

@dataclass
class ReportOutput:
    report_id: str
    title: str
    report_type: str
    html_path: str
    stix_path: str
    json_path: str
    generated_at: str
    stats: Dict[str, Any]


# ---------------------------------------------------------------------------
# Report Engine
# ---------------------------------------------------------------------------

class PremiumReportEngine:
    """Generate enterprise-grade threat intelligence reports."""

    def __init__(self):
        self._manifest: List[Dict] = []

    def _load_intelligence(self):
        """Load intelligence data from feed manifest."""
        manifest_path = STIX_DIR / "feed_manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r") as f:
                    data = json.load(f)
                    self._manifest = data if isinstance(data, list) else data.get("entries", [])
            except Exception as e:
                logger.error(f"Failed to load manifest: {e}")
                self._manifest = []
        else:
            self._manifest = []

    def generate(self, config: ReportConfig) -> ReportOutput:
        """Generate a complete report based on configuration."""
        self._load_intelligence()

        report_id = hashlib.md5(
            f"{config.report_type}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        ts = datetime.now(timezone.utc)

        # Filter by time range
        cutoff = ts - timedelta(days=config.time_range_days)
        entries = []
        for entry in self._manifest:
            entry_ts = entry.get("timestamp", "")
            if entry_ts:
                try:
                    if entry_ts >= cutoff.isoformat():
                        entries.append(entry)
                except Exception:
                    entries.append(entry)
            else:
                entries.append(entry)

        if not entries:
            entries = self._manifest  # Fallback to all data

        # Compute stats
        stats = self._compute_stats(entries)

        # Generate title
        title = config.title or self._default_title(config.report_type, ts)

        # Generate HTML
        html_content = self._build_html(config, title, report_id, ts, entries, stats)

        # Generate STIX bundle
        stix_bundle = self._build_stix_bundle(report_id, ts, entries)

        # Generate JSON report
        json_report = self._build_json_report(config, title, report_id, ts, entries, stats)

        # Write outputs
        prefix = f"{config.report_type}_{report_id}"
        html_path = REPORTS_DIR / f"{prefix}.html"
        stix_path = REPORTS_DIR / f"{prefix}_stix.json"
        json_path = REPORTS_DIR / f"{prefix}.json"

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        with open(stix_path, "w") as f:
            json.dump(stix_bundle, f, indent=2, default=str)
        with open(json_path, "w") as f:
            json.dump(json_report, f, indent=2, default=str)

        logger.info(f"Report generated: {title} ({report_id})")

        return ReportOutput(
            report_id=report_id,
            title=title,
            report_type=config.report_type,
            html_path=str(html_path),
            stix_path=str(stix_path),
            json_path=str(json_path),
            generated_at=ts.isoformat(),
            stats=stats,
        )

    def _compute_stats(self, entries: List[Dict]) -> Dict:
        total = len(entries)
        critical = sum(1 for e in entries if e.get("risk_score", 0) >= 80)
        high = sum(1 for e in entries if 60 <= e.get("risk_score", 0) < 80)
        medium = sum(1 for e in entries if 40 <= e.get("risk_score", 0) < 60)
        low = sum(1 for e in entries if e.get("risk_score", 0) < 40)
        avg_risk = round(sum(e.get("risk_score", 0) for e in entries) / max(total, 1), 1)

        # Unique actors
        actors = set(e.get("actor_tag", "") for e in entries if e.get("actor_tag"))
        actors.discard("")
        actors.discard("Unknown")

        # Unique tactics
        tactics = set()
        for e in entries:
            for t in e.get("mitre_tactics", []):
                tactics.add(t)

        # IOC counts
        total_iocs = 0
        for e in entries:
            ioc_data = e.get("ioc_counts", e.get("iocs", {}))
            if isinstance(ioc_data, dict):
                for v in ioc_data.values():
                    if isinstance(v, int):
                        total_iocs += v
                    elif isinstance(v, list):
                        total_iocs += len(v)

        return {
            "total_advisories": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "avg_risk": avg_risk,
            "unique_actors": len(actors),
            "actors": sorted(actors),
            "unique_tactics": len(tactics),
            "tactics": sorted(tactics),
            "total_iocs": total_iocs,
        }

    def _default_title(self, report_type: str, ts: datetime) -> str:
        date_str = ts.strftime("%B %d, %Y")
        titles = {
            "executive_briefing": f"Executive Threat Intelligence Briefing — {date_str}",
            "tactical_ioc": f"Tactical IOC Intelligence Report — {date_str}",
            "campaign": f"Campaign Analysis & Attribution Report — {date_str}",
            "vulnerability": f"Vulnerability Intelligence Report — {date_str}",
            "weekly": f"Weekly Threat Landscape Report — {date_str}",
        }
        return titles.get(report_type, f"Threat Intelligence Report — {date_str}")

    def _build_html(self, config: ReportConfig, title: str, report_id: str,
                    ts: datetime, entries: List[Dict], stats: Dict) -> str:
        """Build the complete HTML report."""

        sections = []

        # Executive Summary
        sections.append(self._section_executive_summary(stats, config))

        # Threat Landscape Overview
        sections.append(self._section_threat_landscape(entries, stats))

        # Top Advisories
        sections.append(self._section_top_advisories(entries))

        # IOC Intelligence (if enabled)
        if config.include_iocs:
            sections.append(self._section_ioc_intelligence(entries))

        # MITRE ATT&CK Coverage (if enabled)
        if config.include_mitre:
            sections.append(self._section_mitre_coverage(entries, stats))

        # Threat Actor Tracking
        if stats["unique_actors"] > 0:
            sections.append(self._section_threat_actors(entries, stats))

        # Detection Recommendations (if enabled)
        if config.include_detection:
            sections.append(self._section_detection_recommendations(entries))

        # Strategic Recommendations
        if config.include_recommendations:
            sections.append(self._section_recommendations(stats))

        sections_html = "\n".join(sections)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)} | CDB SENTINEL APEX</title>
    <style>{REPORT_CSS}</style>
</head>
<body>
    <div class="report-header">
        <h1>{html.escape(title)}</h1>
        <div class="subtitle">CYBERDUDEBIVASH SENTINEL APEX — Premium Threat Intelligence</div>
        <div class="meta-strip">
            <span class="meta-badge">Report ID: {report_id}</span>
            <span class="meta-badge">Generated: {ts.strftime('%Y-%m-%d %H:%M UTC')}</span>
            <span class="meta-badge">Classification: {html.escape(config.classification)}</span>
            <span class="meta-badge">Period: {config.time_range_days} days</span>
        </div>
    </div>

    {sections_html}

    <div class="footer">
        <p>&copy; {ts.year} CyberDudeBivash Pvt. Ltd. — All Rights Reserved</p>
        <p>CYBERDUDEBIVASH SENTINEL APEX v52 Premium Report Engine</p>
        <p>intel.cyberdudebivash.com | cyberdudebivash.com</p>
    </div>
</body>
</html>"""

    def _section_executive_summary(self, stats: Dict, config: ReportConfig) -> str:
        return f"""
    <div class="section">
        <h2>1. Executive Summary</h2>
        <p>This report provides a comprehensive threat intelligence briefing covering the past {config.time_range_days} days
        of global cyber threat activity monitored by the CYBERDUDEBIVASH SENTINEL APEX platform.
        The analysis encompasses {stats['total_advisories']} security advisories across multiple threat categories.</p>

        <div class="stat-grid">
            <div class="stat-card">
                <div class="value">{stats['total_advisories']}</div>
                <div class="label">Total Advisories</div>
            </div>
            <div class="stat-card">
                <div class="value severity-critical">{stats['critical']}</div>
                <div class="label">Critical Severity</div>
            </div>
            <div class="stat-card">
                <div class="value severity-high">{stats['high']}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['avg_risk']}</div>
                <div class="label">Avg Risk Score</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['total_iocs']}</div>
                <div class="label">IOCs Extracted</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['unique_actors']}</div>
                <div class="label">Threat Actors</div>
            </div>
        </div>

        <p><strong>Risk Assessment:</strong>
        {"The threat landscape shows ELEVATED risk with " + str(stats['critical']) + " critical and " + str(stats['high']) + " high severity advisories requiring immediate attention." if stats['critical'] + stats['high'] > 5 else "The current threat landscape shows moderate activity levels with standard risk indicators."}
        </p>
    </div>"""

    def _section_threat_landscape(self, entries: List[Dict], stats: Dict) -> str:
        severity_rows = ""
        for level, count, css_class in [
            ("CRITICAL", stats['critical'], "severity-critical"),
            ("HIGH", stats['high'], "severity-high"),
            ("MEDIUM", stats['medium'], "severity-medium"),
            ("LOW", stats['low'], "severity-low"),
        ]:
            pct = round(count / max(stats['total_advisories'], 1) * 100, 1)
            severity_rows += f"<tr><td class='{css_class}'>{level}</td><td>{count}</td><td>{pct}%</td></tr>\n"

        return f"""
    <div class="section">
        <h2>2. Threat Landscape Overview</h2>
        <p>Analysis of {stats['total_advisories']} advisories reveals the following severity distribution:</p>
        <table>
            <thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead>
            <tbody>{severity_rows}</tbody>
        </table>
        <p>{stats['unique_tactics']} unique MITRE ATT&amp;CK tactics observed across {stats['unique_actors']} attributed threat actors.</p>
    </div>"""

    def _section_top_advisories(self, entries: List[Dict]) -> str:
        top = sorted(entries, key=lambda e: e.get("risk_score", 0), reverse=True)[:15]
        rows = ""
        for e in top:
            score = e.get("risk_score", 0)
            css = "severity-critical" if score >= 80 else "severity-high" if score >= 60 else "severity-medium" if score >= 40 else "severity-low"
            title = html.escape(str(e.get("title", "N/A"))[:80])
            actor = html.escape(str(e.get("actor_tag", "—")))
            tactics = ", ".join(e.get("mitre_tactics", [])[:3]) or "—"
            rows += f"<tr><td>{title}</td><td class='{css}'>{score}</td><td>{actor}</td><td>{html.escape(tactics)}</td></tr>\n"

        return f"""
    <div class="section">
        <h2>3. Top Priority Advisories</h2>
        <p>The following advisories carry the highest risk scores and warrant immediate attention:</p>
        <table>
            <thead><tr><th>Advisory</th><th>Risk</th><th>Actor</th><th>Tactics</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""

    def _section_ioc_intelligence(self, entries: List[Dict]) -> str:
        ioc_summary: Dict[str, int] = {}
        sample_iocs: Dict[str, List[str]] = {}

        for e in entries:
            ioc_data = e.get("iocs", e.get("ioc_counts", {}))
            if isinstance(ioc_data, dict):
                for itype, vals in ioc_data.items():
                    if isinstance(vals, list):
                        ioc_summary[itype] = ioc_summary.get(itype, 0) + len(vals)
                        if itype not in sample_iocs:
                            sample_iocs[itype] = []
                        sample_iocs[itype].extend(str(v) for v in vals[:5])
                    elif isinstance(vals, int):
                        ioc_summary[itype] = ioc_summary.get(itype, 0) + vals

        rows = ""
        for itype, count in sorted(ioc_summary.items(), key=lambda x: x[1], reverse=True):
            samples = sample_iocs.get(itype, [])[:3]
            sample_html = " ".join(f"<span class='ioc-tag'>{html.escape(s[:40])}</span>" for s in samples)
            rows += f"<tr><td>{html.escape(itype.upper())}</td><td>{count}</td><td>{sample_html}</td></tr>\n"

        return f"""
    <div class="section">
        <h2>4. Indicator of Compromise (IOC) Intelligence</h2>
        <p>Extracted and validated IOCs from all intelligence sources:</p>
        <table>
            <thead><tr><th>IOC Type</th><th>Count</th><th>Samples</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""

    def _section_mitre_coverage(self, entries: List[Dict], stats: Dict) -> str:
        tactic_counts: Dict[str, int] = {}
        for e in entries:
            for t in e.get("mitre_tactics", []):
                tactic_counts[t] = tactic_counts.get(t, 0) + 1

        rows = ""
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            rows += f"<tr><td><span class='mitre-tag'>{html.escape(tactic)}</span></td><td>{count}</td></tr>\n"

        return f"""
    <div class="section">
        <h2>5. MITRE ATT&amp;CK Coverage</h2>
        <p>{stats['unique_tactics']} unique techniques observed across the intelligence corpus:</p>
        <table>
            <thead><tr><th>Technique</th><th>Advisory Count</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""

    def _section_threat_actors(self, entries: List[Dict], stats: Dict) -> str:
        actor_data: Dict[str, Dict] = {}
        for e in entries:
            actor = e.get("actor_tag", "")
            if not actor or actor == "Unknown":
                continue
            if actor not in actor_data:
                actor_data[actor] = {"count": 0, "max_risk": 0, "tactics": set()}
            actor_data[actor]["count"] += 1
            actor_data[actor]["max_risk"] = max(actor_data[actor]["max_risk"], e.get("risk_score", 0))
            for t in e.get("mitre_tactics", []):
                actor_data[actor]["tactics"].add(t)

        rows = ""
        for actor, data in sorted(actor_data.items(), key=lambda x: x[1]["max_risk"], reverse=True)[:15]:
            risk = data["max_risk"]
            css = "severity-critical" if risk >= 80 else "severity-high" if risk >= 60 else "severity-medium"
            tactics_html = " ".join(f"<span class='mitre-tag'>{html.escape(t)}</span>" for t in list(data["tactics"])[:4])
            rows += f"<tr><td>{html.escape(actor)}</td><td>{data['count']}</td><td class='{css}'>{risk}</td><td>{tactics_html}</td></tr>\n"

        return f"""
    <div class="section">
        <h2>6. Threat Actor Tracking</h2>
        <p>{stats['unique_actors']} attributed threat actors identified:</p>
        <table>
            <thead><tr><th>Actor</th><th>Advisories</th><th>Max Risk</th><th>TTPs</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""

    def _section_detection_recommendations(self, entries: List[Dict]) -> str:
        return f"""
    <div class="section">
        <h2>7. Detection Engineering Recommendations</h2>
        <h3>Priority Detection Rules</h3>
        <p>Based on the intelligence in this report, deploy the following detection capabilities:</p>
        <ul>
            <li><strong>Network:</strong> Block or alert on all IP and domain IOCs at firewall/proxy layer</li>
            <li><strong>Endpoint:</strong> Deploy YARA rules for file hash detection across all endpoints</li>
            <li><strong>SIEM:</strong> Import Sigma rules for log-based detection of lateral movement and C2 activity</li>
            <li><strong>IDS/IPS:</strong> Deploy Suricata rules for real-time network traffic inspection</li>
            <li><strong>Email Gateway:</strong> Block phishing sender addresses and malicious URLs</li>
        </ul>
        <h3>Rule Deployment Priority</h3>
        <ul>
            <li><span class="severity-critical">P0:</span> All IOCs from CRITICAL severity advisories — deploy within 1 hour</li>
            <li><span class="severity-high">P1:</span> All IOCs from HIGH severity advisories — deploy within 4 hours</li>
            <li><span class="severity-medium">P2:</span> MEDIUM severity IOCs — deploy within 24 hours</li>
            <li><span class="severity-low">P3:</span> LOW severity IOCs — schedule for next maintenance window</li>
        </ul>
        <p><strong>Note:</strong> Detection rules are available via the SENTINEL APEX API at
        <code>/api/detection-rules</code> in Sigma, YARA, Suricata, Snort, KQL, and SPL formats.</p>
    </div>"""

    def _section_recommendations(self, stats: Dict) -> str:
        return f"""
    <div class="section">
        <h2>8. Strategic Recommendations</h2>
        <h3>Immediate Actions (0-24 hours)</h3>
        <ul>
            <li>Review and triage all {stats['critical']} CRITICAL severity advisories</li>
            <li>Deploy blocking rules for network IOCs at perimeter defenses</li>
            <li>Conduct targeted threat hunt for indicators matching top threat actors</li>
        </ul>
        <h3>Short-Term Actions (1-7 days)</h3>
        <ul>
            <li>Update endpoint detection rules with latest hash IOCs</li>
            <li>Review MITRE ATT&amp;CK coverage gaps identified in this report</li>
            <li>Brief SOC analysts on emerging threat actor TTPs</li>
            <li>Validate detection coverage for {stats['unique_tactics']} observed techniques</li>
        </ul>
        <h3>Long-Term Actions (7-30 days)</h3>
        <ul>
            <li>Conduct purple team exercises based on identified threat actor playbooks</li>
            <li>Review and enhance security controls for high-frequency attack vectors</li>
            <li>Update incident response playbooks based on latest campaign intelligence</li>
            <li>Schedule architectural review addressing exposed attack surface findings</li>
        </ul>
    </div>"""

    def _build_stix_bundle(self, report_id: str, ts: datetime, entries: List[Dict]) -> Dict:
        """Generate STIX 2.1 bundle for machine-readable intelligence sharing."""
        objects = []

        # Identity
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--cdb-sentinel-apex",
            "created": ts.isoformat(),
            "modified": ts.isoformat(),
            "name": "CyberDudeBivash SENTINEL APEX",
            "description": "AI-Powered Threat Intelligence Platform",
            "identity_class": "organization",
        })

        # Report object
        indicator_ids = []
        for i, entry in enumerate(entries[:100]):
            ind_id = f"indicator--{hashlib.md5(f'{report_id}:{i}'.encode()).hexdigest()}"
            indicator_ids.append(ind_id)

            ioc_data = entry.get("iocs", entry.get("ioc_counts", {}))
            pattern_parts = []
            if isinstance(ioc_data, dict):
                for itype, vals in ioc_data.items():
                    if isinstance(vals, list):
                        for v in vals[:5]:
                            if itype == "ipv4":
                                pattern_parts.append(f"[ipv4-addr:value = '{v}']")
                            elif itype == "domain":
                                pattern_parts.append(f"[domain-name:value = '{v}']")
                            elif itype in ("sha256", "sha1", "md5"):
                                pattern_parts.append(f"[file:hashes.'{itype.upper()}' = '{v}']")

            pattern = " OR ".join(pattern_parts) if pattern_parts else "[ipv4-addr:value = '0.0.0.0']"

            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": ts.isoformat(),
                "modified": ts.isoformat(),
                "name": entry.get("title", f"Advisory {i}"),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ts.isoformat(),
                "confidence": min(int(entry.get("risk_score", 50)), 100),
                "labels": [f"risk-score:{entry.get('risk_score', 0)}"],
            })

        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{report_id}",
            "created": ts.isoformat(),
            "modified": ts.isoformat(),
            "name": f"CDB SENTINEL APEX Intelligence Report {report_id}",
            "published": ts.isoformat(),
            "object_refs": indicator_ids,
        })

        return {
            "type": "bundle",
            "id": f"bundle--{report_id}",
            "objects": objects,
        }

    def _build_json_report(self, config: ReportConfig, title: str, report_id: str,
                            ts: datetime, entries: List[Dict], stats: Dict) -> Dict:
        return {
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "module": "v52_report_engine",
            "report_id": report_id,
            "title": title,
            "report_type": config.report_type,
            "classification": config.classification,
            "generated_at": ts.isoformat(),
            "time_range_days": config.time_range_days,
            "statistics": stats,
            "advisory_count": len(entries),
            "top_advisories": sorted(entries, key=lambda e: e.get("risk_score", 0), reverse=True)[:10],
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CDB SENTINEL APEX — Premium Report Engine v52")
    parser.add_argument("--type", choices=["executive_briefing", "tactical_ioc", "campaign", "vulnerability", "weekly"],
                        default="executive_briefing", help="Report type")
    parser.add_argument("--days", type=int, default=7, help="Time range in days")
    parser.add_argument("--title", help="Custom report title")
    parser.add_argument("--classification", default="TLP:AMBER", help="TLP classification")
    args = parser.parse_args()

    engine = PremiumReportEngine()
    config = ReportConfig(
        report_type=args.type,
        time_range_days=args.days,
        title=args.title,
        classification=args.classification,
    )
    output = engine.generate(config)
    print(json.dumps({
        "report_id": output.report_id,
        "title": output.title,
        "html_path": output.html_path,
        "stix_path": output.stix_path,
        "json_path": output.json_path,
        "stats": output.stats,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
