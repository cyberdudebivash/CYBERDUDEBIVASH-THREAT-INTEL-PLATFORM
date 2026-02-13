import { useState, useEffect, useCallback } from "react";

const API_BASE = "";

// ═══════════════════════════════════════════════════
// DESIGN TOKENS
// ═══════════════════════════════════════════════════
const T = {
  bg: "#060a10",
  bgCard: "#0c1218",
  bgHover: "#111a24",
  bgAccent: "#0d1f2d",
  accent: "#00d4aa",
  accentDim: "rgba(0,212,170,0.12)",
  accentGlow: "rgba(0,212,170,0.25)",
  blue: "#3b82f6",
  purple: "#8b5cf6",
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  text: "#e2e8f0",
  textMuted: "#64748b",
  border: "#1e293b",
  white: "#f8fafc",
  fontHeading: "'DM Sans', 'Segoe UI', sans-serif",
  fontBody: "'DM Sans', 'Segoe UI', sans-serif",
  fontMono: "'JetBrains Mono', 'Fira Code', monospace",
};

const sevColor = (s) =>
  ({ CRITICAL: T.critical, HIGH: T.high, MEDIUM: T.medium, LOW: T.low }[
    (s || "").toUpperCase()
  ] || T.textMuted);

// ═══════════════════════════════════════════════════
// REUSABLE COMPONENTS
// ═══════════════════════════════════════════════════

function Badge({ children, color, bg }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "3px 10px",
        borderRadius: 100,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        color: color || T.accent,
        background: bg || T.accentDim,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function Card({ children, style, glow, borderColor }) {
  return (
    <div
      style={{
        background: T.bgCard,
        border: `1px solid ${borderColor || T.border}`,
        borderRadius: 14,
        padding: "20px 22px",
        boxShadow: glow
          ? `0 0 20px ${T.accentGlow}, inset 0 1px 0 rgba(255,255,255,0.03)`
          : "0 2px 12px rgba(0,0,0,0.3)",
        transition: "all 0.2s",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function StatCard({ icon, label, value, sub, color }) {
  return (
    <Card>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
        <div
          style={{
            width: 44,
            height: 44,
            borderRadius: 12,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 20,
            background: `${color || T.accent}15`,
            flexShrink: 0,
          }}
        >
          {icon}
        </div>
        <div>
          <div style={{ color: T.textMuted, fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>
            {label}
          </div>
          <div style={{ color: T.white, fontSize: 26, fontWeight: 800, fontFamily: T.fontHeading, lineHeight: 1.1 }}>
            {value}
          </div>
          {sub && <div style={{ color: T.textMuted, fontSize: 12, marginTop: 2 }}>{sub}</div>}
        </div>
      </div>
    </Card>
  );
}

function SectionHeader({ icon, title, sub, action }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 14, marginTop: 28 }}>
      <div>
        <h2 style={{ color: T.white, fontSize: 18, fontWeight: 700, margin: 0, fontFamily: T.fontHeading, display: "flex", alignItems: "center", gap: 8 }}>
          <span>{icon}</span> {title}
        </h2>
        {sub && <p style={{ color: T.textMuted, fontSize: 13, margin: "2px 0 0" }}>{sub}</p>}
      </div>
      {action}
    </div>
  );
}

function Btn({ children, onClick, variant = "primary", small, disabled }) {
  const isPrimary = variant === "primary";
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: small ? "6px 14px" : "10px 22px",
        fontSize: small ? 12 : 14,
        fontWeight: 700,
        fontFamily: T.fontBody,
        borderRadius: 100,
        border: isPrimary ? "none" : `2px solid ${T.accent}`,
        background: isPrimary ? T.accent : "transparent",
        color: isPrimary ? T.bg : T.accent,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "all 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function Loader() {
  return (
    <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
      <div style={{ width: 32, height: 32, border: `3px solid ${T.border}`, borderTopColor: T.accent, borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  );
}

function EmptyState({ message }) {
  return (
    <Card>
      <div style={{ textAlign: "center", padding: "24px 0", color: T.textMuted, fontSize: 14 }}>
        {message || "No data available. Click refresh to fetch latest intel."}
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════
// CVE TABLE
// ═══════════════════════════════════════════════════

function CVETable({ cves }) {
  if (!cves || cves.length === 0) return <EmptyState message="No CVEs loaded yet" />;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr>
            {["CVE ID", "CVSS", "EPSS", "Trend", "Severity"].map((h) => (
              <th key={h} style={{ textAlign: "left", padding: "10px 12px", color: T.textMuted, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: `2px solid ${T.border}` }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {cves.map((c) => (
            <tr key={c.id} style={{ borderBottom: `1px solid ${T.border}` }}>
              <td style={{ padding: "10px 12px", color: T.accent, fontWeight: 700, fontFamily: T.fontMono, fontSize: 12 }}>{c.id}</td>
              <td style={{ padding: "10px 12px", color: T.white, fontWeight: 700 }}>{c.cvss ?? "—"}</td>
              <td style={{ padding: "10px 12px", color: T.white }}>{typeof c.epss === "number" ? c.epss.toFixed(3) : "—"}</td>
              <td style={{ padding: "10px 12px" }}>
                <Badge color={c.epss_trend === "STABLE" ? T.textMuted : T.high} bg={c.epss_trend === "STABLE" ? `${T.textMuted}18` : `${T.high}18`}>
                  {c.epss_trend || "STABLE"}
                </Badge>
              </td>
              <td style={{ padding: "10px 12px" }}>
                <Badge color={sevColor(c.severity)} bg={`${sevColor(c.severity)}18`}>
                  {c.severity || "—"}
                </Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// COVERAGE GAPS
// ═══════════════════════════════════════════════════

function GapsList({ gaps }) {
  if (!gaps || gaps.length === 0) return <EmptyState message="No coverage gaps detected" />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {gaps.map((g, i) => (
        <Card key={i} style={{ borderLeft: `3px solid ${sevColor(g.gap_severity)}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
            <div>
              <span style={{ color: T.white, fontWeight: 700, fontSize: 14 }}>{g.technique_id}</span>
              <span style={{ color: T.textMuted, marginLeft: 8, fontSize: 13 }}>{g.technique_name}</span>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <Badge color={sevColor(g.gap_severity)} bg={`${sevColor(g.gap_severity)}18`}>{g.gap_severity}</Badge>
              <Badge color={T.blue} bg={`${T.blue}18`}>{g.tactic}</Badge>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// INTEL FEED
// ═══════════════════════════════════════════════════

function IntelFeed({ items }) {
  if (!items || items.length === 0) return <EmptyState message="No intel items loaded" />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.slice(0, 8).map((item, i) => (
        <Card key={i}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: T.white, fontWeight: 600, fontSize: 14, marginBottom: 4, lineHeight: 1.4, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                {item.title}
              </div>
              <div style={{ color: T.textMuted, fontSize: 12 }}>
                {item.source} · {item.published ? new Date(item.published).toLocaleDateString() : ""}
              </div>
            </div>
            <Badge>{item.source?.substring(0, 12)}</Badge>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════

export default function CDBSentinelDashboard() {
  const [tab, setTab] = useState("overview");
  const [cves, setCves] = useState([]);
  const [kev, setKev] = useState([]);
  const [malware, setMalware] = useState([]);
  const [gaps, setGaps] = useState([]);
  const [intel, setIntel] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [menuOpen, setMenuOpen] = useState(false);

  // Demo data loader (since we can't hit real APIs in artifact)
  const loadDemoData = useCallback(() => {
    setLoading(true);
    setTimeout(() => {
      setCves([
        { id: "CVE-2026-21413", cvss: 9.8, epss: 0.943, epss_trend: "SHARPLY RISING", epss_acceleration: "RAPID", severity: "CRITICAL", description: "Remote code execution via unauthenticated API endpoint" },
        { id: "CVE-2026-20198", cvss: 9.1, epss: 0.872, epss_trend: "RISING", epss_acceleration: "ACCELERATING", severity: "CRITICAL", description: "Authentication bypass in network management" },
        { id: "CVE-2026-3721", cvss: 8.8, epss: 0.654, epss_trend: "RISING", severity: "HIGH", description: "SQL injection in web application framework" },
        { id: "CVE-2026-14002", cvss: 8.5, epss: 0.412, epss_trend: "STABLE", severity: "HIGH", description: "Privilege escalation via kernel driver" },
        { id: "CVE-2026-8847", cvss: 7.5, epss: 0.287, epss_trend: "STABLE", severity: "HIGH", description: "XSS in content management system" },
        { id: "CVE-2026-5519", cvss: 7.2, epss: 0.198, epss_trend: "STABLE", severity: "MEDIUM", description: "Information disclosure via debug endpoint" },
      ]);
      setKev([
        { cveID: "CVE-2026-21413", vendorProject: "Apache", product: "Struts", dueDate: "2026-03-01" },
        { cveID: "CVE-2026-20198", vendorProject: "Cisco", product: "IOS XE", dueDate: "2026-02-28" },
        { cveID: "CVE-2026-3721", vendorProject: "Microsoft", product: "Exchange Server", dueDate: "2026-03-15" },
      ]);
      setMalware([
        { family: "DarkGate", severity: "CRITICAL", sha256: "a1b2c3d4e5f6...", first_seen: "2026-02-13" },
        { family: "AsyncRAT", severity: "HIGH", sha256: "f7e8d9c0b1a2...", first_seen: "2026-02-12" },
        { family: "Lumma Stealer", severity: "HIGH", sha256: "1a2b3c4d5e6f...", first_seen: "2026-02-11" },
        { family: "Remcos", severity: "HIGH", sha256: "9f8e7d6c5b4a...", first_seen: "2026-02-10" },
      ]);
      setGaps([
        { technique_id: "T1190", technique_name: "Exploit Public-Facing Application", tactic: "initial-access", gap_severity: "CRITICAL", status: "UNDETECTED" },
        { technique_id: "T1027", technique_name: "Obfuscated Files or Information", tactic: "defense-evasion", gap_severity: "HIGH", status: "UNDETECTED" },
        { technique_id: "T1486", technique_name: "Data Encrypted for Impact", tactic: "impact", gap_severity: "CRITICAL", status: "UNDETECTED" },
        { technique_id: "T1078", technique_name: "Valid Accounts", tactic: "persistence", gap_severity: "HIGH", status: "UNDETECTED" },
        { technique_id: "T1003", technique_name: "OS Credential Dumping", tactic: "credential-access", gap_severity: "HIGH", status: "UNDETECTED" },
      ]);
      setIntel([
        { title: "Critical Apache Struts RCE Vulnerability Actively Exploited", source: "The Hacker News", published: "2026-02-13T08:00:00Z", guid: "1" },
        { title: "Cisco Patches Emergency IOS XE Auth Bypass", source: "BleepingComputer", published: "2026-02-13T06:30:00Z", guid: "2" },
        { title: "CISA Adds 3 CVEs to Known Exploited Vulnerabilities Catalog", source: "US-CERT", published: "2026-02-12T21:00:00Z", guid: "3" },
        { title: "New DarkGate Malware Campaign Targets Financial Sector", source: "SecurityWeek", published: "2026-02-12T14:00:00Z", guid: "4" },
        { title: "Microsoft Exchange Server Zero-Day Under Active Attack", source: "KrebsOnSecurity", published: "2026-02-12T10:00:00Z", guid: "5" },
        { title: "Lumma Stealer Distributed via GitHub Repos", source: "DarkReading", published: "2026-02-11T16:00:00Z", guid: "6" },
      ]);
      setLastRefresh(new Date());
      setLoading(false);
    }, 800);
  }, []);

  useEffect(() => { loadDemoData(); }, [loadDemoData]);

  const tabs = [
    { id: "overview", label: "Overview", icon: "📊" },
    { id: "cves", label: "CVEs", icon: "🔴" },
    { id: "feed", label: "Intel Feed", icon: "📡" },
    { id: "gaps", label: "ATT&CK Gaps", icon: "🎯" },
    { id: "api", label: "API Access", icon: "🔌" },
  ];

  const critCount = cves.filter((c) => (c.severity || "").toUpperCase() === "CRITICAL").length;
  const highCount = cves.filter((c) => (c.severity || "").toUpperCase() === "HIGH").length;

  return (
    <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: T.fontBody }}>
      {/* ──── NAVBAR ──── */}
      <nav style={{ position: "sticky", top: 0, zIndex: 100, background: "rgba(6,10,16,0.92)", backdropFilter: "blur(12px)", borderBottom: `1px solid ${T.border}`, padding: "0 20px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", height: 56 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${T.accent}, ${T.blue})`, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 14, color: T.bg }}>
              S
            </div>
            <span style={{ fontWeight: 800, fontSize: 16, color: T.white, fontFamily: T.fontHeading }}>
              CDB-SENTINEL
            </span>
            <Badge color={T.accent} bg={T.accentDim}>v1.0</Badge>
          </div>

          {/* Desktop tabs */}
          <div style={{ display: "flex", gap: 2 }}>
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => { setTab(t.id); setMenuOpen(false); }}
                style={{
                  padding: "8px 14px",
                  fontSize: 13,
                  fontWeight: tab === t.id ? 700 : 500,
                  color: tab === t.id ? T.accent : T.textMuted,
                  background: tab === t.id ? T.accentDim : "transparent",
                  border: "none",
                  borderRadius: 8,
                  cursor: "pointer",
                  fontFamily: T.fontBody,
                  transition: "all 0.15s",
                }}
              >
                <span style={{ marginRight: 4 }}>{t.icon}</span> {t.label}
              </button>
            ))}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {lastRefresh && (
              <span style={{ color: T.textMuted, fontSize: 11 }}>
                Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
            <Btn onClick={loadDemoData} small disabled={loading}>
              {loading ? "⟳" : "↻"} Refresh
            </Btn>
          </div>
        </div>
      </nav>

      {/* ──── CONTENT ──── */}
      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "20px 20px 60px" }}>
        {loading && <Loader />}

        {/* OVERVIEW TAB */}
        {!loading && tab === "overview" && (
          <>
            {/* Stats Row */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 20 }}>
              <StatCard icon="🔴" label="Critical CVEs" value={critCount} sub="Immediate action required" color={T.critical} />
              <StatCard icon="🟠" label="High CVEs" value={highCount} sub="Patch within 48h" color={T.high} />
              <StatCard icon="⚡" label="Active KEVs" value={kev.length} sub="CISA confirmed exploited" color={T.high} />
              <StatCard icon="🧬" label="Malware Families" value={malware.length} sub="Active campaigns detected" color={T.purple} />
              <StatCard icon="🎯" label="ATT&CK Gaps" value={gaps.length} sub="Undetected techniques" color={T.critical} />
              <StatCard icon="📡" label="Intel Items" value={intel.length} sub="From global feeds" color={T.accent} />
            </div>

            {/* Two-column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div>
                <SectionHeader icon="🔴" title="Top CVEs" sub="Ranked by exploitation risk" />
                <CVETable cves={cves.slice(0, 4)} />

                <SectionHeader icon="⚡" title="CISA KEV Alerts" sub="Confirmed active exploitation" />
                {kev.length > 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {kev.map((k, i) => (
                      <Card key={i} style={{ borderLeft: `3px solid ${T.critical}` }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <span style={{ color: T.white, fontWeight: 700, fontSize: 14, fontFamily: T.fontMono }}>{k.cveID}</span>
                            <div style={{ color: T.textMuted, fontSize: 12, marginTop: 2 }}>
                              {k.vendorProject} — {k.product}
                            </div>
                          </div>
                          <Badge color={T.critical} bg={`${T.critical}18`}>EXPLOITED</Badge>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : <EmptyState />}
              </div>

              <div>
                <SectionHeader icon="📡" title="Latest Threat Intel" sub="Global feed aggregation" />
                <IntelFeed items={intel} />

                <SectionHeader icon="🧬" title="Active Malware" sub="MalwareBazaar detections" />
                {malware.length > 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {malware.map((m, i) => (
                      <Card key={i}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <span style={{ color: T.white, fontWeight: 700, fontSize: 14 }}>{m.family}</span>
                            <div style={{ color: T.textMuted, fontSize: 11, fontFamily: T.fontMono, marginTop: 2 }}>{m.sha256}</div>
                          </div>
                          <Badge color={sevColor(m.severity)} bg={`${sevColor(m.severity)}18`}>{m.severity}</Badge>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : <EmptyState />}
              </div>
            </div>
          </>
        )}

        {/* CVE TAB */}
        {!loading && tab === "cves" && (
          <>
            <SectionHeader icon="🔴" title="CVE Intelligence" sub={`${cves.length} vulnerabilities with EPSS enrichment`} />
            <Card><CVETable cves={cves} /></Card>
          </>
        )}

        {/* INTEL FEED TAB */}
        {!loading && tab === "feed" && (
          <>
            <SectionHeader icon="📡" title="Global Threat Intelligence Feed" sub="8+ sources aggregated in real-time" />
            <IntelFeed items={intel} />
          </>
        )}

        {/* ATT&CK GAPS TAB */}
        {!loading && tab === "gaps" && (
          <>
            <SectionHeader icon="🎯" title="MITRE ATT&CK Coverage Gaps" sub={`${gaps.length} undetected techniques requiring attention`} />
            <GapsList gaps={gaps} />
          </>
        )}

        {/* API ACCESS TAB */}
        {!loading && tab === "api" && (
          <>
            <SectionHeader icon="🔌" title="API Access" sub="Integrate CDB-SENTINEL into your SOC workflow" />

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
              {[
                { tier: "Free", price: "$0", limit: "60 req/hr", color: T.accent, features: ["CVE feed", "KEV alerts", "Basic reports", "Community support"] },
                { tier: "Pro", price: "$49/mo", limit: "600 req/hr", color: T.blue, features: ["Everything in Free", "STIX/MISP export", "ATT&CK analysis", "Detection rules", "Priority support"] },
                { tier: "Enterprise", price: "Custom", limit: "6000 req/hr", color: T.purple, features: ["Everything in Pro", "Custom feeds", "SIEM connectors", "SLA guarantee", "Dedicated support", "On-prem option"] },
              ].map((plan) => (
                <Card key={plan.tier} glow={plan.tier === "Pro"} borderColor={plan.tier === "Pro" ? T.accent : undefined}>
                  <div style={{ textAlign: "center", marginBottom: 16 }}>
                    <Badge color={plan.color} bg={`${plan.color}18`}>{plan.tier}</Badge>
                    <div style={{ color: T.white, fontSize: 28, fontWeight: 800, marginTop: 8, fontFamily: T.fontHeading }}>{plan.price}</div>
                    <div style={{ color: T.textMuted, fontSize: 12 }}>{plan.limit}</div>
                  </div>
                  <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                    {plan.features.map((f, i) => (
                      <li key={i} style={{ padding: "6px 0", fontSize: 13, color: T.text, borderBottom: `1px solid ${T.border}` }}>
                        <span style={{ color: T.accent, marginRight: 8 }}>✓</span> {f}
                      </li>
                    ))}
                  </ul>
                  <div style={{ textAlign: "center", marginTop: 16 }}>
                    <Btn variant={plan.tier === "Pro" ? "primary" : "outline"} small>
                      {plan.tier === "Enterprise" ? "Contact Sales" : "Get Started"}
                    </Btn>
                  </div>
                </Card>
              ))}
            </div>

            <SectionHeader icon="📖" title="API Endpoints" sub="RESTful JSON API with OpenAPI documentation" />
            <Card>
              <div style={{ fontFamily: T.fontMono, fontSize: 13 }}>
                {[
                  { method: "GET", path: "/api/v1/intel/cves", desc: "Latest CVEs with EPSS" },
                  { method: "GET", path: "/api/v1/intel/kev", desc: "CISA KEV catalog" },
                  { method: "GET", path: "/api/v1/intel/malware", desc: "Malware activity" },
                  { method: "GET", path: "/api/v1/intel/feed", desc: "RSS threat feed" },
                  { method: "GET", path: "/api/v1/analysis/rank", desc: "Risk-ranked CVEs" },
                  { method: "GET", path: "/api/v1/analysis/gaps", desc: "ATT&CK gaps" },
                  { method: "GET", path: "/api/v1/analysis/detections", desc: "Sigma/KQL rules" },
                  { method: "GET", path: "/api/v1/reports/daily", desc: "Daily report HTML" },
                  { method: "GET", path: "/api/v1/reports/weekly", desc: "Weekly mega-report" },
                  { method: "GET", path: "/api/v1/exports/stix", desc: "STIX 2.1 bundle" },
                  { method: "GET", path: "/api/v1/exports/misp", desc: "MISP event" },
                  { method: "GET", path: "/api/v1/exports/navigator", desc: "ATT&CK Navigator" },
                ].map((ep, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: `1px solid ${T.border}` }}>
                    <span style={{ color: T.accent, fontWeight: 700, width: 40 }}>{ep.method}</span>
                    <span style={{ color: T.white, flex: 1 }}>{ep.path}</span>
                    <span style={{ color: T.textMuted, fontSize: 12 }}>{ep.desc}</span>
                  </div>
                ))}
              </div>
            </Card>

            <SectionHeader icon="🔑" title="Authentication" sub="Include API key in every request" />
            <Card>
              <div style={{ background: T.bg, padding: 16, borderRadius: 8, fontFamily: T.fontMono, fontSize: 13, color: T.text, lineHeight: 1.8, overflowX: "auto" }}>
                <span style={{ color: T.textMuted }}>{"# Using header (recommended)"}</span><br />
                <span style={{ color: T.accent }}>curl</span> -H <span style={{ color: "#f97583" }}>"X-API-Key: your_api_key"</span> \<br />
                &nbsp;&nbsp;https://api.cyberdudebivash.com/api/v1/intel/cves<br /><br />
                <span style={{ color: T.textMuted }}>{"# Using query parameter"}</span><br />
                <span style={{ color: T.accent }}>curl</span> https://api.cyberdudebivash.com/api/v1/intel/cves?api_key=<span style={{ color: "#f97583" }}>your_key</span>
              </div>
            </Card>
          </>
        )}
      </main>

      {/* ──── FOOTER ──── */}
      <footer style={{ borderTop: `1px solid ${T.border}`, padding: "20px 0", textAlign: "center" }}>
        <div style={{ color: T.accent, fontWeight: 800, fontSize: 16, marginBottom: 4 }}>CyberDudeBivash</div>
        <div style={{ color: T.textMuted, fontSize: 12, lineHeight: 1.8 }}>
          Evolve or Extinct — Your Cybersecurity Authority<br />
          © 2024–2026 CyberDudeBivash Pvt. Ltd. — Bhubaneswar, India<br />
          <a href="https://www.cyberdudebivash.com" style={{ color: T.accent, textDecoration: "none" }}>cyberdudebivash.com</a>
          {" · "}
          <a href="mailto:iambivash@cyberdudebivash.com" style={{ color: T.accent, textDecoration: "none" }}>iambivash@cyberdudebivash.com</a>
        </div>
      </footer>
    </div>
  );
}
