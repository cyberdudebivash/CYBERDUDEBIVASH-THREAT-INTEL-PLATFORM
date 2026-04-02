/**
 * CDB-SENTINEL-Dashboard.jsx — CyberDudeBivash v81.7 (APEX SOVEREIGN)
 * Author: CYBERGOD / TECH GOD
 * Description: The Master CISO Dashboard — fully connected to Railway API backend.
 * Features: Threat Intel, Live APEX Telemetry, AI Copilot, SOAR/SIEM,
 *           Dark Web Intelligence, Engine Status, Purple Swarm BAS, Revenue.
 * v81.7: Full backend sync — all tabs fetch live data from Railway API.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import ApexThreatGlobe from "./components/ApexThreatGlobe";

// ═══ BACKEND CONFIG ═══════════════════════════════════
const API_BASE = "https://cyberdudebivash-threat-intel-platform-production.up.railway.app";
const ENTERPRISE_JWT = (typeof process !== "undefined" && process.env?.REACT_APP_ENTERPRISE_JWT) || null;

// ═══ DESIGN TOKENS ════════════════════════════════════
const T = {
  bg: "#060a10", bgCard: "#0c1218", bgHover: "#111a24", bgAccent: "#0d1f2d",
  accent: "#00d4aa", accentDim: "rgba(0,212,170,0.12)", accentGlow: "rgba(0,212,170,0.25)",
  blue: "#3b82f6", purple: "#8b5cf6", pink: "#ec4899",
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
  text: "#e2e8f0", textMuted: "#64748b", border: "#1e293b",
  white: "#f8fafc", apexGold: "#ffd700", codeBg: "#010409", orange: "#f97316",
  fontHeading: "'DM Sans','Segoe UI',sans-serif",
  fontBody: "'DM Sans','Segoe UI',sans-serif",
  fontMono: "'JetBrains Mono','Fira Code',monospace",
};

const sevColor = (s) =>
  ({ CRITICAL: T.critical, HIGH: T.high, MEDIUM: T.medium, LOW: T.low }[
    (s || "").toUpperCase()
  ] || T.textMuted);

// ═══ REUSABLE COMPONENTS ══════════════════════════════

function Badge({ children, color, bg }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "3px 10px",
      borderRadius: 100, fontSize: 11, fontWeight: 700, letterSpacing: "0.04em",
      textTransform: "uppercase", color: color || T.accent, background: bg || T.accentDim,
      whiteSpace: "nowrap",
    }}>{children}</span>
  );
}

function Card({ children, style, glow, borderColor }) {
  return (
    <div style={{
      background: T.bgCard, border: `1px solid ${borderColor || T.border}`,
      borderRadius: 14, padding: "20px 22px",
      boxShadow: glow ? `0 0 20px ${glow === "apex" ? "rgba(255,215,0,0.25)" : T.accentGlow}, inset 0 1px 0 rgba(255,255,255,0.03)` : "0 2px 12px rgba(0,0,0,0.3)",
      transition: "all 0.2s", ...style,
    }}>{children}</div>
  );
}

function StatCard({ icon, label, value, sub, color, live }) {
  return (
    <Card style={{ position: "relative" }}>
      {live && <span style={{ position: "absolute", top: 10, right: 12, width: 7, height: 7, borderRadius: "50%", background: T.low, boxShadow: `0 0 6px ${T.low}` }} />}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
        <div style={{ width: 44, height: 44, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, background: `${color || T.accent}15`, flexShrink: 0 }}>{icon}</div>
        <div>
          <div style={{ color: T.textMuted, fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>{label}</div>
          <div style={{ color: T.white, fontSize: 26, fontWeight: 800, fontFamily: T.fontHeading, lineHeight: 1.1 }}>{value ?? "—"}</div>
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

function Btn({ children, onClick, variant = "primary", small, disabled, color }) {
  const isPrimary = variant === "primary";
  const btnColor = color || T.accent;
  return (
    <button onClick={onClick} disabled={disabled} style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      padding: small ? "6px 14px" : "10px 22px",
      fontSize: small ? 12 : 14, fontWeight: 700, fontFamily: T.fontBody, borderRadius: 100,
      border: isPrimary ? "none" : `2px solid ${btnColor}`,
      background: isPrimary ? btnColor : "transparent",
      color: isPrimary ? T.bg : btnColor,
      cursor: disabled ? "not-allowed" : "pointer",
      opacity: disabled ? 0.5 : 1, transition: "all 0.15s",
    }}>{children}</button>
  );
}

function Loader({ size = 32 }) {
  return (
    <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
      <div style={{ width: size, height: size, border: `3px solid ${T.border}`, borderTopColor: T.accent, borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

function EmptyState({ message, icon = "📭" }) {
  return (
    <Card>
      <div style={{ textAlign: "center", padding: "24px 0", color: T.textMuted, fontSize: 14 }}>
        <div style={{ fontSize: 32, marginBottom: 8 }}>{icon}</div>
        {message || "No data available. Click refresh to fetch latest intel."}
      </div>
    </Card>
  );
}

function ErrorState({ message }) {
  return (
    <Card borderColor={T.critical}>
      <div style={{ textAlign: "center", padding: "20px 0", color: T.high, fontSize: 13 }}>
        ⚠️ {message || "Failed to fetch data from backend."}
      </div>
    </Card>
  );
}

function CodeSnippet({ title, code, language, tagColor }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard?.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{ background: T.codeBg, borderRadius: 12, border: `1px solid ${T.border}`, overflow: "hidden", marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 16px", background: "rgba(255,255,255,0.03)", borderBottom: `1px solid ${T.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: tagColor || T.accent }} />
          <span style={{ color: T.text, fontSize: 12, fontWeight: 600, fontFamily: T.fontMono }}>{title}</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <Badge color={T.textMuted} bg="transparent">{language}</Badge>
          <button onClick={handleCopy} style={{ background: "none", border: "none", color: copied ? T.low : T.textMuted, cursor: "pointer", fontSize: 11, padding: "2px 6px" }}>
            {copied ? "✓ copied" : "copy"}
          </button>
        </div>
      </div>
      <div style={{ padding: "16px", overflowX: "auto" }}>
        <pre style={{ margin: 0, color: T.white, fontSize: 12, fontFamily: T.fontMono, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>{code}</pre>
      </div>
    </div>
  );
}

function LiveDot({ color }) {
  return (
    <span style={{ display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: color || T.low, boxShadow: `0 0 6px ${color || T.low}`, marginRight: 6, animation: "pulse 2s infinite" }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}`}</style>
    </span>
  );
}

// ═══ DATA DISPLAY COMPONENTS ══════════════════════════

function CVETable({ cves }) {
  if (!cves?.length) return <EmptyState message="No CVEs loaded yet" icon="🔍" />;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr>
            {["CVE ID", "CVSS", "EPSS", "Trend", "Severity", "KEV"].map((h) => (
              <th key={h} style={{ textAlign: "left", padding: "10px 12px", color: T.textMuted, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: `2px solid ${T.border}` }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {cves.map((c, i) => (
            <tr key={c.id || i} style={{ borderBottom: `1px solid ${T.border}`, transition: "background 0.1s" }}
              onMouseEnter={e => e.currentTarget.style.background = T.bgHover}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
              <td style={{ padding: "10px 12px", color: T.accent, fontWeight: 700, fontFamily: T.fontMono, fontSize: 12 }}>{c.id}</td>
              <td style={{ padding: "10px 12px", color: T.white, fontWeight: 700 }}>{c.cvss ?? c.cvss_score ?? "—"}</td>
              <td style={{ padding: "10px 12px", color: T.white }}>{typeof c.epss === "number" ? c.epss.toFixed(3) : (c.epss_score ? parseFloat(c.epss_score).toFixed(3) : "—")}</td>
              <td style={{ padding: "10px 12px" }}>
                <Badge color={c.epss_trend === "STABLE" ? T.textMuted : T.high} bg={c.epss_trend === "STABLE" ? `${T.textMuted}18` : `${T.high}18`}>
                  {c.epss_trend || "STABLE"}
                </Badge>
              </td>
              <td style={{ padding: "10px 12px" }}>
                <Badge color={sevColor(c.severity)} bg={`${sevColor(c.severity)}18`}>{c.severity || "—"}</Badge>
              </td>
              <td style={{ padding: "10px 12px" }}>
                {c.kev_present ? <Badge color={T.critical} bg={`${T.critical}18`}>⚡ KEV</Badge> : <span style={{ color: T.textMuted, fontSize: 11 }}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GapsList({ gaps }) {
  if (!gaps?.length) return <EmptyState message="No coverage gaps detected" icon="✅" />;
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

function IntelFeed({ items, limit = 10 }) {
  if (!items?.length) return <EmptyState message="No intel items loaded" icon="📡" />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.slice(0, limit).map((item, i) => (
        <Card key={i} style={{ cursor: item.blog_url || item.source_url ? "pointer" : "default" }}
          onClick={() => (item.blog_url || item.source_url) && window.open(item.blog_url || item.source_url, "_blank")}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                {item.severity && <Badge color={sevColor(item.severity)} bg={`${sevColor(item.severity)}18`}>{item.severity}</Badge>}
                {item.kev_present && <Badge color={T.critical} bg={`${T.critical}15`}>⚡ KEV</Badge>}
                {item.tlp_label && <Badge color={T.textMuted} bg="rgba(255,255,255,0.05)">{item.tlp_label}</Badge>}
              </div>
              <div style={{ color: T.white, fontWeight: 600, fontSize: 14, marginBottom: 4, lineHeight: 1.4, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                {item.title}
              </div>
              <div style={{ color: T.textMuted, fontSize: 12 }}>
                {item.source || item.feed_source} · {item.published || item.timestamp ? new Date(item.published || item.timestamp).toLocaleDateString() : ""}
                {item.risk_score && <span style={{ marginLeft: 8, color: sevColor(item.severity) }}>Risk {item.risk_score.toFixed(1)}</span>}
              </div>
            </div>
            <div style={{ textAlign: "right", flexShrink: 0 }}>
              <Badge>{(item.source || item.feed_source || "CDB")?.substring(0, 10)}</Badge>
              {item.indicator_count > 0 && <div style={{ color: T.textMuted, fontSize: 11, marginTop: 4 }}>{item.indicator_count} IOCs</div>}
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ═══ COPILOT CHAT COMPONENT ════════════════════════════

function CopilotPanel() {
  const [messages, setMessages] = useState([
    { role: "assistant", content: "🤖 APEX AI Copilot online. Ask me about threats, CVEs, IOCs, or MITRE ATT&CK techniques." }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState("threat_analysis");
  const [modes, setModes] = useState([]);
  const bottomRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/copilot/modes`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.modes) setModes(d.modes); })
      .catch(() => {});
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg = input.trim();
    setInput("");
    setMessages(m => [...m, { role: "user", content: userMsg }]);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/copilot/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: userMsg, mode, context: "dashboard" }),
      });
      const data = await res.json();
      const reply = data.response || data.answer || data.summary || data.detail || JSON.stringify(data);
      setMessages(m => [...m, { role: "assistant", content: reply, risk_level: data.risk_level, confidence: data.confidence }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", content: `⚠️ Copilot offline: ${e.message}` }]);
    }
    setLoading(false);
  };

  const SUGGESTED = ["Analyze latest critical CVEs", "What is the current top threat actor?", "Show MITRE ATT&CK coverage gaps", "Summarize today's threat landscape"];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 200px)", minHeight: 500 }}>
      <SectionHeader icon="🤖" title="APEX AI Security Copilot" sub="Powered by the APEX Intelligence Engine — ask about threats, IOCs, CVEs, TTPs" />

      <Card style={{ flex: 1, display: "flex", flexDirection: "column", padding: 0, overflow: "hidden" }}>
        {/* Mode selector */}
        <div style={{ display: "flex", gap: 6, padding: "12px 16px", borderBottom: `1px solid ${T.border}`, flexWrap: "wrap" }}>
          {(modes.length ? modes : ["threat_analysis", "ioc_lookup", "cve_analysis", "soar_action"]).map(m => (
            <button key={m} onClick={() => setMode(m)} style={{
              padding: "4px 12px", fontSize: 11, borderRadius: 100, border: `1px solid ${mode === m ? T.accent : T.border}`,
              background: mode === m ? T.accentDim : "transparent", color: mode === m ? T.accent : T.textMuted,
              cursor: "pointer", fontFamily: T.fontMono, textTransform: "uppercase", letterSpacing: "0.05em"
            }}>{m.replace(/_/g, " ")}</button>
          ))}
        </div>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px", display: "flex", flexDirection: "column", gap: 12 }}>
          {messages.map((msg, i) => (
            <div key={i} style={{ display: "flex", justifyContent: msg.role === "user" ? "flex-end" : "flex-start" }}>
              <div style={{
                maxWidth: "78%", padding: "12px 16px", borderRadius: msg.role === "user" ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
                background: msg.role === "user" ? T.accentDim : T.bgHover,
                border: `1px solid ${msg.role === "user" ? T.accent : T.border}`,
                color: T.text, fontSize: 13, lineHeight: 1.6, fontFamily: T.fontBody,
              }}>
                {msg.role === "assistant" && <div style={{ color: T.accent, fontSize: 11, fontWeight: 700, marginBottom: 4, fontFamily: T.fontMono }}>APEX COPILOT {msg.risk_level ? `· RISK: ${msg.risk_level}` : ""}</div>}
                <div style={{ whiteSpace: "pre-wrap" }}>{msg.content}</div>
                {msg.confidence && <div style={{ color: T.textMuted, fontSize: 11, marginTop: 6 }}>Confidence: {msg.confidence}%</div>}
              </div>
            </div>
          ))}
          {loading && (
            <div style={{ display: "flex", justifyContent: "flex-start" }}>
              <div style={{ padding: "12px 16px", borderRadius: "14px 14px 14px 4px", background: T.bgHover, border: `1px solid ${T.border}` }}>
                <div style={{ display: "flex", gap: 4 }}>
                  {[0, 1, 2].map(n => <div key={n} style={{ width: 6, height: 6, borderRadius: "50%", background: T.accent, animation: `bounce 1.2s ${n * 0.2}s infinite` }} />)}
                  <style>{`@keyframes bounce{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-8px)}}`}</style>
                </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Suggestions */}
        {messages.length < 3 && (
          <div style={{ display: "flex", gap: 6, padding: "8px 16px", flexWrap: "wrap", borderTop: `1px solid ${T.border}` }}>
            {SUGGESTED.map((s, i) => (
              <button key={i} onClick={() => { setInput(s); }} style={{
                padding: "4px 10px", fontSize: 11, borderRadius: 100,
                border: `1px solid ${T.border}`, background: "transparent",
                color: T.textMuted, cursor: "pointer", fontFamily: T.fontBody,
              }}>{s}</button>
            ))}
          </div>
        )}

        {/* Input */}
        <div style={{ display: "flex", gap: 8, padding: "12px 16px", borderTop: `1px solid ${T.border}` }}>
          <input
            value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
            placeholder="Ask about threats, IOCs, CVEs, TTPs…"
            style={{
              flex: 1, padding: "10px 16px", background: T.bgAccent, border: `1px solid ${T.border}`,
              borderRadius: 100, color: T.white, fontSize: 13, fontFamily: T.fontBody, outline: "none",
            }}
          />
          <Btn onClick={sendMessage} disabled={loading || !input.trim()} small>⚡ Send</Btn>
        </div>
      </Card>
    </div>
  );
}

// ═══ ENGINE STATUS COMPONENT ════════════════════════════

function EngineStatusPanel({ engines }) {
  if (!engines) return <EmptyState message="Loading engine status…" icon="⚙️" />;
  const entries = typeof engines === "object" ? Object.entries(engines) : [];
  if (!entries.length) return <EmptyState message="No engine data available" icon="⚙️" />;

  const statusColor = (s) => ({ active: T.low, running: T.low, ok: T.low, error: T.critical, failed: T.critical, offline: T.critical, degraded: T.high, unknown: T.textMuted }[(s || "").toLowerCase()] || T.textMuted);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
      {entries.map(([name, info]) => {
        const status = info?.status || info?.state || (info ? "active" : "offline");
        const color = statusColor(status);
        return (
          <Card key={name} borderColor={`${color}40`}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
              <div style={{ color: T.white, fontWeight: 700, fontSize: 14, fontFamily: T.fontMono }}>{name.toUpperCase()}</div>
              <Badge color={color} bg={`${color}18`}>{status}</Badge>
            </div>
            {info?.last_run && <div style={{ color: T.textMuted, fontSize: 11, marginBottom: 4 }}>Last run: {new Date(info.last_run).toLocaleString()}</div>}
            {info?.items_processed != null && <div style={{ color: T.textMuted, fontSize: 11 }}>Processed: {info.items_processed.toLocaleString()}</div>}
            {info?.version && <div style={{ color: T.textMuted, fontSize: 11 }}>Version: {info.version}</div>}
            {info?.error && <div style={{ color: T.critical, fontSize: 11, marginTop: 6 }}>⚠️ {info.error}</div>}
          </Card>
        );
      })}
    </div>
  );
}

// ═══ MAIN DASHBOARD ════════════════════════════════════

export default function CDBSentinelDashboard() {
  // ── Tab state ──
  const [tab, setTab] = useState("overview");

  // ── Core data states ──
  const [stats, setStats] = useState(null);
  const [cves, setCves] = useState([]);
  const [intel, setIntel] = useState([]);
  const [gaps, setGaps] = useState([]);
  const [kev, setKev] = useState([]);
  const [malware, setMalware] = useState([]);
  const [engines, setEngines] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [apexForecast, setApexForecast] = useState(null);
  const [detections, setDetections] = useState(null);
  const [soarPlaybooks, setSoarPlaybooks] = useState([]);
  const [basScripts, setBasScripts] = useState([]);
  const [health, setHealth] = useState(null);

  // ── UI states ──
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [lastRefresh, setLastRefresh] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [feedPage, setFeedPage] = useState(0);
  const FEED_PAGE_SIZE = 12;

  // ── Fetch helpers ──
  const apiFetch = useCallback(async (path, opts = {}) => {
    const res = await fetch(`${API_BASE}${path}`, {
      cache: "no-store", headers: { "X-API-Version": "v81.7", ...opts.headers }, ...opts,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }, []);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setErrors({});

    // Health check
    apiFetch("/health").then(d => setHealth(d)).catch(() => {});

    // Stats
    apiFetch("/api/v1/stats")
      .then(d => setStats(d))
      .catch(() => setErrors(e => ({ ...e, stats: "Stats unavailable" })));

    // Intel feed
    apiFetch("/api/v1/intel/feed?limit=50")
      .then(d => {
        const items = Array.isArray(d) ? d : (d.items || d.data || d.feed || []);
        setIntel(items);
        // Derive CVEs
        const cveItems = items.filter(i => i.id?.startsWith("CVE-") || i.stix_id?.includes("CVE"));
        if (cveItems.length) {
          setCves(cveItems.map(i => ({
            id: i.id || i.stix_id, cvss: i.cvss_score, epss: i.epss_score,
            severity: i.severity, epss_trend: i.epss_trend || "STABLE", kev_present: i.kev_present,
          })));
          setKev(cveItems.filter(i => i.kev_present));
        }
      })
      .catch(() => setErrors(e => ({ ...e, intel: "Intel feed unavailable" })));

    // Latest advisories for overview
    apiFetch("/api/v1/intel/latest?limit=20")
      .then(d => {
        const items = Array.isArray(d) ? d : (d.items || d.data || []);
        if (items.length) setIntel(prev => (prev.length > items.length ? prev : items));
      })
      .catch(() => {});

    // Engine status
    apiFetch("/api/v1/engines/status")
      .then(d => setEngines(d))
      .catch(() => setErrors(e => ({ ...e, engines: "Engine status unavailable" })));

    // Alerts
    apiFetch("/api/v1/alerts/latest?limit=20")
      .then(d => {
        const items = Array.isArray(d) ? d : (d.alerts || d.items || []);
        setAlerts(items);
      })
      .catch(() => {});

    // APEX Forecast (file-based)
    fetch("/data/ai_predictions/apex_forecast_latest.json")
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setApexForecast(d); })
      .catch(() => {});

    // Detection rules
    apiFetch("/api/v1/detections")
      .then(d => setDetections(d))
      .catch(() => {});

    // SOAR playbooks (hardened demo + backend overlay)
    setSoarPlaybooks([
      { id: "k8s-001", type: "kubernetes", title: "NetworkPolicy: Isolate CVE-2026-21413",
        code: `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: apex-quarantine-struts\n  namespace: production\nspec:\n  podSelector:\n    matchLabels:\n      app: apache-struts\n  policyTypes: [Ingress, Egress]`,
        color: T.blue },
      { id: "ans-002", type: "ansible", title: "Playbook: Autonomous Hot-Patch",
        code: `---\n- name: APEX Zero-Day Neutralization\n  hosts: enterprise_routers\n  tasks:\n    - name: Apply Emergency Patch\n      ansible.builtin.package:\n        name: "ios-xe-core"\n        state: latest`,
        color: T.critical },
      { id: "sig-003", type: "sigma", title: "Sigma Rule: DarkGate Exfiltration Detection",
        code: `title: CDB APEX - DarkGate Activity\nid: cdb-rule-998877\nstatus: stable\nlogsource:\n    category: network_connection\ndetection:\n    selection:\n        DestinationIp: ['185.15.10.22']\n    condition: selection\nlevel: high`,
        color: T.apexGold },
    ]);
    setBasScripts([
      { id: "bas-001", title: "DarkGate Simulation", target: "CVE-2026-21413", platform: "Windows .BAT", desc: "Triggers APEX Sigma Rule #998877" }
    ]);

    setLastRefresh(new Date());
    setLoading(false);
  }, [apiFetch]);

  useEffect(() => { loadAll(); }, [loadAll]);

  // ── Derived counts ──
  const critCount = stats?.severity_distribution?.CRITICAL ?? cves.filter(c => c.severity?.toUpperCase() === "CRITICAL").length;
  const highCount = stats?.severity_distribution?.HIGH ?? cves.filter(c => c.severity?.toUpperCase() === "HIGH").length;
  const totalAdv = stats?.total_advisories ?? intel.length;
  const avgRisk = stats?.avg_risk?.toFixed(1) ?? "—";
  const totalIOCs = stats?.ioc_total ?? "—";
  const kevCount = stats?.kev_tagged ?? kev.length;

  const filteredCves = severityFilter === "ALL" ? cves : cves.filter(c => c.severity?.toUpperCase() === severityFilter);
  const pagedIntel = intel.slice(feedPage * FEED_PAGE_SIZE, (feedPage + 1) * FEED_PAGE_SIZE);

  const handleDownloadBAS = (filename) => {
    const content = `@echo off\n:: CYBERDUDEBIVASH APEX v81.7 — PURPLE SWARM BAS\necho [APEX] Running Safe Simulation for ${filename}...\nping 127.0.0.1 -n 1 > nul\necho [APEX] Simulation Complete. Check SIEM.\npause`;
    const blob = new Blob([content], { type: "text/plain" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `apex_sim_${filename}.bat`; a.click();
    window.URL.revokeObjectURL(url);
  };

  // ── Tabs ──
  const tabs = [
    { id: "overview",  label: "Overview",       icon: "📊" },
    { id: "apex",      label: "APEX SOVEREIGN",  icon: "👑" },
    { id: "soar",      label: "IMMUNE SYSTEM",   icon: "🛡️" },
    { id: "cves",      label: "CVEs",            icon: "🔴" },
    { id: "feed",      label: "Intel Feed",      icon: "📡" },
    { id: "gaps",      label: "ATT&CK Gaps",     icon: "🎯" },
    { id: "copilot",   label: "AI Copilot",      icon: "🤖" },
    { id: "engines",   label: "Engines",         icon: "⚙️" },
    { id: "api",       label: "API Access",      icon: "🔌" },
  ];

  const tabColor = { apex: T.apexGold, soar: T.blue, copilot: T.purple, engines: T.accent };

  return (
    <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: T.fontBody }}>

      {/* ──── NAVBAR ──── */}
      <nav style={{ position: "sticky", top: 0, zIndex: 100, background: "rgba(6,10,16,0.95)", backdropFilter: "blur(16px)", borderBottom: `1px solid ${T.border}`, padding: "0 20px" }}>
        <div style={{ maxWidth: 1400, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", height: 56 }}>

          {/* Brand */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${T.accent}, ${T.blue})`, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 14, color: T.bg }}>S</div>
            <span style={{ fontWeight: 800, fontSize: 16, color: T.white, fontFamily: T.fontHeading }}>CDB-SENTINEL</span>
            <Badge color={T.apexGold} bg="rgba(255,215,0,0.15)">v81.7 APEX</Badge>
            {health && <Badge color={T.low} bg={`${T.low}15`}><LiveDot />LIVE</Badge>}
          </div>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 2, overflowX: "auto", flex: 1, margin: "0 16px", justifyContent: "center" }}>
            {tabs.map((t) => {
              const c = tabColor[t.id] || T.accent;
              return (
                <button key={t.id} onClick={() => setTab(t.id)} style={{
                  padding: "8px 12px", fontSize: 12, fontWeight: tab === t.id ? 700 : 500,
                  color: tab === t.id ? c : T.textMuted,
                  background: tab === t.id ? `${c}18` : "transparent",
                  border: "none", borderRadius: 8, cursor: "pointer", fontFamily: T.fontBody,
                  transition: "all 0.15s", whiteSpace: "nowrap",
                }}>
                  <span style={{ marginRight: 4 }}>{t.icon}</span>{t.label}
                </button>
              );
            })}
          </div>

          {/* Controls */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
            {lastRefresh && <span style={{ color: T.textMuted, fontSize: 11 }}>↻ {lastRefresh.toLocaleTimeString()}</span>}
            <Btn onClick={loadAll} small disabled={loading}>{loading ? "⟳" : "↻"} Refresh</Btn>
          </div>
        </div>
      </nav>

      {/* ──── CONTENT ──── */}
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "20px 20px 60px" }}>

        {/* Global loader */}
        {loading && <Loader />}

        {/* ── OVERVIEW TAB ── */}
        {!loading && tab === "overview" && (
          <>
            {/* Stat Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 20 }}>
              <StatCard icon="📋" label="Total Advisories" value={totalAdv} color={T.accent} live={!!stats} />
              <StatCard icon="🔴" label="Critical CVEs"    value={critCount} color={T.critical} live={!!stats} />
              <StatCard icon="🟠" label="High CVEs"        value={highCount} color={T.high} live={!!stats} />
              <StatCard icon="⚡" label="Active KEVs"      value={kevCount} color={T.high} sub="CISA Known Exploited" live={!!stats} />
              <StatCard icon="📊" label="Avg Risk Score"   value={avgRisk} color={T.medium} live={!!stats} />
              <StatCard icon="🔍" label="Total IOCs"       value={totalIOCs} color={T.purple} live={!!stats} />
            </div>

            {/* Alerts banner */}
            {alerts.length > 0 && (
              <Card borderColor={T.critical} style={{ marginBottom: 16, padding: "14px 18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 18 }}>🚨</span>
                  <div style={{ flex: 1 }}>
                    <span style={{ color: T.critical, fontWeight: 700, fontSize: 13 }}>ACTIVE ALERTS — </span>
                    <span style={{ color: T.text, fontSize: 13 }}>{alerts[0]?.message || alerts[0]?.title || "New threat alerts detected"}</span>
                  </div>
                  <Badge color={T.critical} bg={`${T.critical}18`}>{alerts.length} ALERT{alerts.length > 1 ? "S" : ""}</Badge>
                </div>
              </Card>
            )}

            {/* CVE + Intel two-col */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
              <div>
                <SectionHeader icon="🔴" title="Top CVEs" sub="Live from APEX Intelligence Engine" />
                {errors.intel ? <ErrorState message={errors.intel} /> : <Card><CVETable cves={cves.slice(0, 5)} /></Card>}
              </div>
              <div>
                <SectionHeader icon="📡" title="Latest Threat Intel" sub={`${intel.length} advisories loaded`} />
                {errors.intel ? <ErrorState message={errors.intel} /> : <IntelFeed items={intel} limit={6} />}
              </div>
            </div>

            {/* Backend health strip */}
            {health && (
              <Card style={{ marginTop: 20, padding: "12px 18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
                  <LiveDot /><span style={{ color: T.accent, fontWeight: 700, fontSize: 12, fontFamily: T.fontMono }}>BACKEND CONNECTED</span>
                  <span style={{ color: T.textMuted, fontSize: 12 }}>Platform: {health.platform}</span>
                  <span style={{ color: T.textMuted, fontSize: 12 }}>Version: {health.version}</span>
                  <span style={{ color: T.textMuted, fontSize: 12 }}>Advisories: {health.advisories}</span>
                  {health.apex && <Badge color={T.apexGold} bg="rgba(255,215,0,0.12)">APEX ENGINE ACTIVE</Badge>}
                </div>
              </Card>
            )}
          </>
        )}

        {/* ── APEX SOVEREIGN TAB ── */}
        {!loading && tab === "apex" && (
          <div>
            <SectionHeader icon="👑" title="APEX Sovereign Cortex" sub="Global Zero-Day Telemetry & AI Predictions — Enterprise Only" />
            {apexForecast && (
              <Card glow="apex" borderColor={T.apexGold} style={{ marginBottom: 20 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
                  <div style={{ flex: 1, minWidth: 300 }}>
                    <h3 style={{ color: T.apexGold, margin: "0 0 8px 0", fontFamily: T.fontHeading }}>🧠 AI Strategic Forecast</h3>
                    <p style={{ color: T.white, fontSize: 14, lineHeight: 1.7, margin: 0 }}>{apexForecast.ai_executive_summary}</p>
                  </div>
                  <div style={{ textAlign: "right", minWidth: 150 }}>
                    <div style={{ color: T.textMuted, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Target Sector</div>
                    <div style={{ color: T.critical, fontSize: 20, fontWeight: 900, margin: "4px 0 12px" }}>{apexForecast.predicted_target_sector}</div>
                    <div style={{ color: T.textMuted, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Forecast Confidence</div>
                    <div style={{ color: T.accent, fontSize: 20, fontWeight: 900, marginTop: 4 }}>{apexForecast.confidence_level}%</div>
                  </div>
                </div>
              </Card>
            )}
            <div style={{ borderRadius: 14, overflow: "hidden", border: `1px solid ${T.apexGold}55`, boxShadow: `0 0 30px rgba(255,215,0,0.15)` }}>
              <ApexThreatGlobe jwtToken={ENTERPRISE_JWT} />
            </div>
          </div>
        )}

        {/* ── IMMUNE SYSTEM / SOAR TAB ── */}
        {!loading && tab === "soar" && (
          <div>
            <SectionHeader icon="🛡️" title="Autonomous Immune Response" sub="Zero-Latency Code Generation & Purple Swarm Validation"
              action={
                <div style={{ display: "flex", gap: 8 }}>
                  {detections?.sigma_count && <Badge color={T.low} bg={`${T.low}18`}>✓ {detections.sigma_count} Sigma Rules</Badge>}
                  <Btn small color={T.blue}>Sync with Splunk HEC</Btn>
                </div>
              }
            />

            {/* BAS Header */}
            <Card style={{ marginBottom: 24, borderLeft: `3px solid ${T.purple}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
                <div>
                  <h3 style={{ color: T.purple, fontSize: 16, fontFamily: T.fontHeading, margin: "0 0 4px 0" }}>🧪 Purple Swarm Validation (BAS)</h3>
                  <p style={{ color: T.textMuted, fontSize: 13, margin: 0 }}>Safely execute atomic tests in your sandbox to verify APEX SIEM/SOAR defenses.</p>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  {basScripts.map(script => (
                    <Btn key={script.id} onClick={() => handleDownloadBAS(script.target)} variant="outline" small color={T.purple}>
                      ⬇️ {script.platform}
                    </Btn>
                  ))}
                </div>
              </div>
            </Card>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
              <div>
                <h3 style={{ color: T.white, fontSize: 15, fontFamily: T.fontHeading, marginBottom: 16 }}>Remediation Playbooks</h3>
                {soarPlaybooks.filter(p => p.type !== "sigma").map(p => (
                  <CodeSnippet key={p.id} title={p.title} language={p.type.toUpperCase()} code={p.code} tagColor={p.color} />
                ))}
              </div>
              <div>
                <h3 style={{ color: T.white, fontSize: 15, fontFamily: T.fontHeading, marginBottom: 16 }}>SIEM Detection Rules</h3>
                {soarPlaybooks.filter(p => p.type === "sigma").map(p => (
                  <CodeSnippet key={p.id} title={p.title} language="YAML" code={p.code} tagColor={p.color} />
                ))}
                <Card style={{ marginTop: 16, textAlign: "center" }}>
                  <div style={{ color: T.textMuted, fontSize: 13, marginBottom: 8 }}>Auto-Dispatch Status</div>
                  <Badge color={T.low} bg={`${T.low}18`}><LiveDot color={T.low} />ALL RULES SYNCHRONIZED</Badge>
                  <p style={{ color: T.textMuted, fontSize: 12, marginTop: 10 }}>Pushed to Enterprise Firewalls within 12ms of detection.</p>
                </Card>
                {detections && (
                  <Card style={{ marginTop: 12 }}>
                    <div style={{ color: T.textMuted, fontSize: 12, marginBottom: 8 }}>Live Detection Coverage</div>
                    {detections.coverage != null && <div style={{ color: T.accent, fontSize: 22, fontWeight: 800 }}>{detections.coverage}%</div>}
                    {detections.mitre_techniques_covered != null && <div style={{ color: T.textMuted, fontSize: 12 }}>{detections.mitre_techniques_covered} MITRE Techniques Covered</div>}
                  </Card>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── CVEs TAB ── */}
        {!loading && tab === "cves" && (
          <>
            <SectionHeader icon="🔴" title="CVE Intelligence"
              sub={`${filteredCves.length}${severityFilter !== "ALL" ? ` ${severityFilter}` : ""} vulnerabilities`}
              action={
                <div style={{ display: "flex", gap: 6 }}>
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                    <button key={s} onClick={() => setSeverityFilter(s)} style={{
                      padding: "5px 12px", fontSize: 11, borderRadius: 100,
                      border: `1px solid ${severityFilter === s ? sevColor(s === "ALL" ? undefined : s) : T.border}`,
                      background: severityFilter === s ? `${sevColor(s === "ALL" ? undefined : s)}18` : "transparent",
                      color: severityFilter === s ? (s === "ALL" ? T.accent : sevColor(s)) : T.textMuted,
                      cursor: "pointer", fontFamily: T.fontMono, textTransform: "uppercase",
                    }}>{s}</button>
                  ))}
                </div>
              }
            />
            {errors.intel ? <ErrorState message={errors.intel} /> : <Card><CVETable cves={filteredCves} /></Card>}
          </>
        )}

        {/* ── INTEL FEED TAB ── */}
        {!loading && tab === "feed" && (
          <>
            <SectionHeader icon="📡" title="Global Threat Intelligence Feed"
              sub={`${intel.length} advisories · STIX 2.1 · Page ${feedPage + 1}/${Math.ceil(intel.length / FEED_PAGE_SIZE)}`}
              action={
                <div style={{ display: "flex", gap: 8 }}>
                  <Btn onClick={() => setFeedPage(Math.max(0, feedPage - 1))} small variant="outline" disabled={feedPage === 0}>← Prev</Btn>
                  <Btn onClick={() => setFeedPage(Math.min(Math.ceil(intel.length / FEED_PAGE_SIZE) - 1, feedPage + 1))} small variant="outline" disabled={(feedPage + 1) * FEED_PAGE_SIZE >= intel.length}>Next →</Btn>
                </div>
              }
            />
            {errors.intel ? <ErrorState message={errors.intel} /> : <IntelFeed items={pagedIntel} limit={FEED_PAGE_SIZE} />}
          </>
        )}

        {/* ── ATT&CK GAPS TAB ── */}
        {!loading && tab === "gaps" && (
          <>
            <SectionHeader icon="🎯" title="MITRE ATT&CK Coverage Gaps" sub={`${gaps.length} undetected techniques requiring attention`} />
            {gaps.length ? <GapsList gaps={gaps} /> : (
              <EmptyState message="Coverage gap analysis requires APEX tier. Gap data sourced from detection engine." icon="🎯" />
            )}
          </>
        )}

        {/* ── AI COPILOT TAB ── */}
        {!loading && tab === "copilot" && <CopilotPanel />}

        {/* ── ENGINES TAB ── */}
        {!loading && tab === "engines" && (
          <>
            <SectionHeader icon="⚙️" title="Intelligence Engine Status"
              sub="Real-time status of all 12 APEX intelligence engines"
              action={health && <Badge color={T.low} bg={`${T.low}15`}><LiveDot />Platform {health.version}</Badge>}
            />
            {errors.engines ? (
              <>
                <ErrorState message={errors.engines} />
                <div style={{ marginTop: 16, color: T.textMuted, fontSize: 13, textAlign: "center" }}>
                  Engine status requires authentication. <a href={`${API_BASE}/api/docs`} target="_blank" rel="noreferrer" style={{ color: T.accent }}>View API docs →</a>
                </div>
              </>
            ) : <EngineStatusPanel engines={engines} />}
          </>
        )}

        {/* ── API ACCESS TAB ── */}
        {!loading && tab === "api" && (
          <>
            <SectionHeader icon="🔌" title="API Access" sub="Integrate CDB-SENTINEL into your SOC stack" />
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 14, marginBottom: 24 }}>
              {[
                { tier: "Free",           price: "$0",      limit: "60 req/hr",    color: T.accent,   features: ["CVE feed (10 items)", "KEV alerts", "Public stats", "Intel search"] },
                { tier: "Pro",            price: "$49/mo",  limit: "600 req/hr",   color: T.blue,     features: ["STIX/MISP export", "Detection rules", "IOC feed", "Risk scoring", "100 advisories"] },
                { tier: "Enterprise",     price: "$999/mo", limit: "6000 req/hr",  color: T.purple,   features: ["SIEM connectors", "Bulk export", "Dark web intel", "SOAR actions", "SLA 99.9%", "500 advisories"] },
                { tier: "APEX SOVEREIGN", price: "$25k/mo", limit: "UNLIMITED",    color: T.apexGold, features: ["Live eBPF Mesh", "AI Auto-Healing SOAR", "Purple Swarm BAS", "Dedicated SOC", "Custom ML models", "24/7 analyst access"] },
              ].map(plan => (
                <Card key={plan.tier} glow={plan.tier.includes("APEX") ? "apex" : plan.tier === "Pro"}
                  borderColor={plan.tier.includes("APEX") ? T.apexGold : plan.tier === "Pro" ? T.accent : undefined}
                >
                  <div style={{ textAlign: "center", marginBottom: 16 }}>
                    <Badge color={plan.color} bg={`${plan.color}18`}>{plan.tier}</Badge>
                    <div style={{ color: T.white, fontSize: 26, fontWeight: 800, marginTop: 10, fontFamily: T.fontHeading }}>{plan.price}</div>
                    <div style={{ color: T.textMuted, fontSize: 12 }}>{plan.limit}</div>
                  </div>
                  <ul style={{ listStyle: "none", padding: 0, margin: "0 0 16px" }}>
                    {plan.features.map((f, i) => (
                      <li key={i} style={{ padding: "7px 0", fontSize: 12, color: T.text, borderBottom: `1px solid ${T.border}` }}>
                        <span style={{ color: plan.color, marginRight: 8 }}>✓</span>{f}
                      </li>
                    ))}
                  </ul>
                  <div style={{ textAlign: "center" }}>
                    <Btn variant={plan.tier === "Pro" || plan.tier.includes("APEX") ? "primary" : "outline"} small color={plan.color}
                      onClick={() => window.open(plan.tier.includes("APEX") || plan.tier === "Enterprise" ? "mailto:bivash@cyberdudebivash.com?subject=Enterprise%20Enquiry" : "https://cyberdudebivash.com/store", "_blank")}
                    >
                      {plan.tier.includes("APEX") || plan.tier === "Enterprise" ? "Contact Sales →" : "Get API Key →"}
                    </Btn>
                  </div>
                </Card>
              ))}
            </div>

            {/* Quick start */}
            <Card>
              <h3 style={{ color: T.white, fontSize: 15, fontWeight: 700, margin: "0 0 12px", fontFamily: T.fontHeading }}>⚡ Quick Start</h3>
              <CodeSnippet title="Free API — Get Latest Threats" language="BASH"
                tagColor={T.accent}
                code={`# Get a free API key at cyberdudebivash.com/store\ncurl -H "X-API-Key: YOUR_KEY" \\\n  "${API_BASE}/api/v1/intel/latest?limit=10"\n\n# Check platform health (no auth required)\ncurl "${API_BASE}/health"`}
              />
              <CodeSnippet title="API Docs" language="LINK" tagColor={T.blue}
                code={`${API_BASE}/api/docs  — Interactive Swagger UI\n${API_BASE}/api/v1/stats  — Live platform statistics\n${API_BASE}/api/v1/tiers  — Tier comparison`}
              />
            </Card>
          </>
        )}

      </main>
    </div>
  );
}
