import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "Threat Intelligence Platform — Real-Time CVE, IOC & APT Intelligence | SENTINEL APEX",
  description:
    "SENTINEL APEX is an AI-native threat intelligence platform delivering real-time IOC feeds, CVE tracking, and 25+ APT actor profiles. Free tier. No setup required. Used by analysts globally.",
  keywords: [
    "threat intelligence platform", "threat intel platform", "cyber threat intelligence",
    "real-time threat intelligence", "IOC feed platform", "APT intelligence platform",
    "CVE threat intelligence", "MITRE ATT&CK platform", "AI threat intelligence",
    "SENTINEL APEX platform", "CYBERDUDEBIVASH threat intel", "threat intelligence as a service",
    "TIP platform", "threat intelligence tool", "SOC threat intelligence",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/threat-intelligence-platform" },
  openGraph: {
    title: "Threat Intelligence Platform — SENTINEL APEX by CYBERDUDEBIVASH",
    description: "Real-time IOC feeds, CVE tracking, and APT intelligence. AI-native. No setup required.",
    url: "https://intel.cyberdudebivash.com/threat-intelligence-platform",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "SENTINEL APEX Threat Intelligence Platform",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Web",
  "url": "https://intel.cyberdudebivash.com",
  "description": "AI-native threat intelligence platform with real-time IOC feeds, CVE intelligence, APT profiles, and MITRE ATT&CK mapping. Free tier available.",
  "offers": [
    { "@type": "Offer", "name": "Free", "price": "0", "priceCurrency": "USD" },
    { "@type": "Offer", "name": "Pro", "price": "49", "priceCurrency": "USD", "billingIncrement": "P1M" },
  ],
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
  "featureList": [
    "2.4M+ live IOC indicators",
    "Real-time CVE vulnerability tracking",
    "25+ APT threat actor profiles",
    "MITRE ATT&CK mapping",
    "STIX 2.1 export",
    "SIEM integration",
    "AI triage and risk scoring",
  ],
};

const CAPABILITIES = [
  {
    icon: "🛡️",
    title: "2.4M+ Live IOC Indicators",
    desc: "Real-time feed of malicious IPs, domains, URLs, and file hashes. Updated continuously from 40+ OSINT sources, government feeds, and honeypot networks.",
    tag: "PRO",
  },
  {
    icon: "🔍",
    title: "CVE Vulnerability Intelligence",
    desc: "Track critical vulnerabilities with CVSS scores, CISA KEV cross-reference, active exploitation status, and affected vendor advisories — all in one view.",
    tag: "FREE",
  },
  {
    icon: "🕵️",
    title: "APT Threat Actor Profiles",
    desc: "Deep profiles on 25+ nation-state and criminal APT groups with MITRE ATT&CK TTPs, tooling, infrastructure, and attributed campaigns.",
    tag: "FREE",
  },
  {
    icon: "🧠",
    title: "AI Triage Engine",
    desc: "Autonomous alert analysis and risk scoring. Reduces analyst alert fatigue by 60% by surfacing only high-confidence, high-severity indicators.",
    tag: "PRO",
  },
  {
    icon: "📦",
    title: "STIX 2.1 Export",
    desc: "Machine-readable threat bundles for SIEM/SOAR ingestion. Native connectors for Splunk, Elastic, Microsoft Sentinel, and IBM QRadar.",
    tag: "PRO",
  },
  {
    icon: "🔗",
    title: "REST API Access",
    desc: "Programmatic access to all intelligence feeds. Rate-limited free tier available. Enterprise tier supports 10,000 API calls/day with SLA guarantee.",
    tag: "PRO",
  },
];

const USE_CASES = [
  {
    role: "SOC Analyst",
    problem: "Alert fatigue from thousands of low-fidelity IOC hits daily",
    solution: "AI triage reduces noise — only verified, HIGH/CRITICAL confidence IOCs surface in your queue",
    result: "60% reduction in analyst investigation time",
  },
  {
    role: "Threat Intelligence Team",
    problem: "Manual pivot across 15+ data sources with inconsistent formats",
    solution: "Unified platform aggregates OSINT, government feeds, and honeypot data into STIX 2.1",
    result: "Single-pane-of-glass across all intelligence sources",
  },
  {
    role: "CISO / Security Leadership",
    problem: "No visibility into APT groups targeting your industry sector",
    solution: "Sector-tagged APT profiles with active campaign tracking and executive-ready risk summaries",
    result: "Board-ready threat briefings in minutes, not hours",
  },
  {
    role: "MSSP / MDR Provider",
    problem: "Per-customer threat context at scale is cost-prohibitive",
    solution: "Multi-tenant API with white-label reporting and volume licensing",
    result: "Margin-positive threat intel for every managed customer",
  },
];

const STATS = [
  { value: "2.4M+", label: "Live IOC Indicators" },
  { value: "30+", label: "Free IOC Samples" },
  { value: "25+", label: "APT Actor Profiles" },
  { value: "28+", label: "CVE Records" },
  { value: "40+", label: "Data Sources" },
  { value: "99.9%", label: "API Uptime SLA" },
];

export default function ThreatIntelligencePlatformPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "Threat Intelligence Platform" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="text-center max-w-4xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          AI-NATIVE THREAT INTELLIGENCE PLATFORM
        </div>
        <h1 className="text-5xl font-bold text-white mb-6 leading-tight">
          The Threat Intelligence Platform<br />
          <span className="text-cyan-400">Built for Modern SOCs</span>
        </h1>
        <p className="text-xl text-gray-400 leading-relaxed mb-8">
          SENTINEL APEX delivers real-time IOC feeds, CVE vulnerability tracking, and deep APT actor intelligence
          with MITRE ATT&CK mapping. Free tier available. No setup. No hardware. No delay.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/playground"
            className="px-8 py-3.5 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors"
          >
            Try Free Playground →
          </Link>
          <Link
            href="/pricing.html"
            className="px-8 py-3.5 rounded-xl bg-gray-800 border border-gray-700 text-gray-200 font-semibold text-sm hover:bg-gray-700 transition-colors"
          >
            View Pricing
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-16">
        {STATS.map((s) => (
          <div key={s.label} className="bg-gray-900/60 border border-gray-800 rounded-xl p-4 text-center">
            <p className="text-2xl font-bold text-cyan-400 mb-1">{s.value}</p>
            <p className="text-xs text-gray-500">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Capabilities */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Platform Capabilities</h2>
        <p className="text-gray-500 text-center mb-10">Everything your security team needs in one platform</p>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CAPABILITIES.map((cap) => (
            <div key={cap.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-6 hover:border-gray-700 transition-colors">
              <div className="flex items-start justify-between mb-3">
                <span className="text-2xl">{cap.icon}</span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${
                  cap.tag === "FREE"
                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                    : "text-cyan-400 bg-cyan-500/10 border-cyan-500/30"
                }`}>{cap.tag}</span>
              </div>
              <h3 className="text-sm font-semibold text-white mb-2">{cap.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Use Cases */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Built for Every Security Role</h2>
        <p className="text-gray-500 text-center mb-10">From individual analysts to enterprise security teams</p>
        <div className="grid md:grid-cols-2 gap-6">
          {USE_CASES.map((uc) => (
            <div key={uc.role} className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-3">{uc.role}</p>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-gray-600 uppercase tracking-wider mb-1">Challenge</p>
                  <p className="text-sm text-gray-400">{uc.problem}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-600 uppercase tracking-wider mb-1">Solution</p>
                  <p className="text-sm text-gray-300">{uc.solution}</p>
                </div>
                <div className="pt-2 border-t border-gray-800">
                  <p className="text-sm font-semibold text-emerald-400">✓ {uc.result}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="text-center bg-gradient-to-r from-cyan-500/10 via-gray-900/40 to-cyan-500/10 border border-cyan-500/20 rounded-2xl p-12">
        <h2 className="text-3xl font-bold text-white mb-4">Start with the Free Playground</h2>
        <p className="text-gray-400 mb-8 max-w-xl mx-auto">
          No account. No credit card. Search live IOCs, CVEs, and APT profiles right now.
          Upgrade when you&apos;re ready for API access and full feeds.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/playground"
            className="px-8 py-3.5 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors"
          >
            Open Free Playground →
          </Link>
          <Link
            href="/ioc-feed-api"
            className="px-8 py-3.5 rounded-xl border border-gray-700 text-gray-300 font-semibold text-sm hover:bg-gray-800 transition-colors"
          >
            IOC Feed API Docs
          </Link>
        </div>
      </div>
    </IntelPageLayout>
  );
}
