import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "IOC Feed API — Live Malicious IP, Domain & Hash Intelligence | SENTINEL APEX",
  description:
    "Programmatic access to 2.4M+ live IOC indicators. REST API for malicious IPs, domains, URLs, and file hashes. STIX 2.1 output. SIEM-ready. Free tier available.",
  keywords: [
    "IOC feed API", "threat intelligence API", "malicious IP API", "domain reputation API",
    "file hash lookup API", "IOC API free", "STIX 2.1 API", "threat intel REST API",
    "IOC integration API", "SIEM IOC feed", "SENTINEL APEX API", "cybersecurity API",
    "indicator of compromise API", "malware hash API", "IP blocklist API",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/ioc-feed-api" },
  openGraph: {
    title: "IOC Feed API — 2.4M+ Live Indicators | SENTINEL APEX",
    description: "REST API for live malicious IP, domain, URL, and hash intelligence. STIX 2.1. SIEM-ready.",
    url: "https://intel.cyberdudebivash.com/ioc-feed-api",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "name": "SENTINEL APEX IOC Feed API Documentation",
  "description": "Technical documentation for the SENTINEL APEX IOC Feed REST API. 2.4M+ live indicators, STIX 2.1 output, SIEM integration.",
  "url": "https://intel.cyberdudebivash.com/ioc-feed-api",
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
};

const ENDPOINTS = [
  {
    method: "GET",
    path: "/api/v1/iocs",
    desc: "List all IOC indicators with pagination",
    params: "page, limit, type, severity, tlp",
  },
  {
    method: "GET",
    path: "/api/v1/iocs/{slug}",
    desc: "Get full IOC record by slug identifier",
    params: "slug (path)",
  },
  {
    method: "GET",
    path: "/api/v1/iocs/search",
    desc: "Search IOCs by value, actor, malware family",
    params: "q, type, confidence, since",
  },
  {
    method: "GET",
    path: "/api/v1/iocs/feed/stix",
    desc: "Export IOC bundle as STIX 2.1 JSON",
    params: "since, type, severity",
  },
  {
    method: "GET",
    path: "/api/v1/iocs/feed/csv",
    desc: "Export IOC feed as CSV for bulk ingestion",
    params: "since, type, limit",
  },
  {
    method: "GET",
    path: "/api/v1/iocs/enrich/{value}",
    desc: "Real-time enrichment for a given IP, domain, or hash",
    params: "value (path), context",
  },
];

const INTEGRATIONS = [
  { name: "Splunk", logo: "📊", desc: "Native TA for Splunk Enterprise Security" },
  { name: "Microsoft Sentinel", logo: "🔵", desc: "Azure Logic App connector + playbooks" },
  { name: "Elastic SIEM", logo: "🟡", desc: "Filebeat module with ECS field mapping" },
  { name: "IBM QRadar", logo: "🔴", desc: "DSM integration for IOC correlation" },
  { name: "Palo Alto XSOAR", logo: "🟠", desc: "Cortex XSOAR content pack" },
  { name: "CrowdStrike Falcon", logo: "🦅", desc: "Custom IOC import via Falcon API" },
];

const TIERS = [
  {
    name: "Free",
    calls: "100 API calls/day",
    indicators: "30 sample IOCs",
    stix: false,
    siem: false,
    support: "Community",
    price: "₹0",
  },
  {
    name: "Pro",
    calls: "10,000 API calls/day",
    indicators: "2.4M+ live IOCs",
    stix: true,
    siem: true,
    support: "Email (24h SLA)",
    price: "₹4,100/mo",
  },
  {
    name: "Enterprise",
    calls: "Unlimited",
    indicators: "2.4M+ + private feeds",
    stix: true,
    siem: true,
    support: "Dedicated CSM",
    price: "₹41,600/mo",
  },
];

const CODE_EXAMPLE = `# Search IOCs by threat actor
curl -X GET \\
  "https://api.intel.cyberdudebivash.com/v1/iocs/search?q=APT29" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Accept: application/json"

# Response
{
  "status": "ok",
  "total": 3,
  "data": [
    {
      "id": "ioc-001",
      "type": "ip",
      "value": "45.32.74.183",
      "threat_actor": "APT29 (Cozy Bear)",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "tlp": "GREEN",
      "mitre_tactics": ["Command and Control", "Exfiltration"],
      "tags": ["c2", "svr", "sunburst"]
    }
  ]
}`;

export default function IocFeedApiPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "IOC Feed API" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="text-center max-w-4xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          REST API — STIX 2.1 — SIEM NATIVE
        </div>
        <h1 className="text-5xl font-bold text-white mb-6 leading-tight">
          IOC Feed API<br />
          <span className="text-cyan-400">2.4M+ Live Indicators</span>
        </h1>
        <p className="text-xl text-gray-400 leading-relaxed mb-8">
          Programmatic access to malicious IPs, domains, URLs, and file hashes.
          Real-time enrichment. STIX 2.1 export. Plug directly into Splunk, Sentinel, Elastic, and QRadar.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/get-api-key.html"
            className="px-8 py-3.5 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors"
          >
            Get Free API Key →
          </Link>
          <Link
            href="/playground"
            className="px-8 py-3.5 rounded-xl bg-gray-800 border border-gray-700 text-gray-200 font-semibold text-sm hover:bg-gray-700 transition-colors"
          >
            Try Without API Key
          </Link>
        </div>
      </div>

      {/* Code Example */}
      <div className="mb-16 max-w-3xl mx-auto">
        <h2 className="text-lg font-semibold text-white mb-4 text-center">Example API Request</h2>
        <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-800 bg-gray-900/60">
            <span className="w-3 h-3 rounded-full bg-red-500/60" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <span className="w-3 h-3 rounded-full bg-green-500/60" />
            <span className="ml-2 text-xs text-gray-500 font-mono">ioc-search.sh</span>
          </div>
          <pre className="p-5 text-xs text-gray-300 font-mono leading-relaxed overflow-x-auto">
            <code>{CODE_EXAMPLE}</code>
          </pre>
        </div>
      </div>

      {/* Endpoints */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">API Endpoints</h2>
        <p className="text-gray-500 text-center mb-10">Base URL: <code className="text-cyan-400 text-sm">https://api.intel.cyberdudebivash.com/v1</code></p>
        <div className="space-y-3 max-w-3xl mx-auto">
          {ENDPOINTS.map((ep) => (
            <div key={ep.path} className="bg-gray-900/40 border border-gray-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center gap-3">
              <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-1 rounded font-mono w-fit">
                {ep.method}
              </span>
              <code className="text-sm text-cyan-300 font-mono flex-shrink-0">{ep.path}</code>
              <div className="flex-1">
                <p className="text-xs text-gray-400">{ep.desc}</p>
                <p className="text-xs text-gray-600 mt-0.5">Params: {ep.params}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SIEM Integrations */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Native SIEM Integrations</h2>
        <p className="text-gray-500 text-center mb-10">Pre-built connectors for enterprise security stacks</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {INTEGRATIONS.map((int) => (
            <div key={int.name} className="bg-gray-900/40 border border-gray-800 rounded-xl p-5 flex items-start gap-4">
              <span className="text-2xl">{int.logo}</span>
              <div>
                <p className="text-sm font-semibold text-gray-200 mb-1">{int.name}</p>
                <p className="text-xs text-gray-500">{int.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Pricing Tiers */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">API Access Tiers</h2>
        <p className="text-gray-500 text-center mb-10">Start free. Scale as you grow.</p>
        <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {TIERS.map((tier, i) => (
            <div key={tier.name} className={`bg-gray-900/40 border rounded-xl p-6 ${
              i === 1 ? "border-cyan-500/50 shadow-lg shadow-cyan-500/10" : "border-gray-800"
            }`}>
              {i === 1 && (
                <p className="text-xs font-semibold text-cyan-400 mb-2">MOST POPULAR</p>
              )}
              <p className="text-xl font-bold text-white mb-1">{tier.name}</p>
              <p className="text-2xl font-bold text-cyan-400 mb-4">{tier.price}</p>
              <ul className="space-y-2 text-xs text-gray-400">
                <li className="flex items-center gap-2"><span className="text-emerald-400">✓</span>{tier.calls}</li>
                <li className="flex items-center gap-2"><span className="text-emerald-400">✓</span>{tier.indicators}</li>
                <li className={`flex items-center gap-2 ${tier.stix ? "" : "opacity-40"}`}>
                  <span className={tier.stix ? "text-emerald-400" : "text-gray-600"}>{tier.stix ? "✓" : "✗"}</span>
                  STIX 2.1 export
                </li>
                <li className={`flex items-center gap-2 ${tier.siem ? "" : "opacity-40"}`}>
                  <span className={tier.siem ? "text-emerald-400" : "text-gray-600"}>{tier.siem ? "✓" : "✗"}</span>
                  SIEM connectors
                </li>
                <li className="flex items-center gap-2"><span className="text-emerald-400">✓</span>Support: {tier.support}</li>
              </ul>
              <Link
                href={i === 0 ? "/get-api-key.html" : "/pricing.html"}
                className={`mt-5 block text-center py-2.5 rounded-lg text-xs font-semibold transition-colors ${
                  i === 1
                    ? "bg-cyan-500 text-gray-950 hover:bg-cyan-400"
                    : "bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700"
                }`}
              >
                {i === 0 ? "Get Free Key" : "Get Started"}
              </Link>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="text-center bg-gray-900/40 border border-gray-800 rounded-2xl p-10">
        <h2 className="text-2xl font-bold text-white mb-3">Ready to integrate threat intelligence?</h2>
        <p className="text-gray-500 mb-6">Free API key. No credit card. 100 calls/day forever on free tier.</p>
        <Link
          href="/get-api-key.html"
          className="px-8 py-3.5 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors"
        >
          Get Your Free API Key →
        </Link>
      </div>
    </IntelPageLayout>
  );
}
