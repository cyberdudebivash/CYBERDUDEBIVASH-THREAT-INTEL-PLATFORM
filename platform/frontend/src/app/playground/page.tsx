import type { Metadata } from "next";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { PlaygroundClient } from "@/components/playground/PlaygroundClient";

export const metadata: Metadata = {
  title: "Free Threat Intelligence Playground — Live IOC, CVE & APT Search",
  description:
    "Search 30+ live IOCs, CVEs, and 25+ APT threat actor profiles instantly — no account required. CYBERDUDEBIVASH® SENTINEL APEX free intelligence playground. MITRE ATT&CK mapped.",
  keywords: [
    "free threat intelligence search", "IOC lookup free", "CVE search tool", "APT threat actor search",
    "free cybersecurity tool", "IP reputation check", "malware hash lookup",
    "MITRE ATT&CK search", "SENTINEL APEX playground", "no signup threat intel",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/playground" },
  openGraph: {
    title: "Free Threat Intel Playground — Live IOC, CVE & APT Search | SENTINEL APEX",
    description: "Search live threat intelligence instantly — no account, no credit card. IOC lookup, CVE search, APT profiles.",
    url: "https://intel.cyberdudebivash.com/playground",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "name": "SENTINEL APEX Threat Intelligence Playground",
  "description": "Free, no-signup threat intelligence search tool. Look up IOCs, CVEs, and APT threat actor profiles powered by CYBERDUDEBIVASH SENTINEL APEX.",
  "url": "https://intel.cyberdudebivash.com/playground",
  "applicationCategory": "SecurityApplication",
  "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
};

export default function PlaygroundPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "Free Playground" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="mb-10 text-center max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          FREE — NO ACCOUNT REQUIRED
        </div>
        <h1 className="text-4xl font-bold text-white mb-4">
          Threat Intelligence Playground
        </h1>
        <p className="text-gray-400 text-lg leading-relaxed">
          Search live IOC indicators, CVE vulnerabilities, and APT threat actor profiles instantly.
          No signup. No credit card. Powered by SENTINEL APEX real-time intelligence feeds.
        </p>
        <div className="mt-5 flex flex-wrap items-center justify-center gap-4 text-sm text-gray-500">
          {[
            "30+ Live IOCs",
            "28 CVE Records",
            "25 APT Profiles",
            "MITRE ATT&CK Mapped",
            "TLP:GREEN",
          ].map((f) => (
            <span key={f} className="flex items-center gap-1.5">
              <span className="w-1 h-1 rounded-full bg-cyan-500" />
              {f}
            </span>
          ))}
        </div>
      </div>

      {/* Interactive Search */}
      <div className="max-w-4xl mx-auto">
        <PlaygroundClient />
      </div>

      {/* Feature tease */}
      <div className="mt-16 max-w-4xl mx-auto">
        <p className="text-center text-xs text-gray-600 mb-6 uppercase tracking-wider">PRO Tier Unlocks</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { icon: "🔴", title: "2.4M+ Live IOCs", desc: "Full real-time indicator feed with API access" },
            { icon: "📦", title: "STIX 2.1 Export", desc: "Machine-readable bundles for SIEM ingestion" },
            { icon: "🧠", title: "AI Triage", desc: "Autonomous alert analysis and risk scoring" },
            { icon: "🔗", title: "SIEM Integration", desc: "Splunk, Elastic, Microsoft Sentinel connectors" },
          ].map((f) => (
            <div key={f.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-4 text-center">
              <p className="text-2xl mb-2">{f.icon}</p>
              <p className="text-sm font-semibold text-gray-200 mb-1">{f.title}</p>
              <p className="text-xs text-gray-500">{f.desc}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 text-center">
          <a
            href="/pricing.html"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-semibold text-sm hover:bg-cyan-500/20 transition-colors"
          >
            View Pricing — Free tier available
          </a>
        </div>
      </div>
    </IntelPageLayout>
  );
}
