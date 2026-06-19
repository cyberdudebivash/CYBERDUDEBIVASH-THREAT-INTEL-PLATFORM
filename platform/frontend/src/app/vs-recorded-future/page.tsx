import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "SENTINEL APEX vs Recorded Future — Threat Intelligence Platform Comparison",
  description:
    "SENTINEL APEX vs Recorded Future: Compare APT intelligence, IOC feeds, CVE tracking, and pricing. See why growing security teams choose SENTINEL APEX over expensive enterprise TIPs.",
  keywords: [
    "SENTINEL APEX vs Recorded Future", "Recorded Future alternative", "threat intelligence platform comparison",
    "Recorded Future competitor", "cheaper threat intelligence", "Recorded Future pricing alternative",
    "IOC feed vs Recorded Future", "APT intelligence alternative", "affordable threat intel platform",
    "CYBERDUDEBIVASH vs Recorded Future", "MITRE ATT&CK platform alternative",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/vs-recorded-future" },
  openGraph: {
    title: "SENTINEL APEX vs Recorded Future — Threat Intel Platform Comparison",
    description: "Enterprise threat intelligence at a fraction of the cost. Compare SENTINEL APEX to Recorded Future.",
    url: "https://intel.cyberdudebivash.com/vs-recorded-future",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "Article",
  "name": "SENTINEL APEX vs Recorded Future — Threat Intelligence Platform Comparison",
  "description": "Detailed comparison of SENTINEL APEX and Recorded Future for threat intelligence platform capabilities and pricing.",
  "url": "https://intel.cyberdudebivash.com/vs-recorded-future",
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
};

const COMPARISON = [
  { feature: "Target User", apex: "SOC analysts, IR teams, growing security ops", rf: "Fortune 500, government, large enterprise" },
  { feature: "Setup Time", apex: "Zero — free playground live immediately", rf: "Weeks — sales cycle, contracts, onboarding" },
  { feature: "Entry Pricing", apex: "Free tier → ₹4,100/mo Pro", rf: "Enterprise pricing only ($25K–$100K+/yr)" },
  { feature: "API Access", apex: "REST API + STIX 2.1. Free tier available.", rf: "Fusion API — enterprise contract required" },
  { feature: "APT Profiles", apex: "25+ MITRE-mapped profiles, free access", rf: "Comprehensive but paywalled" },
  { feature: "CVE Intelligence", apex: "28+ CVEs, CISA KEV, exploitation status — free", rf: "Vulnerability intelligence module (add-on)" },
  { feature: "IOC Feed", apex: "2.4M+ indicators, REST API, STIX 2.1", rf: "Comprehensive feeds — enterprise pricing" },
  { feature: "STIX 2.1 Export", apex: "Native export, included in Pro tier", rf: "Available — requires enterprise license" },
  { feature: "MITRE ATT&CK", apex: "Full TTP mapping on all data points", rf: "ATT&CK alignment — enterprise feature" },
  { feature: "Free Trial", apex: "Free forever tier + playground", rf: "Proof-of-concept only via sales" },
  { feature: "Deployment", apex: "SaaS — no infrastructure", rf: "SaaS — no infrastructure" },
  { feature: "India/APAC Pricing", apex: "INR pricing, accessible for Indian SOCs", rf: "USD pricing, cost-prohibitive for most" },
];

const APEX_ADVANTAGES = [
  {
    title: "Accessible from Day One",
    desc: "No sales calls. No contracts. No 6-week procurement cycle. Start searching IOCs, CVEs, and APT profiles in 30 seconds with the free playground.",
  },
  {
    title: "India-First Pricing",
    desc: "Recorded Future is priced for US enterprise budgets ($25,000+/year). SENTINEL APEX starts at ₹4,100/month — built for Indian SOCs, MSSPs, and growing teams.",
  },
  {
    title: "MITRE ATT&CK Native",
    desc: "Every IOC, CVE, and APT profile is MITRE ATT&CK mapped from day one. No additional modules or professional services required.",
  },
  {
    title: "STIX 2.1 Included",
    desc: "Machine-readable threat bundles for SIEM ingestion are included in the Pro tier — not an enterprise add-on requiring separate negotiation.",
  },
];

const WHO_APEX = [
  "Teams with <10 security analysts",
  "Indian and APAC security organizations",
  "MSSPs needing white-label intel per customer",
  "Startups and scale-ups building security practices",
  "Red teams needing fast APT TTP reference",
  "Universities and training programs",
];

const WHO_RF = [
  "Fortune 500 global security programs",
  "Government and intelligence agencies",
  "Teams with dedicated CTI budgets >$50K/yr",
  "Organizations needing dark web monitoring",
  "Programs requiring geopolitical risk signals",
];

export default function VsRecordedFuturePage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "SENTINEL APEX vs Recorded Future" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="text-center max-w-4xl mx-auto mb-12">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-semibold mb-6">
          PLATFORM COMPARISON
        </div>
        <h1 className="text-4xl font-bold text-white mb-6 leading-tight">
          SENTINEL APEX vs Recorded Future
        </h1>
        <p className="text-lg text-gray-400 leading-relaxed">
          Recorded Future is a best-in-class enterprise threat intelligence platform — for organizations with
          enterprise budgets. SENTINEL APEX delivers comparable intelligence capabilities at a fraction of the cost,
          with zero setup and a free tier that requires no credit card.
        </p>
      </div>

      {/* Price Shock Card */}
      <div className="grid md:grid-cols-2 gap-6 mb-12 max-w-2xl mx-auto">
        <div className="bg-cyan-500/5 border border-cyan-500/30 rounded-xl p-6 text-center">
          <p className="text-xs text-cyan-400 font-semibold uppercase tracking-wider mb-2">SENTINEL APEX Pro</p>
          <p className="text-5xl font-bold text-cyan-400 mb-1">₹4,100</p>
          <p className="text-sm text-gray-500">/month</p>
          <p className="text-xs text-gray-600 mt-3">2.4M+ IOCs · STIX 2.1 · API · APT Profiles · CVE Intel</p>
        </div>
        <div className="bg-gray-900/40 border border-gray-700 rounded-xl p-6 text-center">
          <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-2">Recorded Future</p>
          <p className="text-5xl font-bold text-gray-600 mb-1">$25K+</p>
          <p className="text-sm text-gray-600">/year (enterprise)</p>
          <p className="text-xs text-gray-700 mt-3">Sales cycle · Contract · Onboarding weeks · No free tier</p>
        </div>
      </div>

      {/* Full Comparison Table */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-8">Feature Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left py-3 px-4 text-gray-500 font-medium w-1/3">Feature</th>
                <th className="text-left py-3 px-4 text-cyan-400 font-semibold w-1/3">SENTINEL APEX</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium w-1/3">Recorded Future</th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((row, i) => (
                <tr key={row.feature} className={`border-b border-gray-800/50 ${i % 2 === 0 ? "bg-gray-900/20" : ""}`}>
                  <td className="py-3 px-4 text-gray-400 font-medium">{row.feature}</td>
                  <td className="py-3 px-4 text-gray-200">{row.apex}</td>
                  <td className="py-3 px-4 text-gray-500">{row.rf}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* APEX Advantages */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Why Teams Switch to SENTINEL APEX</h2>
        <p className="text-gray-500 text-center mb-10">Enterprise intelligence. Accessible pricing. Zero friction.</p>
        <div className="grid md:grid-cols-2 gap-6">
          {APEX_ADVANTAGES.map((a) => (
            <div key={a.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-white mb-2">{a.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{a.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Who Should Use What */}
      <div className="mb-16 grid md:grid-cols-2 gap-6 max-w-3xl mx-auto">
        <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-6">
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-4">Choose SENTINEL APEX if you are...</p>
          <ul className="space-y-2">
            {WHO_APEX.map((w) => (
              <li key={w} className="flex items-start gap-2 text-sm text-gray-300">
                <span className="text-cyan-400 mt-0.5">✓</span>{w}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-gray-900/40 border border-gray-700 rounded-xl p-6">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Recorded Future may fit if you are...</p>
          <ul className="space-y-2">
            {WHO_RF.map((w) => (
              <li key={w} className="flex items-start gap-2 text-sm text-gray-500">
                <span className="text-gray-600 mt-0.5">→</span>{w}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* CTA */}
      <div className="text-center bg-gradient-to-r from-purple-500/10 via-gray-900/40 to-cyan-500/10 border border-cyan-500/20 rounded-2xl p-12">
        <h2 className="text-3xl font-bold text-white mb-4">Enterprise Intelligence. Accessible Pricing.</h2>
        <p className="text-gray-400 mb-8 max-w-xl mx-auto">
          Try SENTINEL APEX free — no account, no sales call. See the intelligence quality for yourself.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link href="/playground" className="px-8 py-3.5 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors">
            Try Free Playground →
          </Link>
          <Link href="/partners" className="px-8 py-3.5 rounded-xl border border-gray-700 text-gray-300 font-semibold text-sm hover:bg-gray-800 transition-colors">
            MSSP Partner Program
          </Link>
        </div>
      </div>
    </IntelPageLayout>
  );
}
