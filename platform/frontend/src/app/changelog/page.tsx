import type { Metadata } from "next";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "Platform Changelog — SENTINEL APEX Release Notes | CYBERDUDEBIVASH",
  description:
    "Track every update to the SENTINEL APEX threat intelligence platform. New IOC feeds, CVE tracking improvements, APT profiles, API enhancements, and SIEM integrations — documented release by release.",
  keywords: [
    "SENTINEL APEX changelog", "threat intelligence platform updates", "CYBERDUDEBIVASH releases",
    "IOC feed updates", "CVE tracking updates", "threat intel platform changelog",
    "SENTINEL APEX release notes", "platform improvements", "new threat intelligence features",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/changelog" },
  openGraph: {
    title: "SENTINEL APEX Platform Changelog — Release Notes",
    description: "Track every improvement to SENTINEL APEX threat intelligence — IOC feeds, CVE tracking, API updates.",
    url: "https://intel.cyberdudebivash.com/changelog",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  "name": "SENTINEL APEX Platform Changelog",
  "description": "Complete release history for the SENTINEL APEX threat intelligence platform.",
  "url": "https://intel.cyberdudebivash.com/changelog",
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
};

type ReleaseType = "feature" | "improvement" | "fix" | "security" | "data";

interface Release {
  version: string;
  date: string;
  title: string;
  changes: { type: ReleaseType; text: string }[];
}

const BADGE: Record<ReleaseType, string> = {
  feature: "bg-cyan-500/10 border-cyan-500/30 text-cyan-400",
  improvement: "bg-blue-500/10 border-blue-500/30 text-blue-400",
  fix: "bg-orange-500/10 border-orange-500/30 text-orange-400",
  security: "bg-red-500/10 border-red-500/30 text-red-400",
  data: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
};

const LABEL: Record<ReleaseType, string> = {
  feature: "FEATURE",
  improvement: "IMPROVEMENT",
  fix: "FIX",
  security: "SECURITY",
  data: "DATA",
};

const RELEASES: Release[] = [
  {
    version: "2.3.0",
    date: "2026-06-19",
    title: "Commercial Expansion — Playground, SEO Pages & Partner Program",
    changes: [
      { type: "feature", text: "Free Threat Intelligence Playground — no-auth interactive IOC/CVE/APT search" },
      { type: "feature", text: "SEO feature pages: /threat-intelligence-platform, /ioc-feed-api, /cve-tracking-tool" },
      { type: "feature", text: "Comparison pages: /vs-virustotal, /vs-recorded-future" },
      { type: "feature", text: "MSSP & Partner Program page with 3-tier structure (Referral / MSSP / Strategic)" },
      { type: "feature", text: "Weekly threat intelligence newsletter subscription page" },
      { type: "feature", text: "Platform changelog page (this page)" },
      { type: "improvement", text: "Navigation updated with Playground and Partners links" },
      { type: "data", text: "Sitemap expanded to 70+ URLs for improved crawl coverage" },
    ],
  },
  {
    version: "2.2.0",
    date: "2026-06-19",
    title: "Phase 2 — IOC Intelligence Feed, Blog & Mobile Nav",
    changes: [
      { type: "feature", text: "30-record IOC Intelligence Feed — 10 IPs, 10 domains, 10 SHA256 hashes" },
      { type: "feature", text: "Individual IOC profile pages with MITRE ATT&CK mapping and confidence scoring" },
      { type: "feature", text: "Blog listing page surfacing 11 existing security research posts" },
      { type: "feature", text: "Branded 404 page with recovery navigation" },
      { type: "feature", text: "Mobile-responsive hamburger navigation for all intel pages" },
      { type: "data", text: "IOC data includes APT29/SUNBURST, Volt Typhoon, LockBit 3.0, Lazarus, Sandworm, Clop/MOVEit" },
      { type: "improvement", text: "Footer expanded with IOC Feed and Blog links" },
      { type: "improvement", text: "Sitemap expanded with 44 new URLs" },
    ],
  },
  {
    version: "2.1.0",
    date: "2026-06-15",
    title: "CVE Intelligence Module",
    changes: [
      { type: "feature", text: "28 CVE records with CVSS 3.1 scoring, CISA KEV cross-reference, and exploitation status" },
      { type: "feature", text: "Individual CVE profile pages with MITRE ATT&CK TTP mapping" },
      { type: "feature", text: "CVE listing hub with severity filtering and KEV badge system" },
      { type: "data", text: "Coverage includes Fortinet, Ivanti, Microsoft, Apache, Cisco, VMware, and 10+ vendors" },
      { type: "improvement", text: "Related CVE recommendations on profile pages" },
    ],
  },
  {
    version: "2.0.0",
    date: "2026-06-10",
    title: "Ransomware Intelligence Module",
    changes: [
      { type: "feature", text: "10 ransomware group profiles: LockBit 3.0, BlackCat/ALPHV, Clop, Akira, Black Basta, and more" },
      { type: "feature", text: "Ransomware listing hub with active status, TTP coverage, and attribution" },
      { type: "feature", text: "Notable incident tracking per ransomware group" },
      { type: "data", text: "MITRE ATT&CK TTP mapping for all ransomware toolchains" },
      { type: "improvement", text: "Cross-references between ransomware groups and APT threat actors" },
    ],
  },
  {
    version: "1.5.0",
    date: "2026-06-01",
    title: "APT Threat Actor Profiles",
    changes: [
      { type: "feature", text: "25+ APT threat actor profiles: APT28, APT29, Volt Typhoon, Lazarus, Sandworm, and more" },
      { type: "feature", text: "MITRE ATT&CK G-ID referenced on all actor profiles" },
      { type: "feature", text: "Threat actor listing hub with country, sponsor, and threat level filtering" },
      { type: "data", text: "Full TTP matrix, malware tooling, and known campaign attribution per actor" },
      { type: "feature", text: "Schema.org TechArticle + BreadcrumbList structured data for SEO" },
    ],
  },
  {
    version: "1.0.0",
    date: "2026-05-20",
    title: "Platform Launch — SENTINEL APEX v1",
    changes: [
      { type: "feature", text: "Initial platform launch — CYBERDUDEBIVASH SENTINEL APEX threat intelligence platform" },
      { type: "feature", text: "Enterprise dashboard with Zustand tier-based access control (FREE/PRO/ENTERPRISE/MSSP)" },
      { type: "feature", text: "Stripe billing integration with INR pricing tiers" },
      { type: "feature", text: "Static Next.js 14 App Router with SSG for all intelligence pages" },
      { type: "feature", text: "Schema.org JSON-LD structured data across all pages" },
      { type: "security", text: "TLP:GREEN classification system on all publicly accessible intelligence data" },
    ],
  },
];

export default function ChangelogPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "Changelog" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="text-center max-w-3xl mx-auto mb-12">
        <h1 className="text-4xl font-bold text-white mb-4">Platform Changelog</h1>
        <p className="text-gray-400 leading-relaxed">
          Every improvement to SENTINEL APEX — new intelligence data, platform features, API updates,
          and performance enhancements. Updated with every release.
        </p>
      </div>

      {/* Stats bar */}
      <div className="flex flex-wrap justify-center gap-6 mb-12 text-sm">
        {[
          { label: "Total Releases", value: RELEASES.length.toString() },
          { label: "Latest Version", value: RELEASES[0].version },
          { label: "Last Updated", value: RELEASES[0].date },
          { label: "Status", value: "Active Development" },
        ].map((s) => (
          <div key={s.label} className="text-center">
            <p className="font-bold text-cyan-400">{s.value}</p>
            <p className="text-xs text-gray-600">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Release Timeline */}
      <div className="max-w-3xl mx-auto space-y-8">
        {RELEASES.map((release, i) => (
          <div key={release.version} className="relative pl-6 border-l-2 border-gray-800">
            {/* Timeline dot */}
            <div className={`absolute -left-2 top-1.5 w-3.5 h-3.5 rounded-full border-2 ${
              i === 0 ? "bg-cyan-400 border-cyan-400" : "bg-gray-800 border-gray-700"
            }`} />

            <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              {/* Header */}
              <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-cyan-400 font-mono">v{release.version}</span>
                    {i === 0 && (
                      <span className="text-xs font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                        LATEST
                      </span>
                    )}
                  </div>
                  <h2 className="text-base font-semibold text-white">{release.title}</h2>
                </div>
                <time className="text-xs text-gray-600 flex-shrink-0">{release.date}</time>
              </div>

              {/* Changes */}
              <ul className="space-y-2">
                {release.changes.map((change, j) => (
                  <li key={j} className="flex items-start gap-3">
                    <span className={`text-xs font-semibold px-1.5 py-0.5 rounded border flex-shrink-0 mt-0.5 ${BADGE[change.type]}`}>
                      {LABEL[change.type]}
                    </span>
                    <span className="text-sm text-gray-400">{change.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Subscribe CTA */}
      <div className="mt-16 text-center bg-gray-900/40 border border-gray-800 rounded-2xl p-10 max-w-2xl mx-auto">
        <h2 className="text-xl font-bold text-white mb-3">Stay Updated</h2>
        <p className="text-gray-500 mb-6 text-sm">
          Subscribe to the weekly threat intelligence digest. New IOC data, CVE alerts, and platform updates delivered to your inbox.
        </p>
        <a
          href="/newsletter"
          className="px-8 py-3 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors"
        >
          Subscribe to Weekly Intel →
        </a>
      </div>
    </IntelPageLayout>
  );
}
