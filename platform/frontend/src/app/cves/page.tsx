import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { CVE_RECORDS } from "@/lib/intel-data";
import type { Severity } from "@/lib/intel-data";

export const metadata: Metadata = {
  title: "CVE Intelligence — Real-Time Vulnerability Tracking with EPSS & KEV",
  description:
    "Real-time CVE intelligence with EPSS scoring, CISA KEV integration, CVSS v4.0, and MITRE ATT&CK mapping. Track 28+ active vulnerabilities with exploitation probability and advisory correlation — CYBERDUDEBIVASH® SENTINEL APEX.",
  alternates: { canonical: "https://intel.cyberdudebivash.com/cves" },
  openGraph: {
    title: "CVE Intelligence | CYBERDUDEBIVASH® SENTINEL APEX",
    description: `Track ${CVE_RECORDS.length} active CVEs with EPSS scoring, KEV status, and MITRE ATT&CK mapping.`,
    url: "https://intel.cyberdudebivash.com/cves",
    type: "website",
  },
};

const listingSchema = {
  "@context": "https://schema.org",
  "@type": "Dataset",
  name: "CVE Intelligence Database — CYBERDUDEBIVASH SENTINEL APEX",
  description: `Active CVE tracking database with EPSS scoring, CISA KEV status, and MITRE ATT&CK mapping. ${CVE_RECORDS.length} CVEs tracked.`,
  url: "https://intel.cyberdudebivash.com/cves",
  creator: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
  keywords: "CVE, vulnerability, EPSS, KEV, CISA, MITRE ATT&CK, CVSS, threat intelligence",
};

const breadcrumbSchema = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
    { "@type": "ListItem", position: 2, name: "CVE Intelligence", item: "https://intel.cyberdudebivash.com/cves" },
  ],
};

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const sortedCves = [...CVE_RECORDS].sort(
  (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.advisory_count - a.advisory_count
);

const highCount = CVE_RECORDS.filter((c) => c.severity === "HIGH" || c.severity === "CRITICAL").length;
const kevCount = CVE_RECORDS.filter((c) => c.kev_present).length;
const maxAdvisories = Math.max(...CVE_RECORDS.map((c) => c.advisory_count));

export default function CvesPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "CVE Intelligence" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(listingSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          LIVE CVE FEED
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">
          CVE Intelligence Database
        </h1>
        <p className="text-gray-400 text-lg max-w-3xl">
          Real-time vulnerability tracking with EPSS exploitation probability scoring, CISA KEV integration,
          CVSS v4.0, and MITRE ATT&CK technique mapping — powered by CYBERDUDEBIVASH® SENTINEL APEX.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8">
          {[
            { label: "Active CVEs Tracked", value: String(CVE_RECORDS.length) },
            { label: "High/Critical Severity", value: String(highCount) },
            { label: "CISA KEV Listed", value: kevCount > 0 ? String(kevCount) : "Monitoring" },
            { label: "Max Advisory Coverage", value: `${maxAdvisories}` },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-2xl font-bold text-white">{s.value}</p>
              <p className="text-xs text-gray-500 mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* CVE table */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/40 overflow-hidden">
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Active CVE Feed</h2>
          <span className="text-xs text-gray-500">Sorted by severity · advisory count</span>
        </div>
        <div className="divide-y divide-gray-800">
          {sortedCves.map((cve) => (
            <Link
              key={cve.id}
              href={`/cves/${cve.slug}`}
              className="group flex items-center gap-4 px-4 py-3.5 hover:bg-gray-800/40 transition-colors"
            >
              <div className="w-40 flex-shrink-0">
                <span className="font-mono text-sm font-semibold text-cyan-400 group-hover:text-cyan-300 transition-colors">
                  {cve.id}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <ThreatLevelBadge level={cve.severity} />
                  {cve.kev_present && (
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-semibold bg-red-500/10 border border-red-500/20 text-red-400">
                      KEV
                    </span>
                  )}
                  {cve.mitre_tactics.map((t) => (
                    <span key={t.id} className="text-xs font-mono text-gray-600">{t.id}</span>
                  ))}
                </div>
              </div>
              <div className="text-right flex-shrink-0">
                <p className="text-xs text-gray-400">{cve.advisory_count} advisories</p>
                {cve.published_at && (
                  <p className="text-xs text-gray-600 mt-0.5">{cve.published_at}</p>
                )}
              </div>
              <span className="text-gray-600 group-hover:text-gray-400 transition-colors text-sm">›</span>
            </Link>
          ))}
        </div>
      </div>

      {/* Methodology */}
      <section className="mt-12 grid grid-cols-1 sm:grid-cols-3 gap-6">
        {[
          {
            label: "EPSS Enrichment",
            body: "Every CVE is enriched with EPSS (Exploit Prediction Scoring System) probability scores, giving defenders a data-driven exploitation likelihood within 30 days.",
          },
          {
            label: "CISA KEV Integration",
            body: "CVEs listed in the CISA Known Exploited Vulnerabilities catalog receive automatic critical escalation and BOD 22-01 compliance tracking.",
          },
          {
            label: "MITRE ATT&CK Mapping",
            body: "Each vulnerability is mapped to MITRE ATT&CK techniques using SENTINEL APEX's AI correlation engine, enabling direct detection rule generation.",
          },
        ].map((m) => (
          <div key={m.label} className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
            <h3 className="text-sm font-semibold text-white mb-2">{m.label}</h3>
            <p className="text-xs text-gray-500 leading-relaxed">{m.body}</p>
          </div>
        ))}
      </section>

      {/* CTA */}
      <div className="mt-12 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">
        <h2 className="text-xl font-bold text-white mb-2">Full CVE Intelligence Feed</h2>
        <p className="text-gray-400 text-sm mb-6 max-w-xl mx-auto">
          Access 250,000+ CVEs with real-time EPSS, KEV, CVSS v4.0, STIX 2.1 export, and AI-prioritized exploitation risk scoring in SENTINEL APEX Enterprise.
        </p>
        <div className="flex flex-wrap justify-center gap-3">
          <Link href="/" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-500 text-gray-950 font-semibold text-sm hover:bg-cyan-400 transition-colors">
            Access Platform
          </Link>
          <Link href="/kev.html" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-gray-700 text-gray-300 text-sm hover:border-gray-600 hover:text-white transition-colors">
            CISA KEV Tracker
          </Link>
        </div>
      </div>
    </IntelPageLayout>
  );
}
