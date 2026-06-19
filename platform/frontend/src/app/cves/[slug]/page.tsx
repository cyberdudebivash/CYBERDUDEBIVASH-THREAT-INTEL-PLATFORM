import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { CVE_RECORDS, getCveBySlug } from "@/lib/intel-data";

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return CVE_RECORDS.map((cve) => ({ slug: cve.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const cve = getCveBySlug(slug);
  if (!cve) return { title: "CVE Not Found" };

  const title = `${cve.id} — Vulnerability Intelligence & Exploitation Analysis`;
  const description = `${cve.id} vulnerability intelligence: severity ${cve.severity}, ${cve.advisory_count} advisories, MITRE ATT&CK techniques ${cve.mitre_tactics.map((t) => t.id).join(", ")}. EPSS scoring and KEV status tracked by CYBERDUDEBIVASH® SENTINEL APEX.`;
  const url = `https://intel.cyberdudebivash.com/cves/${cve.slug}`;

  return {
    title,
    description,
    alternates: { canonical: url },
    openGraph: { title: `${cve.id} Vulnerability | SENTINEL APEX`, description, url, type: "article" },
    twitter: { card: "summary", title, description },
  };
}

export default async function CvePage({ params }: Props) {
  const { slug } = await params;
  const cve = getCveBySlug(slug);
  if (!cve) notFound();

  const url = `https://intel.cyberdudebivash.com/cves/${cve.slug}`;
  const cveYear = cve.id.split("-")[1];

  const articleSchema = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "@id": url,
    headline: `${cve.id} — Vulnerability Intelligence Profile`,
    description: `Severity: ${cve.severity}. Advisory coverage: ${cve.advisory_count} advisories. CISA KEV: ${cve.kev_present ? "Yes" : "No"}. MITRE techniques: ${cve.mitre_tactics.map((t) => t.id).join(", ")}.`,
    url,
    datePublished: cve.published_at || "2026-06-01",
    dateModified: "2026-06-19",
    author: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    publisher: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    keywords: [cve.id, "CVE", "vulnerability", cve.severity, "EPSS", "MITRE ATT&CK", ...cve.mitre_tactics.map((t) => t.id)].join(", "),
  };

  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
      { "@type": "ListItem", position: 2, name: "CVE Intelligence", item: "https://intel.cyberdudebivash.com/cves" },
      { "@type": "ListItem", position: 3, name: cve.id, item: url },
    ],
  };

  const relatedCves = CVE_RECORDS.filter(
    (c) => c.id !== cve.id && (c.severity === cve.severity || c.mitre_tactics.some((t) => cve.mitre_tactics.some((ct) => ct.id === t.id)))
  ).slice(0, 6);

  return (
    <IntelPageLayout
      breadcrumbs={[
        { label: "CVE Intelligence", href: "/cves" },
        { label: cve.id },
      ]}
    >
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <ThreatLevelBadge level={cve.severity} />
          {cve.kev_present && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-red-500/15 text-red-400 border-red-500/30">
              CISA KEV
            </span>
          )}
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-gray-800 text-gray-400 border-gray-700">
            {cveYear}
          </span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-bold font-mono text-white mb-2">{cve.id}</h1>
        <p className="text-gray-400 text-base">
          Vulnerability intelligence profile — severity {cve.severity}, {cve.advisory_count} correlated advisories,
          tracked across {cve.mitre_tactics.length} MITRE ATT&CK technique{cve.mitre_tactics.length !== 1 ? "s" : ""}.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main */}
        <div className="lg:col-span-2 space-y-8">

          {/* Score dashboard */}
          <section className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-xs text-gray-500 mb-1">Severity</p>
              <ThreatLevelBadge level={cve.severity} />
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-xs text-gray-500 mb-1">CVSS Score</p>
              <p className="text-sm font-semibold text-white">{cve.cvss_score != null ? cve.cvss_score.toFixed(1) : "Pending"}</p>
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-xs text-gray-500 mb-1">EPSS Score</p>
              <p className="text-sm font-semibold text-white">{cve.epss_score != null ? (cve.epss_score * 100).toFixed(2) + "%" : "Pending"}</p>
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-xs text-gray-500 mb-1">CISA KEV</p>
              <p className={`text-sm font-semibold ${cve.kev_present ? "text-red-400" : "text-gray-400"}`}>
                {cve.kev_present ? "Yes — BOD 22-01" : "Not Listed"}
              </p>
            </div>
          </section>

          {/* Advisory coverage */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Advisory Coverage</h2>
            <div className="flex items-center gap-4 mb-4">
              <div className="flex-1 bg-gray-800 rounded-full h-2">
                <div
                  className="bg-cyan-500 h-2 rounded-full transition-all"
                  style={{ width: `${Math.min(100, (cve.advisory_count / 30) * 100)}%` }}
                />
              </div>
              <span className="text-sm font-semibold text-white flex-shrink-0">{cve.advisory_count} advisories</span>
            </div>
            <p className="text-sm text-gray-400">
              This vulnerability appears across <strong className="text-white">{cve.advisory_count}</strong> correlated threat advisories
              in the SENTINEL APEX intelligence corpus. High advisory coverage indicates broad industry reporting and
              active threat actor interest.
            </p>
            <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
                <p className="text-gray-500 mb-0.5">Intelligence Score</p>
                <p className="text-white font-semibold">{cve.risk_score.toFixed(1)} / 100</p>
              </div>
              <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
                <p className="text-gray-500 mb-0.5">Published</p>
                <p className="text-white font-semibold">{cve.published_at || "2026"}</p>
              </div>
            </div>
          </section>

          {/* MITRE ATT&CK */}
          {cve.mitre_tactics.length > 0 && (
            <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
              <h2 className="text-base font-semibold text-white mb-4">MITRE ATT&CK Techniques</h2>
              <div className="space-y-3">
                {cve.mitre_tactics.map((tactic) => (
                  <div key={tactic.id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-800/60 border border-gray-700">
                    <span className="font-mono text-xs font-semibold text-cyan-400 bg-cyan-500/10 px-2 py-1 rounded flex-shrink-0">
                      {tactic.id}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-white">{tactic.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">Tactic: {tactic.tactic}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Remediation guidance */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Remediation Guidance</h2>
            <ul className="space-y-3 text-sm text-gray-400">
              <li className="flex items-start gap-2">
                <span className="text-cyan-500 mt-0.5 flex-shrink-0">1.</span>
                Apply vendor patches immediately — check NVD and vendor security bulletins for patch availability.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-500 mt-0.5 flex-shrink-0">2.</span>
                If no patch is available, implement mitigations: disable affected feature, restrict network access, or apply WAF rules.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-500 mt-0.5 flex-shrink-0">3.</span>
                Deploy SENTINEL APEX-generated Sigma and YARA detection rules to your SIEM and EDR for exploitation attempts.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-500 mt-0.5 flex-shrink-0">4.</span>
                {cve.kev_present
                  ? "CISA KEV listed — federal agencies must remediate within 2 weeks per BOD 22-01. All organizations should treat as urgent."
                  : "Monitor CISA KEV for escalation. Enable alerting for IOCs associated with this CVE in your threat intelligence platform."}
              </li>
            </ul>
          </section>
        </div>

        {/* Sidebar */}
        <aside className="space-y-6">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
            <h3 className="text-sm font-semibold text-cyan-400 mb-3">SENTINEL APEX Coverage</h3>
            <ul className="space-y-2 text-xs text-gray-400">
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Real-time advisory correlation</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> EPSS scoring integration</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> CISA KEV status monitoring</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Sigma detection rules</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> YARA signatures</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> STIX 2.1 bundle export</li>
            </ul>
            <Link href="/" className="block mt-4 text-center px-4 py-2 rounded-lg bg-cyan-500 text-gray-950 font-semibold text-xs hover:bg-cyan-400 transition-colors">
              Full CVE Intelligence
            </Link>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
            <h3 className="text-sm font-semibold text-white mb-3">Related Intelligence</h3>
            <ul className="space-y-2 text-xs">
              <li><Link href="/cves.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ CVE Intelligence Hub</Link></li>
              <li><Link href="/kev.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ CISA KEV Tracker</Link></li>
              <li><Link href="/vulnerabilities.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ Vulnerability Hub</Link></li>
              <li><Link href="/advisories.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ Security Advisories</Link></li>
              <li><Link href="/iocs.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ IOC Intelligence</Link></li>
            </ul>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
            <h3 className="text-sm font-semibold text-white mb-2">External References</h3>
            <ul className="space-y-2 text-xs">
              <li>
                <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-cyan-400 transition-colors">
                  → NVD — {cve.id} ↗
                </a>
              </li>
              <li>
                <a href={`https://www.cve.org/CVERecord?id=${cve.id}`} target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-cyan-400 transition-colors">
                  → CVE.org Record ↗
                </a>
              </li>
              <li>
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-cyan-400 transition-colors">
                  → CISA KEV Catalog ↗
                </a>
              </li>
            </ul>
          </div>

          <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4 text-xs text-gray-500">
            <span className="text-green-400 font-semibold">TLP:GREEN</span> — Intelligence sourced from NVD, CISA, vendor advisories, and SENTINEL APEX correlation engine.
          </div>
        </aside>
      </div>

      {/* Related CVEs */}
      {relatedCves.length > 0 && (
        <section className="mt-12">
          <h2 className="text-lg font-semibold text-white mb-4">Related CVEs</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {relatedCves.map((rc) => (
              <Link
                key={rc.id}
                href={`/cves/${rc.slug}`}
                className="group rounded-lg border border-gray-800 bg-gray-900/40 p-4 hover:border-cyan-500/30 transition-colors"
              >
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="font-mono text-sm font-semibold text-cyan-400 group-hover:text-cyan-300">{rc.id}</span>
                  <ThreatLevelBadge level={rc.severity} />
                </div>
                <p className="text-xs text-gray-500">{rc.advisory_count} advisories · {rc.mitre_tactics.map((t) => t.id).join(", ")}</p>
              </Link>
            ))}
          </div>
        </section>
      )}
    </IntelPageLayout>
  );
}
