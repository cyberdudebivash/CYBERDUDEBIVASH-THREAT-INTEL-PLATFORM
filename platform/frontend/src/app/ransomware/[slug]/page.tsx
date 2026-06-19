import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { RANSOMWARE_ACTORS, getRansomwareBySlug } from "@/lib/intel-data";

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return RANSOMWARE_ACTORS.map((actor) => ({ slug: actor.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const actor = getRansomwareBySlug(slug);
  if (!actor) return { title: "Group Not Found" };

  const title = `${actor.display_name} — Ransomware Intelligence Profile`;
  const description = `${actor.display_name} ransomware intelligence: TTPs, victim sectors, malware variants, disruption status, and MITRE ATT&CK mapping. Active ${actor.active_since}–${actor.last_active}. Tracked by CYBERDUDEBIVASH® SENTINEL APEX.`;
  const url = `https://intel.cyberdudebivash.com/ransomware/${actor.slug}`;

  return {
    title,
    description,
    alternates: { canonical: url },
    openGraph: { title: `${actor.display_name} | SENTINEL APEX Ransomware Intel`, description, url, type: "article" },
    twitter: { card: "summary", title, description },
  };
}

const STATUS_MAP: Record<string, { label: string; detail: string; color: string }> = {
  LockBit: { label: "Disrupted", detail: "Operation Cronos — Feb 2024 (FBI / Europol / NCA)", color: "text-amber-400 border-amber-500/30 bg-amber-500/10" },
  BlackCatALPHV: { label: "Defunct", detail: "Exit scam — March 2024 after Change Healthcare $22M ransom", color: "text-gray-400 border-gray-600/30 bg-gray-800/50" },
  BlackBasta: { label: "Active", detail: "Ongoing double-extortion operations", color: "text-red-400 border-red-500/30 bg-red-500/10" },
  Akira: { label: "Active", detail: "Expanding victim count, exploiting Cisco VPN vulnerabilities", color: "text-red-400 border-red-500/30 bg-red-500/10" },
  Clop: { label: "Active", detail: "Mass exploitation of zero-days in file transfer software", color: "text-red-400 border-red-500/30 bg-red-500/10" },
  Hive: { label: "Disrupted", detail: "FBI infiltration + seizure — January 2023", color: "text-green-400 border-green-500/30 bg-green-500/10" },
  ScatteredSpider: { label: "Active", detail: "Social engineering and SIM-swap attacks ongoing", color: "text-red-400 border-red-500/30 bg-red-500/10" },
  EvilCorp: { label: "Sanctioned", detail: "OFAC sanctions (2019) — US Treasury. Affiliates active", color: "text-amber-400 border-amber-500/30 bg-amber-500/10" },
  FIN7: { label: "Active", detail: "Pivoted to Black Basta ransomware deployment", color: "text-red-400 border-red-500/30 bg-red-500/10" },
  TA505: { label: "Reduced Activity", detail: "Linked to Cl0p; reduced volume after law enforcement action", color: "text-amber-400 border-amber-500/30 bg-amber-500/10" },
};

export default async function RansomwareGroupPage({ params }: Props) {
  const { slug } = await params;
  const actor = getRansomwareBySlug(slug);
  if (!actor) notFound();

  const url = `https://intel.cyberdudebivash.com/ransomware/${actor.slug}`;
  const status = STATUS_MAP[actor.id] ?? { label: "Monitoring", detail: "Under continuous monitoring", color: "text-gray-400 border-gray-600/30 bg-gray-800/50" };

  const articleSchema = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "@id": url,
    headline: `${actor.display_name} — Ransomware Intelligence Profile`,
    description: actor.description,
    url,
    dateModified: "2026-06-19",
    author: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    publisher: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    keywords: [actor.display_name, ...actor.aliases, "ransomware", "RaaS", "cyber extortion", actor.country].join(", "),
  };

  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
      { "@type": "ListItem", position: 2, name: "Ransomware", item: "https://intel.cyberdudebivash.com/ransomware" },
      { "@type": "ListItem", position: 3, name: actor.display_name, item: url },
    ],
  };

  const relatedGroups = RANSOMWARE_ACTORS.filter((a) => a.id !== actor.id).slice(0, 4);
  const ttpIds = actor.primary_ttps.map((t) => t.split(" ")[0]);

  return (
    <IntelPageLayout
      breadcrumbs={[
        { label: "Ransomware Intelligence", href: "/ransomware" },
        { label: actor.display_name },
      ]}
    >
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <ThreatLevelBadge level={actor.threat_level} />
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${status.color}`}>
            {status.label}
          </span>
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-violet-500/10 border-violet-500/20 text-violet-400">
            Ransomware Operator
          </span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">{actor.display_name}</h1>
        <p className="text-gray-400 text-lg max-w-3xl">{actor.description}</p>

        {/* Status banner */}
        <div className={`mt-6 rounded-lg border p-4 text-sm ${status.color}`}>
          <span className="font-semibold">Current Status: {status.label}</span>
          <span className="text-gray-400 ml-2">— {status.detail}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main */}
        <div className="lg:col-span-2 space-y-8">

          {/* Key metrics */}
          <section className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            {[
              { label: "First Observed", value: actor.active_since },
              { label: "Last Active", value: actor.last_active },
              { label: "Country", value: actor.country },
              { label: "Threat Level", value: actor.threat_level },
              { label: "Motivation", value: actor.motivation[0] },
              { label: "Aliases", value: `${actor.aliases.length} known` },
            ].map((m) => (
              <div key={m.label} className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <p className="text-xs text-gray-500 mb-1">{m.label}</p>
                <p className="text-sm font-semibold text-white">{m.value}</p>
              </div>
            ))}
          </section>

          {/* Sponsorship */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Sponsorship & Attribution</h2>
            <div className="space-y-3 text-sm">
              <div className="flex gap-4">
                <span className="text-gray-500 w-28 flex-shrink-0">Sponsor</span>
                <span className="text-gray-300">{actor.sponsor}</span>
              </div>
              <div className="flex gap-4">
                <span className="text-gray-500 w-28 flex-shrink-0">Motivation</span>
                <span className="text-gray-300">{actor.motivation.join(" · ")}</span>
              </div>
              <div className="flex gap-4">
                <span className="text-gray-500 w-28 flex-shrink-0">Aliases</span>
                <span className="text-gray-300">{actor.aliases.join(", ")}</span>
              </div>
            </div>
          </section>

          {/* MITRE ATT&CK */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">MITRE ATT&CK Techniques</h2>
            <div className="flex flex-wrap gap-2 mb-4">
              {ttpIds.map((ttp) => (
                <span key={ttp} className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-gray-800 border border-gray-700 text-cyan-400">
                  {ttp}
                </span>
              ))}
            </div>
            <ul className="space-y-2 text-sm text-gray-400">
              {actor.primary_ttps.map((ttp) => (
                <li key={ttp} className="flex items-start gap-2">
                  <span className="text-violet-500 mt-0.5">›</span>
                  <span>{ttp}</span>
                </li>
              ))}
            </ul>
          </section>

          {/* Ransomware tools */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Ransomware Variants & Tooling</h2>
            <div className="flex flex-wrap gap-2">
              {actor.malware.map((m) => (
                <span key={m} className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-red-500/10 border border-red-500/20 text-red-400">
                  {m}
                </span>
              ))}
            </div>
          </section>

          {/* Target sectors */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Target Sectors</h2>
            <div className="flex flex-wrap gap-2">
              {actor.sectors_targeted.map((sector) => (
                <span key={sector} className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-gray-800 border border-gray-700 text-gray-300">
                  {sector}
                </span>
              ))}
            </div>
          </section>
        </div>

        {/* Sidebar */}
        <aside className="space-y-6">
          <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-5">
            <h3 className="text-sm font-semibold text-violet-400 mb-3">SENTINEL APEX Coverage</h3>
            <ul className="space-y-2 text-xs text-gray-400">
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Leak site monitoring</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Victim publication alerts</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> IOC correlation feed</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> STIX 2.1 bundle</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Sigma / YARA rules</li>
              <li className="flex items-center gap-2"><span className="text-amber-400">●</span> Decryption key database</li>
            </ul>
            <Link href="/" className="block mt-4 text-center px-4 py-2 rounded-lg bg-violet-500 text-white font-semibold text-xs hover:bg-violet-400 transition-colors">
              Access Full Intelligence
            </Link>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
            <h3 className="text-sm font-semibold text-white mb-3">Related Intelligence</h3>
            <ul className="space-y-2 text-xs">
              <li><Link href="/ransomware.html" className="text-gray-400 hover:text-violet-400 transition-colors">→ Ransomware Hub</Link></li>
              <li><Link href="/iocs.html" className="text-gray-400 hover:text-violet-400 transition-colors">→ IOC Intelligence</Link></li>
              <li><Link href="/threats.html" className="text-gray-400 hover:text-violet-400 transition-colors">→ Threat Intelligence Hub</Link></li>
              <li><Link href="/kev.html" className="text-gray-400 hover:text-violet-400 transition-colors">→ CISA KEV Tracking</Link></li>
              <li><Link href="/threat-actors" className="text-gray-400 hover:text-violet-400 transition-colors">→ All Threat Actors</Link></li>
            </ul>
          </div>

          <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4 text-xs text-gray-500">
            <span className="text-green-400 font-semibold">TLP:GREEN</span> — Shareable within the cybersecurity community. Data sourced from law enforcement advisories, ISAC reports, and SENTINEL APEX intelligence feeds.
          </div>
        </aside>
      </div>

      {/* Related groups */}
      <section className="mt-12">
        <h2 className="text-lg font-semibold text-white mb-4">Other Tracked Ransomware Groups</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {relatedGroups.map((ra) => (
            <Link key={ra.id} href={`/ransomware/${ra.slug}`} className="group rounded-lg border border-gray-800 bg-gray-900/40 p-4 hover:border-violet-500/30 transition-colors">
              <div className="flex items-start justify-between gap-2 mb-2">
                <span className="text-sm font-medium text-white group-hover:text-violet-400 transition-colors leading-tight">{ra.display_name}</span>
                <ThreatLevelBadge level={ra.threat_level} />
              </div>
              <p className="text-xs text-gray-500 line-clamp-2">{ra.description}</p>
            </Link>
          ))}
        </div>
      </section>
    </IntelPageLayout>
  );
}
