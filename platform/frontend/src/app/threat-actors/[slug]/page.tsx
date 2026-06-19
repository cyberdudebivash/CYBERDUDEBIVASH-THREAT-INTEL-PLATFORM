import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { THREAT_ACTORS, getActorBySlug } from "@/lib/intel-data";

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return THREAT_ACTORS.map((actor) => ({ slug: actor.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const actor = getActorBySlug(slug);
  if (!actor) return { title: "Actor Not Found" };

  const title = `${actor.display_name} — Threat Actor Profile`;
  const description = `${actor.display_name} threat intelligence: TTPs, malware, campaigns, MITRE ATT&CK mapping (${actor.mitre_id ?? "tracked"}). Active since ${actor.active_since}. Sponsored by ${actor.sponsor}. Tracked by CYBERDUDEBIVASH® SENTINEL APEX.`;
  const url = `https://intel.cyberdudebivash.com/threat-actors/${actor.slug}`;

  return {
    title,
    description,
    alternates: { canonical: url },
    openGraph: {
      title: `${actor.display_name} | CYBERDUDEBIVASH SENTINEL APEX`,
      description,
      url,
      type: "article",
    },
    twitter: {
      card: "summary",
      title: `${actor.display_name} — Threat Actor Profile`,
      description,
    },
  };
}

export default async function ThreatActorPage({ params }: Props) {
  const { slug } = await params;
  const actor = getActorBySlug(slug);
  if (!actor) notFound();

  const url = `https://intel.cyberdudebivash.com/threat-actors/${actor.slug}`;

  const articleSchema = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "@id": url,
    headline: `${actor.display_name} — Threat Actor Intelligence Profile`,
    description: actor.description,
    url,
    dateModified: "2026-06-19",
    author: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    publisher: { "@type": "Organization", "@id": "https://cyberdudebivash.com/#organization" },
    mainEntityOfPage: url,
    keywords: [actor.display_name, ...actor.aliases, "threat actor", "APT", "MITRE ATT&CK", actor.country].join(", "),
  };

  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
      { "@type": "ListItem", position: 2, name: "Threat Actors", item: "https://intel.cyberdudebivash.com/threat-actors" },
      { "@type": "ListItem", position: 3, name: actor.display_name, item: url },
    ],
  };

  const relatedActors = THREAT_ACTORS.filter(
    (a) => a.id !== actor.id && a.country === actor.country
  ).slice(0, 4);

  const ttpIds = actor.primary_ttps.map((t) => t.split(" ")[0]);

  return (
    <IntelPageLayout
      breadcrumbs={[
        { label: "Threat Actors", href: "/threat-actors" },
        { label: actor.display_name },
      ]}
    >
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <ThreatLevelBadge level={actor.threat_level} />
          {actor.is_ransomware && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-violet-500/15 text-violet-400 border-violet-500/30">
              Ransomware Operator
            </span>
          )}
          {actor.mitre_id && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
              MITRE {actor.mitre_id}
            </span>
          )}
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">{actor.display_name}</h1>
        <p className="text-gray-400 text-lg max-w-3xl">{actor.description}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-8">

          {/* Key metrics */}
          <section className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            {[
              { label: "Country of Origin", value: actor.country },
              { label: "Active Since", value: actor.active_since },
              { label: "Last Observed", value: actor.last_active },
              { label: "Threat Level", value: actor.threat_level },
              { label: "MITRE ATT&CK", value: actor.mitre_id ?? "Tracked (no ID)" },
              { label: "Aliases", value: String(actor.aliases.length) + " known" },
            ].map((m) => (
              <div key={m.label} className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <p className="text-xs text-gray-500 mb-1">{m.label}</p>
                <p className="text-sm font-semibold text-white">{m.value}</p>
              </div>
            ))}
          </section>

          {/* Sponsor & Motivation */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Attribution & Sponsorship</h2>
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
                <span className="text-gray-500 w-28 flex-shrink-0">Known Aliases</span>
                <span className="text-gray-300">{actor.aliases.join(", ")}</span>
              </div>
            </div>
          </section>

          {/* MITRE ATT&CK TTPs */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">MITRE ATT&CK Techniques</h2>
            <div className="flex flex-wrap gap-2 mb-4">
              {ttpIds.map((ttp) => (
                <span
                  key={ttp}
                  className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-gray-800 border border-gray-700 text-cyan-400"
                >
                  {ttp}
                </span>
              ))}
            </div>
            <ul className="space-y-2 text-sm text-gray-400">
              {actor.primary_ttps.map((ttp) => (
                <li key={ttp} className="flex items-start gap-2">
                  <span className="text-cyan-600 mt-0.5">›</span>
                  <span>{ttp}</span>
                </li>
              ))}
            </ul>
            {actor.mitre_id && (
              <a
                href={actor.profile_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 mt-4 text-xs text-cyan-500 hover:text-cyan-400 transition-colors"
              >
                View full MITRE ATT&CK profile ↗
              </a>
            )}
          </section>

          {/* Tooling & Malware */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Malware & Tooling</h2>
            <div className="flex flex-wrap gap-2">
              {actor.malware.map((m) => (
                <span
                  key={m}
                  className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-red-500/10 border border-red-500/20 text-red-400"
                >
                  {m}
                </span>
              ))}
            </div>
          </section>

          {/* Target Sectors */}
          <section className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h2 className="text-base font-semibold text-white mb-4">Target Sectors</h2>
            <div className="flex flex-wrap gap-2">
              {actor.sectors_targeted.map((sector) => (
                <span
                  key={sector}
                  className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-gray-800 border border-gray-700 text-gray-300"
                >
                  {sector}
                </span>
              ))}
            </div>
          </section>
        </div>

        {/* Sidebar */}
        <aside className="space-y-6">
          {/* Quick intelligence */}
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
            <h3 className="text-sm font-semibold text-cyan-400 mb-3">SENTINEL APEX Intelligence</h3>
            <ul className="space-y-2 text-xs text-gray-400">
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Active IOC correlation</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Infrastructure graph tracking</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> STIX 2.1 bundle available</li>
              <li className="flex items-center gap-2"><span className="text-emerald-400">●</span> Sigma & YARA rules generated</li>
              <li className="flex items-center gap-2"><span className="text-amber-400">●</span> Dark web monitoring active</li>
            </ul>
            <Link
              href="/"
              className="block mt-4 text-center px-4 py-2 rounded-lg bg-cyan-500 text-gray-950 font-semibold text-xs hover:bg-cyan-400 transition-colors"
            >
              Access Full Profile
            </Link>
          </div>

          {/* Related threat hub links */}
          <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
            <h3 className="text-sm font-semibold text-white mb-3">Related Intelligence</h3>
            <ul className="space-y-2 text-xs">
              <li><Link href="/threats.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ Threat Intelligence Hub</Link></li>
              <li><Link href="/iocs.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ IOC Intelligence</Link></li>
              <li><Link href="/advisories.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ Security Advisories</Link></li>
              {actor.is_ransomware && (
                <li><Link href="/ransomware.html" className="text-gray-400 hover:text-cyan-400 transition-colors">→ Ransomware Intelligence</Link></li>
              )}
              <li><Link href="/cves" className="text-gray-400 hover:text-cyan-400 transition-colors">→ CVE Intelligence</Link></li>
            </ul>
          </div>

          {/* TLP notice */}
          <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4 text-xs text-gray-500">
            <span className="text-green-400 font-semibold">TLP:GREEN</span> — This intelligence may be shared within the cybersecurity community. Not for public disclosure without context.
          </div>
        </aside>
      </div>

      {/* Related actors */}
      {relatedActors.length > 0 && (
        <section className="mt-12">
          <h2 className="text-lg font-semibold text-white mb-4">Related Actors — {actor.country}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {relatedActors.map((ra) => (
              <Link
                key={ra.id}
                href={`/threat-actors/${ra.slug}`}
                className="group rounded-lg border border-gray-800 bg-gray-900/40 p-4 hover:border-gray-700 transition-colors"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-sm font-medium text-white group-hover:text-cyan-400 transition-colors leading-tight">
                    {ra.display_name}
                  </span>
                  <ThreatLevelBadge level={ra.threat_level} />
                </div>
                <p className="text-xs text-gray-500 line-clamp-2">{ra.description}</p>
              </Link>
            ))}
          </div>
        </section>
      )}
    </IntelPageLayout>
  );
}
