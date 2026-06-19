import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { THREAT_ACTORS } from "@/lib/intel-data";

export const metadata: Metadata = {
  title: "Threat Actor Profiles — APT Groups & Cybercriminal Organizations",
  description:
    "Comprehensive threat actor intelligence database covering 25+ APT groups, nation-state actors, and cybercriminal organizations. MITRE ATT&CK mapping, TTP analysis, and campaign history — powered by CYBERDUDEBIVASH® SENTINEL APEX.",
  alternates: { canonical: "https://intel.cyberdudebivash.com/threat-actors" },
  openGraph: {
    title: "Threat Actor Profiles | CYBERDUDEBIVASH® SENTINEL APEX",
    description: "25+ APT groups and cybercriminal organizations with MITRE ATT&CK mapping, TTP analysis, and campaign history.",
    url: "https://intel.cyberdudebivash.com/threat-actors",
    type: "website",
  },
};

const COUNTRY_GROUPS: Record<string, string[]> = {
  Russia: ["APT28", "APT29", "Turla", "FancyBear", "Sandworm", "LAPSUS", "TA505", "LockBit", "BlackBasta", "Clop", "EvilCorp", "UNC2452", "MuddyWater"],
  China: ["APT41", "VoltTyphoon", "MustangPanda", "Hafnium"],
  "North Korea": ["Lazarus"],
  Iran: ["APT33", "APT35"],
  Criminal: ["ScatteredSpider", "Akira", "Hive", "BlackCatALPHV", "FIN7"],
};

const listingSchema = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Cyber Threat Actor Intelligence Database — SENTINEL APEX",
  description: "Comprehensive database of APT groups, nation-state actors, and cybercriminal organizations tracked by CYBERDUDEBIVASH SENTINEL APEX.",
  url: "https://intel.cyberdudebivash.com/threat-actors",
  numberOfItems: THREAT_ACTORS.length,
  itemListElement: THREAT_ACTORS.map((actor, idx) => ({
    "@type": "ListItem",
    position: idx + 1,
    name: actor.display_name,
    url: `https://intel.cyberdudebivash.com/threat-actors/${actor.slug}`,
  })),
};

const breadcrumbSchema = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
    { "@type": "ListItem", position: 2, name: "Threat Actors", item: "https://intel.cyberdudebivash.com/threat-actors" },
  ],
};

const CRITICAL_COUNT = THREAT_ACTORS.filter((a) => a.threat_level === "CRITICAL").length;
const NATION_STATE_COUNT = THREAT_ACTORS.filter((a) => ["Russia", "China", "North Korea", "Iran"].includes(a.country)).length;
const RANSOMWARE_COUNT = THREAT_ACTORS.filter((a) => a.is_ransomware).length;

export default function ThreatActorsPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "Threat Actors" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(listingSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
          LIVE TRACKING
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">
          Threat Actor Intelligence Database
        </h1>
        <p className="text-gray-400 text-lg max-w-3xl">
          Comprehensive profiling of {THREAT_ACTORS.length} APT groups, nation-state actors, and cybercriminal
          organizations — with MITRE ATT&CK mapping, TTP analysis, campaign history, and real-time tracking by
          CYBERDUDEBIVASH® SENTINEL APEX.
        </p>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8">
          {[
            { label: "Tracked Actors", value: String(THREAT_ACTORS.length) },
            { label: "Critical Threat Level", value: String(CRITICAL_COUNT) },
            { label: "Nation-State APTs", value: String(NATION_STATE_COUNT) },
            { label: "Ransomware Groups", value: String(RANSOMWARE_COUNT) },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-2xl font-bold text-white">{s.value}</p>
              <p className="text-xs text-gray-500 mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Actor grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {THREAT_ACTORS.map((actor) => (
          <Link
            key={actor.id}
            href={`/threat-actors/${actor.slug}`}
            className="group rounded-xl border border-gray-800 bg-gray-900/50 p-5 hover:border-cyan-500/30 hover:bg-gray-900/80 transition-all"
          >
            <div className="flex items-start justify-between gap-3 mb-3">
              <h2 className="text-sm font-semibold text-white group-hover:text-cyan-400 transition-colors leading-tight">
                {actor.display_name}
              </h2>
              <ThreatLevelBadge level={actor.threat_level} />
            </div>

            <p className="text-xs text-gray-500 mb-3 line-clamp-2">{actor.description}</p>

            <div className="space-y-1.5 text-xs">
              <div className="flex gap-2">
                <span className="text-gray-600 w-14 flex-shrink-0">Origin</span>
                <span className="text-gray-400">{actor.country}</span>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-600 w-14 flex-shrink-0">Active</span>
                <span className="text-gray-400">{actor.active_since}–{actor.last_active}</span>
              </div>
              {actor.mitre_id && (
                <div className="flex gap-2">
                  <span className="text-gray-600 w-14 flex-shrink-0">MITRE</span>
                  <span className="text-cyan-600">{actor.mitre_id}</span>
                </div>
              )}
            </div>

            {actor.is_ransomware && (
              <div className="mt-3 inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs">
                Ransomware Operator
              </div>
            )}
          </Link>
        ))}
      </div>

      {/* Country breakdown */}
      <section className="mt-16">
        <h2 className="text-xl font-bold text-white mb-6">Attribution by Nation-State</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(COUNTRY_GROUPS).map(([country, ids]) => (
            <div key={country} className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
              <h3 className="text-sm font-semibold text-white mb-3">{country}</h3>
              <ul className="space-y-1.5">
                {ids.map((id) => {
                  const actor = THREAT_ACTORS.find((a) => a.id === id);
                  if (!actor) return null;
                  return (
                    <li key={id}>
                      <Link
                        href={`/threat-actors/${actor.slug}`}
                        className="text-xs text-gray-400 hover:text-cyan-400 transition-colors"
                      >
                        {actor.display_name}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <div className="mt-16 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">
        <h2 className="text-xl font-bold text-white mb-2">Real-Time Actor Tracking</h2>
        <p className="text-gray-400 text-sm mb-6 max-w-xl mx-auto">
          Get live alerts, IOC correlation, infrastructure mapping, and dark web monitoring for all tracked threat actors with SENTINEL APEX Enterprise.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-500 text-gray-950 font-semibold text-sm hover:bg-cyan-400 transition-colors"
        >
          Access Full Intelligence Platform
        </Link>
      </div>
    </IntelPageLayout>
  );
}
