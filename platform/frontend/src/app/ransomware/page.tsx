import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { ThreatLevelBadge } from "@/components/intel-pages/ThreatLevelBadge";
import { RANSOMWARE_ACTORS } from "@/lib/intel-data";

export const metadata: Metadata = {
  title: "Ransomware Groups Intelligence — RaaS Operators & Extortion Actors",
  description:
    "Real-time ransomware group intelligence: LockBit, BlackCat/ALPHV, Black Basta, Cl0p, Akira, Hive, Evil Corp and more. TTPs, victim tracking, leak site monitoring, and decryption intelligence — CYBERDUDEBIVASH® SENTINEL APEX.",
  alternates: { canonical: "https://intel.cyberdudebivash.com/ransomware" },
  openGraph: {
    title: "Ransomware Groups Intelligence | CYBERDUDEBIVASH® SENTINEL APEX",
    description: `${RANSOMWARE_ACTORS.length} ransomware operators tracked with TTPs, victim data, and disruption status.`,
    url: "https://intel.cyberdudebivash.com/ransomware",
    type: "website",
  },
};

const listingSchema = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Ransomware Group Intelligence Database — SENTINEL APEX",
  description: `Tracking ${RANSOMWARE_ACTORS.length} ransomware-as-a-service operators and extortion groups.`,
  url: "https://intel.cyberdudebivash.com/ransomware",
  numberOfItems: RANSOMWARE_ACTORS.length,
  itemListElement: RANSOMWARE_ACTORS.map((actor, idx) => ({
    "@type": "ListItem",
    position: idx + 1,
    name: actor.display_name,
    url: `https://intel.cyberdudebivash.com/ransomware/${actor.slug}`,
  })),
};

const breadcrumbSchema = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: "https://intel.cyberdudebivash.com" },
    { "@type": "ListItem", position: 2, name: "Ransomware", item: "https://intel.cyberdudebivash.com/ransomware" },
  ],
};

const STATUS_MAP: Record<string, { label: string; color: string }> = {
  LockBit: { label: "Disrupted (Op. Cronos)", color: "text-amber-400" },
  BlackCatALPHV: { label: "Exit Scam / Defunct", color: "text-gray-500" },
  BlackBasta: { label: "Active", color: "text-red-400" },
  Akira: { label: "Active", color: "text-red-400" },
  Clop: { label: "Active", color: "text-red-400" },
  Hive: { label: "Disrupted (FBI 2023)", color: "text-green-400" },
  ScatteredSpider: { label: "Active", color: "text-red-400" },
  EvilCorp: { label: "Sanctioned", color: "text-amber-400" },
  FIN7: { label: "Active", color: "text-red-400" },
  TA505: { label: "Reduced Activity", color: "text-amber-400" },
};

export default function RansomwarePage() {
  const criticalCount = RANSOMWARE_ACTORS.filter((a) => a.threat_level === "CRITICAL").length;

  return (
    <IntelPageLayout breadcrumbs={[{ label: "Ransomware Intelligence" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(listingSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-semibold mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
          REAL-TIME TRACKING
        </div>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">
          Ransomware Groups Intelligence
        </h1>
        <p className="text-gray-400 text-lg max-w-3xl">
          Comprehensive intelligence on {RANSOMWARE_ACTORS.length} ransomware-as-a-service operators and extortion
          actors — with victim publication monitoring, TTP analysis, disruption status, and AI-powered campaign
          tracking.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8">
          {[
            { label: "Tracked Groups", value: String(RANSOMWARE_ACTORS.length) },
            { label: "Critical Severity", value: String(criticalCount) },
            { label: "Victim Sectors Monitored", value: "40+" },
            { label: "Dark Web Sources", value: "74+" },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <p className="text-2xl font-bold text-white">{s.value}</p>
              <p className="text-xs text-gray-500 mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Groups grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {RANSOMWARE_ACTORS.map((actor) => {
          const status = STATUS_MAP[actor.id] ?? { label: "Monitoring", color: "text-gray-400" };
          return (
            <Link
              key={actor.id}
              href={`/ransomware/${actor.slug}`}
              className="group rounded-xl border border-gray-800 bg-gray-900/50 p-6 hover:border-violet-500/30 hover:bg-gray-900/80 transition-all"
            >
              <div className="flex items-start justify-between gap-3 mb-3">
                <h2 className="text-base font-semibold text-white group-hover:text-violet-400 transition-colors">
                  {actor.display_name}
                </h2>
                <ThreatLevelBadge level={actor.threat_level} />
              </div>

              <p className="text-xs text-gray-500 mb-4 line-clamp-2">{actor.description}</p>

              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div>
                  <span className="text-gray-600">Status </span>
                  <span className={status.color}>{status.label}</span>
                </div>
                <div>
                  <span className="text-gray-600">Origin </span>
                  <span className="text-gray-400">{actor.country}</span>
                </div>
                <div>
                  <span className="text-gray-600">Active </span>
                  <span className="text-gray-400">{actor.active_since}–{actor.last_active}</span>
                </div>
                <div>
                  <span className="text-gray-600">Motivation </span>
                  <span className="text-gray-400">{actor.motivation[0]}</span>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-1.5">
                {actor.malware.slice(0, 3).map((m) => (
                  <span key={m} className="px-1.5 py-0.5 rounded text-xs bg-red-500/10 border border-red-500/20 text-red-400">
                    {m}
                  </span>
                ))}
              </div>
            </Link>
          );
        })}
      </div>

      {/* Capability overview */}
      <section className="mt-16 grid grid-cols-1 sm:grid-cols-3 gap-6">
        {[
          {
            title: "Victim Publication Monitoring",
            body: "Real-time monitoring of 40+ ransomware leak sites. Track new victim publications, negotiation status, and data release timelines before they reach mainstream reporting.",
          },
          {
            title: "Decryption Intelligence",
            body: "SENTINEL APEX maintains a database of publicly available decryption keys from law enforcement operations. Includes Hive, Ragnar Locker, and BlackMatter key releases.",
          },
          {
            title: "Campaign Correlation",
            body: "AI-powered clustering correlates IOCs, TTPs, and infrastructure across ransomware campaigns to identify affiliate overlaps and predecessor groups.",
          },
        ].map((c) => (
          <div key={c.title} className="rounded-xl border border-gray-800 bg-gray-900/40 p-6">
            <h3 className="text-sm font-semibold text-white mb-2">{c.title}</h3>
            <p className="text-xs text-gray-500 leading-relaxed">{c.body}</p>
          </div>
        ))}
      </section>

      {/* CTA */}
      <div className="mt-12 rounded-xl border border-violet-500/20 bg-violet-500/5 p-8 text-center">
        <h2 className="text-xl font-bold text-white mb-2">Enterprise Ransomware Intelligence</h2>
        <p className="text-gray-400 text-sm mb-6 max-w-xl mx-auto">
          Get real-time ransomware victim alerts, pre-release leak site notifications, IOC correlation, and custom threat briefings for your sector.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-violet-500 text-white font-semibold text-sm hover:bg-violet-400 transition-colors"
        >
          Access Full Ransomware Intelligence
        </Link>
      </div>
    </IntelPageLayout>
  );
}
