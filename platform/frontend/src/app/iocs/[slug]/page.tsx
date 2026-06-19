import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { IOC_RECORDS, getIocBySlug } from "@/lib/intel-data";
import type { IocType, Severity } from "@/lib/intel-data";

export const dynamic = "force-static";

export function generateStaticParams() {
  return IOC_RECORDS.map((ioc) => ({ slug: ioc.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: { slug: string };
}): Promise<Metadata> {
  const ioc = getIocBySlug(params.slug);
  if (!ioc) return { title: "IOC Not Found" };

  const title = `${ioc.value} — ${ioc.threat_type} IOC Analysis`;
  const description = `SENTINEL APEX IOC profile for ${ioc.value} (${TYPE_LABELS[ioc.type]}). ${ioc.description.slice(0, 155)}`;

  return {
    title,
    description,
    keywords: [
      ioc.value,
      ioc.threat_type,
      ioc.threat_actor ?? "threat actor",
      ioc.malware_family ?? "malware",
      "IOC analysis",
      "threat indicator",
      "MITRE ATT&CK",
      "SENTINEL APEX",
      ...ioc.tags,
    ],
    alternates: { canonical: `https://intel.cyberdudebivash.com/iocs/${ioc.slug}` },
    openGraph: {
      title: `${ioc.value} IOC | SENTINEL APEX`,
      description,
      url: `https://intel.cyberdudebivash.com/iocs/${ioc.slug}`,
    },
  };
}

const TYPE_LABELS: Record<IocType, string> = {
  ip: "IP Address",
  domain: "Domain",
  hash_sha256: "SHA256 Hash",
  url: "URL",
};

const TYPE_COLORS: Record<IocType, string> = {
  ip: "bg-blue-500/15 text-blue-400 border border-blue-500/25",
  domain: "bg-purple-500/15 text-purple-400 border border-purple-500/25",
  hash_sha256: "bg-orange-500/15 text-orange-400 border border-orange-500/25",
  url: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/25",
};

const SEV_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
  HIGH: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  MEDIUM: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30" },
  LOW: { bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/30" },
};

const CONF_COLORS: Record<string, string> = {
  HIGH: "text-emerald-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-gray-400",
};

export default function IocProfilePage({ params }: { params: { slug: string } }) {
  const ioc = getIocBySlug(params.slug);
  if (!ioc) notFound();

  const sev = SEV_COLORS[ioc.severity];
  const typeLabel = TYPE_LABELS[ioc.type];

  const iocSchema = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": `${ioc.value} — ${ioc.threat_type} IOC Analysis`,
    "description": ioc.description,
    "url": `https://intel.cyberdudebivash.com/iocs/${ioc.slug}`,
    "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
    "publisher": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
    "datePublished": ioc.first_seen,
    "dateModified": ioc.last_seen,
    "keywords": ioc.tags.join(", "),
  };

  const breadcrumbSchema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      { "@type": "ListItem", "position": 1, "name": "Home", "item": "https://intel.cyberdudebivash.com/" },
      { "@type": "ListItem", "position": 2, "name": "IOC Feed", "item": "https://intel.cyberdudebivash.com/iocs" },
      { "@type": "ListItem", "position": 3, "name": ioc.value },
    ],
  };

  return (
    <IntelPageLayout
      breadcrumbs={[
        { label: "IOC Feed", href: "/iocs" },
        { label: ioc.type === "hash_sha256" ? `${ioc.value.slice(0, 16)}…` : ioc.value },
      ]}
    >
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(iocSchema) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }} />

      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <span className={`inline-flex px-2.5 py-1 rounded text-xs font-semibold ${TYPE_COLORS[ioc.type]}`}>
            {typeLabel}
          </span>
          <span className={`inline-flex px-2.5 py-1 rounded text-xs font-semibold ${sev.bg} ${sev.text} border ${sev.border}`}>
            {ioc.severity}
          </span>
          <span className="inline-flex px-2.5 py-1 rounded text-xs font-semibold bg-gray-800 text-gray-400 border border-gray-700">
            TLP:{ioc.tlp}
          </span>
          {ioc.threat_actor && (
            <span className="inline-flex px-2.5 py-1 rounded text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {ioc.threat_actor}
            </span>
          )}
        </div>

        <h1 className="text-3xl font-bold text-white font-mono break-all mb-3">
          {ioc.value}
        </h1>
        <p className="text-gray-400 text-base leading-relaxed max-w-3xl">{ioc.description}</p>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Main details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Core attributes */}
          <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Indicator Details</h2>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm">
              {[
                { label: "Type", value: typeLabel },
                { label: "Threat Type", value: ioc.threat_type },
                { label: "Threat Actor", value: ioc.threat_actor ?? "Unknown / Unattributed" },
                { label: "Malware Family", value: ioc.malware_family ?? "N/A" },
                { label: "Confidence", value: ioc.confidence, colorClass: CONF_COLORS[ioc.confidence] },
                { label: "Severity", value: ioc.severity, colorClass: sev.text },
                { label: "First Seen", value: ioc.first_seen },
                { label: "Last Seen", value: ioc.last_seen },
                { label: "Source", value: ioc.source },
                { label: "TLP Classification", value: `TLP:${ioc.tlp}` },
              ].map(({ label, value, colorClass }) => (
                <div key={label}>
                  <dt className="text-xs text-gray-500 mb-0.5">{label}</dt>
                  <dd className={`font-medium text-sm ${colorClass ?? "text-gray-200"}`}>{value}</dd>
                </div>
              ))}
            </dl>

            {/* Full hash display */}
            {ioc.type === "hash_sha256" && (
              <div className="mt-5 pt-5 border-t border-gray-800">
                <p className="text-xs text-gray-500 mb-2">Full SHA256 Hash</p>
                <code className="block font-mono text-xs text-orange-300 bg-gray-950 border border-gray-800 rounded p-3 break-all">
                  {ioc.value}
                </code>
              </div>
            )}
          </div>

          {/* MITRE ATT&CK */}
          {ioc.mitre_tactics.length > 0 && (
            <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">MITRE ATT&CK Techniques</h2>
              <div className="space-y-3">
                {ioc.mitre_tactics.map((t) => (
                  <div key={t.id} className="flex items-start gap-3 p-3 bg-gray-800/30 rounded-lg">
                    <span className="shrink-0 px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {t.id}
                    </span>
                    <div>
                      <p className="text-sm text-gray-200">{t.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{t.tactic}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-5">
          {/* Tags */}
          <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Intelligence Tags</h3>
            <div className="flex flex-wrap gap-2">
              {ioc.tags.map((tag) => (
                <span
                  key={tag}
                  className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400 border border-gray-700"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>

          {/* Confidence gauge */}
          <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Confidence Score</h3>
            <div className="flex items-center gap-3">
              <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className={`h-2 rounded-full ${ioc.confidence === "HIGH" ? "w-full bg-emerald-500" : ioc.confidence === "MEDIUM" ? "w-2/3 bg-yellow-500" : "w-1/3 bg-gray-500"}`}
                />
              </div>
              <span className={`text-sm font-bold ${CONF_COLORS[ioc.confidence]}`}>{ioc.confidence}</span>
            </div>
            <p className="text-xs text-gray-600 mt-2 leading-relaxed">
              {ioc.confidence === "HIGH"
                ? "Confirmed active IOC with multiple independent corroborating sources."
                : ioc.confidence === "MEDIUM"
                ? "Likely malicious based on behavioral and contextual analysis."
                : "Suspected malicious. Treat with caution and validate before blocking."}
            </p>
          </div>

          {/* Back link */}
          <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Intel Feed</h3>
            <Link
              href="/iocs"
              className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              ← Back to IOC Intelligence Feed
            </Link>
          </div>
        </div>
      </div>
    </IntelPageLayout>
  );
}
