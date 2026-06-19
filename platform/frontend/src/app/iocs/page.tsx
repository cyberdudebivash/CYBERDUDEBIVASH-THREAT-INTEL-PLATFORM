import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";
import { IOC_RECORDS } from "@/lib/intel-data";
import type { IocType, Severity } from "@/lib/intel-data";

export const metadata: Metadata = {
  title: "IOC Intelligence Feed — Indicators of Compromise",
  description:
    "CYBERDUDEBIVASH® SENTINEL APEX IOC Intelligence Feed — live indicators of compromise including malicious IPs, phishing domains, and malware SHA256 hashes. MITRE ATT&CK mapped, TLP:GREEN, updated continuously.",
  keywords: [
    "IOC feed", "indicators of compromise", "malicious IP", "phishing domain",
    "SHA256 malware hash", "STIX 2.1 IOC", "TAXII feed", "threat indicator",
    "Cobalt Strike beacon hash", "APT IOC", "ransomware IP", "SENTINEL APEX",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/iocs" },
  openGraph: {
    title: "IOC Intelligence Feed | CYBERDUDEBIVASH® SENTINEL APEX",
    description: "Live indicators of compromise — malicious IPs, phishing domains, malware hashes. MITRE ATT&CK mapped.",
    url: "https://intel.cyberdudebivash.com/iocs",
  },
};

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

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-green-400",
};

const iocSchema = {
  "@context": "https://schema.org",
  "@type": "Dataset",
  "name": "CYBERDUDEBIVASH SENTINEL APEX — IOC Intelligence Feed",
  "description": "Curated, MITRE ATT&CK-mapped indicators of compromise including malicious IP addresses, phishing domains, and malware SHA256 hashes. TLP:GREEN, continuously updated.",
  "url": "https://intel.cyberdudebivash.com/iocs",
  "creator": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
  "license": "https://www.cisa.gov/tlp",
  "keywords": ["IOC", "threat indicator", "malware hash", "phishing domain", "malicious IP"],
};

export default function IocsPage() {
  const ips = IOC_RECORDS.filter((r) => r.type === "ip");
  const domains = IOC_RECORDS.filter((r) => r.type === "domain");
  const hashes = IOC_RECORDS.filter((r) => r.type === "hash_sha256");

  return (
    <IntelPageLayout
      breadcrumbs={[{ label: "IOC Intelligence Feed" }]}
    >
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(iocSchema) }}
      />

      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-400 text-xs font-semibold mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse" />
          LIVE IOC FEED — TLP:GREEN
        </div>
        <h1 className="text-4xl font-bold text-white mb-3">
          IOC Intelligence Feed
        </h1>
        <p className="text-gray-400 text-lg max-w-3xl leading-relaxed">
          Curated indicators of compromise (IOCs) sourced from active threat campaigns, government advisories,
          and SENTINEL APEX sensors. Each indicator is enriched with MITRE ATT&CK mapping,
          threat actor attribution, and confidence scoring.
        </p>

        {/* Stats */}
        <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total IOCs", value: IOC_RECORDS.length.toString(), color: "text-cyan-400" },
            { label: "Malicious IPs", value: ips.length.toString(), color: "text-blue-400" },
            { label: "Phishing Domains", value: domains.length.toString(), color: "text-purple-400" },
            { label: "Malware Hashes", value: hashes.length.toString(), color: "text-orange-400" },
          ].map((stat) => (
            <div key={stat.label} className="bg-gray-900/60 border border-gray-800 rounded-lg p-4">
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
              <p className="text-xs text-gray-500 mt-1">{stat.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* IOC Table */}
      <div className="bg-gray-900/40 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            Active Threat Indicators
          </h2>
          <span className="text-xs text-gray-600">Last updated: {new Date().toISOString().split("T")[0]}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Indicator</th>
                <th className="px-4 py-3 text-left">Threat</th>
                <th className="px-4 py-3 text-left">Actor</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Confidence</th>
                <th className="px-4 py-3 text-left">Last Seen</th>
                <th className="px-4 py-3 text-left" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {IOC_RECORDS.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-gray-800/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${TYPE_COLORS[ioc.type]}`}>
                      {TYPE_LABELS[ioc.type]}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[200px] truncate">
                    {ioc.type === "hash_sha256"
                      ? `${ioc.value.slice(0, 16)}…`
                      : ioc.value}
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{ioc.threat_type}</td>
                  <td className="px-4 py-3 text-xs">
                    {ioc.threat_actor ? (
                      <span className="text-cyan-400">{ioc.threat_actor}</span>
                    ) : (
                      <span className="text-gray-600">Unknown</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-semibold text-xs ${SEV_COLORS[ioc.severity]}`}>
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">{ioc.confidence}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{ioc.last_seen}</td>
                  <td className="px-4 py-3">
                    <Link
                      href={`/iocs/${ioc.slug}`}
                      className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      Details →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Info block */}
      <div className="mt-10 grid md:grid-cols-3 gap-6">
        {[
          {
            title: "STIX 2.1 Compatible",
            body: "All IOCs are structured for export in STIX 2.1 format, compatible with MISP, OpenCTI, and TAXII 2.1 servers for automated ingestion.",
          },
          {
            title: "MITRE ATT&CK Mapped",
            body: "Every indicator is enriched with relevant MITRE ATT&CK techniques, enabling direct integration with SIEM detection rules and threat hunting playbooks.",
          },
          {
            title: "TLP:GREEN — Share Freely",
            body: "All IOCs on this feed are classified TLP:GREEN and may be shared with community partners, vendors, and security operations teams without restriction.",
          },
        ].map((item) => (
          <div key={item.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-cyan-400 mb-2">{item.title}</h3>
            <p className="text-xs text-gray-500 leading-relaxed">{item.body}</p>
          </div>
        ))}
      </div>
    </IntelPageLayout>
  );
}
