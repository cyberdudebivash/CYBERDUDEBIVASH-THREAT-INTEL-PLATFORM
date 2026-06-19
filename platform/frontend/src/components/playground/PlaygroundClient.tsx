"use client";
import { useState, useCallback } from "react";
import Link from "next/link";
import { IOC_RECORDS, CVE_RECORDS, THREAT_ACTORS } from "@/lib/intel-data";
import type { IocRecord, CveRecord, ThreatActor } from "@/lib/intel-data";

type Tab = "ioc" | "cve" | "actor";

type SearchResult =
  | { kind: "ioc"; data: IocRecord }
  | { kind: "cve"; data: CveRecord }
  | { kind: "actor"; data: ThreatActor };

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  LOW: "text-green-400 bg-green-500/10 border-green-500/30",
};

const THREAT_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-green-400",
};

const PLACEHOLDERS: Record<Tab, string> = {
  ioc: "Search by IP, domain, hash, threat actor, or tag (e.g. 45.32.74.183, APT29, lockbit)…",
  cve: "Search by CVE ID or severity (e.g. CVE-2026-10696, HIGH, CRITICAL)…",
  actor: "Search by threat actor name, country, or alias (e.g. APT28, Russia, FancyBear)…",
};

function searchIocs(q: string): IocRecord[] {
  const lq = q.toLowerCase();
  return IOC_RECORDS.filter(
    (r) =>
      r.value.toLowerCase().includes(lq) ||
      (r.threat_actor?.toLowerCase().includes(lq) ?? false) ||
      (r.malware_family?.toLowerCase().includes(lq) ?? false) ||
      r.threat_type.toLowerCase().includes(lq) ||
      r.tags.some((t) => t.toLowerCase().includes(lq)) ||
      r.type.toLowerCase().includes(lq)
  ).slice(0, 8);
}

function searchCves(q: string): CveRecord[] {
  const lq = q.toLowerCase();
  return CVE_RECORDS.filter(
    (r) =>
      r.id.toLowerCase().includes(lq) ||
      r.severity.toLowerCase().includes(lq) ||
      r.mitre_tactics.some(
        (t) => t.name.toLowerCase().includes(lq) || t.tactic.toLowerCase().includes(lq)
      )
  ).slice(0, 8);
}

function searchActors(q: string): ThreatActor[] {
  const lq = q.toLowerCase();
  return THREAT_ACTORS.filter(
    (r) =>
      r.display_name.toLowerCase().includes(lq) ||
      r.country.toLowerCase().includes(lq) ||
      r.sponsor.toLowerCase().includes(lq) ||
      r.aliases.some((a) => a.toLowerCase().includes(lq)) ||
      r.sectors_targeted.some((s) => s.toLowerCase().includes(lq)) ||
      r.threat_level.toLowerCase().includes(lq)
  ).slice(0, 8);
}

const QUICK: Record<Tab, { label: string; value: string }[]> = {
  ioc: [
    { label: "APT29 C2", value: "APT29" },
    { label: "LockBit IP", value: "91.193" },
    { label: "SUNBURST hash", value: "sunburst" },
    { label: "Phishing domain", value: "phishing" },
    { label: "Lazarus", value: "lazarus" },
  ],
  cve: [
    { label: "Critical CVEs", value: "CRITICAL" },
    { label: "High severity", value: "HIGH" },
    { label: "June 2026", value: "2026-06" },
    { label: "Web Shell", value: "Web Shell" },
    { label: "Privilege Esc", value: "Privilege" },
  ],
  actor: [
    { label: "APT28", value: "APT28" },
    { label: "Russian APTs", value: "Russia" },
    { label: "DPRK actors", value: "North Korea" },
    { label: "Chinese APTs", value: "China" },
    { label: "Ransomware", value: "ransomware" },
  ],
};

export function PlaygroundClient() {
  const [tab, setTab] = useState<Tab>("ioc");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [searched, setSearched] = useState(false);

  const runSearch = useCallback(
    (q: string, t: Tab) => {
      const trimmed = q.trim();
      if (!trimmed) { setResults([]); setSearched(false); return; }
      setSearched(true);
      if (t === "ioc") setResults(searchIocs(trimmed).map((d) => ({ kind: "ioc", data: d })));
      else if (t === "cve") setResults(searchCves(trimmed).map((d) => ({ kind: "cve", data: d })));
      else setResults(searchActors(trimmed).map((d) => ({ kind: "actor", data: d })));
    },
    []
  );

  const handleTab = (t: Tab) => {
    setTab(t);
    setQuery("");
    setResults([]);
    setSearched(false);
  };

  const handleQuick = (v: string) => {
    setQuery(v);
    runSearch(v, tab);
  };

  return (
    <div className="space-y-6">
      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900/60 border border-gray-800 rounded-xl p-1">
        {(["ioc", "cve", "actor"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => handleTab(t)}
            className={`flex-1 py-2.5 rounded-lg text-sm font-semibold transition-all ${
              tab === t
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "ioc" ? "IOC Lookup" : t === "cve" ? "CVE Search" : "Threat Actor Search"}
          </button>
        ))}
      </div>

      {/* Search bar */}
      <div className="relative">
        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
          <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
        <input
          type="text"
          value={query}
          onChange={(e) => { setQuery(e.target.value); runSearch(e.target.value, tab); }}
          placeholder={PLACEHOLDERS[tab]}
          className="w-full pl-12 pr-4 py-4 bg-gray-900/80 border border-gray-700 rounded-xl text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 text-sm transition-all"
        />
        {query && (
          <button
            onClick={() => { setQuery(""); setResults([]); setSearched(false); }}
            className="absolute inset-y-0 right-4 flex items-center text-gray-500 hover:text-gray-300"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Quick searches */}
      <div className="flex flex-wrap gap-2">
        <span className="text-xs text-gray-600 self-center">Try:</span>
        {QUICK[tab].map((q) => (
          <button
            key={q.value}
            onClick={() => handleQuick(q.value)}
            className="px-3 py-1 rounded-full bg-gray-800 border border-gray-700 text-xs text-gray-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
          >
            {q.label}
          </button>
        ))}
      </div>

      {/* Results */}
      {searched && results.length === 0 && (
        <div className="text-center py-12 text-gray-600">
          <p className="text-lg">No results for &ldquo;{query}&rdquo;</p>
          <p className="text-sm mt-1">Try a different term or use one of the quick searches above.</p>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs text-gray-500">{results.length} result{results.length !== 1 ? "s" : ""} — free preview (first 8 matches)</p>
          {results.map((r, i) => {
            if (r.kind === "ioc") {
              const ioc = r.data;
              return (
                <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20 font-medium">
                      {ioc.type === "hash_sha256" ? "SHA256 Hash" : ioc.type === "ip" ? "IP Address" : ioc.type === "domain" ? "Domain" : "URL"}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${SEV_COLOR[ioc.severity]}`}>{ioc.severity}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500 border border-gray-700">TLP:{ioc.tlp}</span>
                    {ioc.threat_actor && <span className="text-xs text-cyan-400">{ioc.threat_actor}</span>}
                  </div>
                  <p className="font-mono text-sm text-gray-200 break-all mb-2">
                    {ioc.type === "hash_sha256" ? `${ioc.value.slice(0, 32)}…` : ioc.value}
                  </p>
                  <p className="text-xs text-gray-500 leading-relaxed mb-3">{ioc.description.slice(0, 180)}…</p>
                  <div className="flex items-center justify-between">
                    <div className="flex flex-wrap gap-1">
                      {ioc.tags.slice(0, 4).map((t) => (
                        <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700/50">{t}</span>
                      ))}
                    </div>
                    <Link href={`/iocs/${ioc.slug}`} className="text-xs text-cyan-400 hover:text-cyan-300 shrink-0">Full Profile →</Link>
                  </div>
                </div>
              );
            }
            if (r.kind === "cve") {
              const cve = r.data;
              return (
                <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <span className="font-mono text-sm font-bold text-white">{cve.id}</span>
                    <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${SEV_COLOR[cve.severity]}`}>{cve.severity}</span>
                    {cve.kev_present && <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-semibold">CISA KEV</span>}
                  </div>
                  <div className="grid grid-cols-3 gap-3 mb-3">
                    {[
                      { label: "Risk Score", value: cve.risk_score.toFixed(1) },
                      { label: "Advisories", value: cve.advisory_count.toString() },
                      { label: "Published", value: cve.published_at },
                    ].map((m) => (
                      <div key={m.label} className="bg-gray-800/50 rounded-lg p-2.5">
                        <p className="text-xs text-gray-500">{m.label}</p>
                        <p className="text-sm font-semibold text-gray-200 mt-0.5">{m.value}</p>
                      </div>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {cve.mitre_tactics.map((t) => (
                      <span key={t.id} className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">{t.id}</span>
                    ))}
                  </div>
                  <Link href={`/cves/${cve.slug}`} className="text-xs text-cyan-400 hover:text-cyan-300">Full CVE Report →</Link>
                </div>
              );
            }
            if (r.kind === "actor") {
              const actor = r.data;
              return (
                <div key={i} className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <span className="text-base font-bold text-white">{actor.display_name}</span>
                    {actor.mitre_id && <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{actor.mitre_id}</span>}
                    <span className={`text-xs font-semibold ${THREAT_COLOR[actor.threat_level]}`}>{actor.threat_level}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 mb-3">
                    {[
                      { label: "Country", value: actor.country },
                      { label: "Sponsor", value: actor.sponsor },
                    ].map((m) => (
                      <div key={m.label}>
                        <p className="text-xs text-gray-600">{m.label}</p>
                        <p className="text-sm text-gray-300">{m.value}</p>
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-gray-500 leading-relaxed mb-3">{actor.description.slice(0, 180)}…</p>
                  <div className="flex items-center justify-between">
                    <div className="flex flex-wrap gap-1">
                      {actor.aliases.slice(0, 3).map((a) => (
                        <span key={a} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700/50">{a}</span>
                      ))}
                    </div>
                    <Link href={`/threat-actors/${actor.slug}`} className="text-xs text-cyan-400 hover:text-cyan-300 shrink-0">Full Profile →</Link>
                  </div>
                </div>
              );
            }
            return null;
          })}

          {/* Upgrade CTA */}
          <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-xl p-5 text-center">
            <p className="text-sm font-semibold text-cyan-400 mb-1">Unlock the Full Dataset</p>
            <p className="text-xs text-gray-400 mb-3">
              PRO tier includes 2.4M+ live IOCs, STIX 2.1 export, SIEM integration, and API access.
            </p>
            <div className="flex items-center justify-center gap-3">
              <a href="/get-api-key.html" className="px-4 py-2 rounded-lg bg-cyan-500 text-gray-950 text-xs font-bold hover:bg-cyan-400 transition-colors">
                Get Free API Key
              </a>
              <a href="/pricing.html" className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 text-xs font-semibold hover:bg-gray-700 transition-colors">
                View Pricing
              </a>
            </div>
          </div>
        </div>
      )}

      {!searched && (
        <div className="text-center py-12 text-gray-700">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-cyan-500/5 border border-cyan-500/10 flex items-center justify-center">
            <svg className="w-7 h-7 text-cyan-500/40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <p className="text-sm">Enter a search term above or click a quick search to begin.</p>
          <p className="text-xs mt-1">No account required — powered by SENTINEL APEX live intelligence.</p>
        </div>
      )}
    </div>
  );
}
