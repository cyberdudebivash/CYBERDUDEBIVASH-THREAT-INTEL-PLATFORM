"use client";
import { ExternalLink, FileText, Shield, Zap } from "lucide-react";

const INTEL_ITEMS = [
  {
    id: "APEX-ADV-001", title: "Critical: LockBit 3.0 Campaign Targeting Healthcare",
    severity: "CRITICAL", type: "Advisory", date: "2026-05-25",
    tags: ["ransomware", "healthcare", "lockbit"], tlp: "TLP:AMBER",
    summary: "Active LockBit 3.0 campaign exploiting Citrix vulnerabilities in healthcare sector. 47 victims in 30 days.",
  },
  {
    id: "APEX-ADV-002", title: "APT29 Leveraging AI Tools for Credential Phishing",
    severity: "HIGH", type: "Threat Actor", date: "2026-05-24",
    tags: ["apt29", "phishing", "ai-lures"], tlp: "TLP:GREEN",
    summary: "Russian APT29 observed using AI-generated phishing content to bypass email security. New TTPs documented.",
  },
  {
    id: "APEX-ADV-003", title: "Volt Typhoon Pre-Positioning in US Critical Infrastructure",
    severity: "CRITICAL", type: "Nation-State", date: "2026-05-23",
    tags: ["volt-typhoon", "china", "critical-infra"], tlp: "TLP:AMBER",
    summary: "CISA joint advisory confirms Volt Typhoon has embedded in US energy and water sector networks.",
  },
  {
    id: "APEX-ADV-004", title: "CVE-2026-23944: Ivanti VPN RCE — Active Exploitation",
    severity: "CRITICAL", type: "Vulnerability", date: "2026-05-22",
    tags: ["ivanti", "rce", "zero-day", "kev"], tlp: "TLP:WHITE",
    summary: "EPSS score 0.97 — actively exploited by multiple threat actors. Patch immediately. KEV listed.",
  },
];

const SEV_COLORS = { CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30", HIGH: "text-amber-400 bg-amber-500/10 border-amber-500/30", MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" };
const TLP_COLORS = { "TLP:WHITE": "text-gray-400", "TLP:GREEN": "text-emerald-400", "TLP:AMBER": "text-amber-400", "TLP:RED": "text-red-400" };

export function IntelFeed() {
  return (
    <div className="surface-card rounded-xl p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-white">Latest Intelligence Advisories</h2>
        <a href="/intelligence" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
          View all <ExternalLink size={12} />
        </a>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {INTEL_ITEMS.map((item) => (
          <div key={item.id} className="p-4 rounded-lg bg-gray-800/40 border border-gray-700/50 hover:border-gray-600 cursor-pointer transition-all group">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${SEV_COLORS[item.severity as keyof typeof SEV_COLORS]}`}>
                  {item.severity}
                </span>
                <span className="text-xs text-gray-500">{item.type}</span>
              </div>
              <span className={`text-xs font-medium ${TLP_COLORS[item.tlp as keyof typeof TLP_COLORS]}`}>{item.tlp}</span>
            </div>

            <h3 className="text-sm font-medium text-white mb-2 group-hover:text-cyan-400 transition-colors">{item.title}</h3>
            <p className="text-xs text-gray-400 mb-3 line-clamp-2">{item.summary}</p>

            <div className="flex items-center justify-between">
              <div className="flex gap-1.5 flex-wrap">
                {item.tags.map(tag => (
                  <span key={tag} className="px-1.5 py-0.5 rounded bg-gray-700 text-[10px] text-gray-400">#{tag}</span>
                ))}
              </div>
              <div className="flex gap-2">
                <button className="text-xs text-cyan-500 hover:text-cyan-400 flex items-center gap-1">
                  <FileText size={12} /> PDF
                </button>
              </div>
            </div>
            <p className="text-[10px] text-gray-600 mt-2">{item.id} · {item.date}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
