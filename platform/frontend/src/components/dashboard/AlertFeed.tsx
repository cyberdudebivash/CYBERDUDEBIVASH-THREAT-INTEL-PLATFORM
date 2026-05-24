"use client";
import { useState, useEffect } from "react";
import { AlertTriangle, Shield, Clock, ChevronRight } from "lucide-react";

const MOCK_ALERTS = [
  { id: "APEX-0001", severity: "critical", title: "APT29 Lateral Movement Detected", source: "EDR", time: "2m ago", status: "investigating" },
  { id: "APEX-0002", severity: "high", title: "Ransomware Behavioral Indicators", source: "NDR", time: "8m ago", status: "triaging" },
  { id: "APEX-0003", severity: "critical", title: "Volt Typhoon C2 Beacon", source: "SIEM", time: "15m ago", status: "remediating" },
  { id: "APEX-0004", severity: "high", title: "Credential Stuffing Attack", source: "WAF", time: "23m ago", status: "resolved" },
  { id: "APEX-0005", severity: "medium", title: "Suspicious PowerShell Execution", source: "EDR", time: "31m ago", status: "resolved" },
  { id: "APEX-0006", severity: "high", title: "Dark Web Credential Leak", source: "SURFACEWATCH", time: "47m ago", status: "new" },
];

const SEV_STYLES = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const STATUS_DOT = {
  new: "bg-cyan-400 animate-pulse",
  triaging: "bg-yellow-400 animate-pulse",
  investigating: "bg-amber-400 animate-pulse",
  remediating: "bg-orange-400 animate-pulse",
  resolved: "bg-emerald-400",
};

export function AlertFeed() {
  const [alerts, setAlerts] = useState(MOCK_ALERTS);

  return (
    <div className="surface-card rounded-xl p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white">Live Alert Feed</h2>
        <span className="text-xs text-gray-500 flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
          LIVE
        </span>
      </div>

      <div className="flex-1 space-y-2 overflow-y-auto">
        {alerts.map((alert) => (
          <div key={alert.id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-800/40 hover:bg-gray-800/60 cursor-pointer group transition-all">
            <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${STATUS_DOT[alert.status as keyof typeof STATUS_DOT] ?? "bg-gray-500"}`} />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-white truncate">{alert.title}</p>
              <div className="flex items-center gap-2 mt-1">
                <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${SEV_STYLES[alert.severity as keyof typeof SEV_STYLES]}`}>
                  {alert.severity.toUpperCase()}
                </span>
                <span className="text-[10px] text-gray-500">{alert.source}</span>
                <span className="text-[10px] text-gray-600">· {alert.time}</span>
              </div>
            </div>
            <ChevronRight size={14} className="text-gray-600 group-hover:text-gray-400 flex-shrink-0 mt-0.5" />
          </div>
        ))}
      </div>

      <div className="mt-4 pt-4 border-t border-gray-800">
        <div className="grid grid-cols-3 gap-2 text-center">
          <div>
            <p className="text-lg font-bold text-red-400">3</p>
            <p className="text-[10px] text-gray-500">Critical</p>
          </div>
          <div>
            <p className="text-lg font-bold text-amber-400">12</p>
            <p className="text-[10px] text-gray-500">High</p>
          </div>
          <div>
            <p className="text-lg font-bold text-emerald-400">73%</p>
            <p className="text-[10px] text-gray-500">Auto-resolved</p>
          </div>
        </div>
      </div>
    </div>
  );
}
