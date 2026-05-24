"use client";
import { useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";

const THREAT_TIMELINE = [
  { time: "00:00", critical: 2, high: 8, medium: 24, blocked: 47 },
  { time: "04:00", critical: 1, high: 12, medium: 31, blocked: 62 },
  { time: "08:00", critical: 4, high: 19, medium: 45, blocked: 89 },
  { time: "12:00", critical: 7, high: 28, medium: 67, blocked: 142 },
  { time: "16:00", critical: 3, high: 22, medium: 58, blocked: 118 },
  { time: "20:00", critical: 5, high: 31, medium: 72, blocked: 167 },
  { time: "Now", critical: 3, high: 27, medium: 61, blocked: 134 },
];

const TOP_ACTORS = [
  { name: "APT29 (Cozy Bear)", count: 847, nation: "RU", severity: "critical" },
  { name: "APT41 (Double Dragon)", count: 634, nation: "CN", severity: "critical" },
  { name: "LockBit 3.0", count: 523, nation: "unk", severity: "high" },
  { name: "Lazarus Group", count: 412, nation: "KP", severity: "high" },
  { name: "Volt Typhoon", count: 389, nation: "CN", severity: "critical" },
];

export function ThreatOverview() {
  const [view, setView] = useState<"timeline" | "actors">("timeline");

  return (
    <div className="surface-card rounded-xl p-6 h-full">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-white">Threat Activity Overview</h2>
        <div className="flex gap-2">
          {(["timeline", "actors"] as const).map((v) => (
            <button key={v} onClick={() => setView(v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all
                ${view === v ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30" : "text-gray-500 hover:text-gray-300"}`}>
              {v === "timeline" ? "24h Timeline" : "Top Actors"}
            </button>
          ))}
        </div>
      </div>

      {view === "timeline" ? (
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={THREAT_TIMELINE}>
            <defs>
              <linearGradient id="critical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blocked" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="time" stroke="#6b7280" tick={{ fontSize: 11 }} />
            <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#111827", border: "1px solid #1f2937", borderRadius: "8px" }} />
            <Area type="monotone" dataKey="blocked" stroke="#00d4ff" fill="url(#blocked)" strokeWidth={2} name="Blocked" />
            <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critical)" strokeWidth={2} name="Critical" />
          </AreaChart>
        </ResponsiveContainer>
      ) : (
        <div className="space-y-3">
          {TOP_ACTORS.map((actor, i) => (
            <div key={actor.name} className="flex items-center gap-4 p-3 rounded-lg bg-gray-800/50">
              <span className="text-xs text-gray-500 w-4">{i + 1}</span>
              <div className="flex-1">
                <p className="text-sm font-medium text-white">{actor.name}</p>
                <p className="text-xs text-gray-500">{actor.nation} · {actor.count} detections</p>
              </div>
              <span className={`px-2 py-0.5 rounded text-xs font-medium
                ${actor.severity === "critical" ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400"}`}>
                {actor.severity}
              </span>
              <div className="w-24 bg-gray-700 rounded-full h-1.5">
                <div className={`h-1.5 rounded-full ${actor.severity === "critical" ? "bg-red-500" : "bg-amber-500"}`}
                  style={{ width: `${(actor.count / 847) * 100}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
