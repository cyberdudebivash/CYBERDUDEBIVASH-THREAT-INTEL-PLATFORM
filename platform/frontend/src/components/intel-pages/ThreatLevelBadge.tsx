import type { ThreatLevel } from "@/lib/intel-data";

const STYLES: Record<ThreatLevel, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-green-500/15 text-green-400 border-green-500/30",
};

export function ThreatLevelBadge({ level }: { level: ThreatLevel }) {
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${STYLES[level]}`}>
      {level}
    </span>
  );
}
