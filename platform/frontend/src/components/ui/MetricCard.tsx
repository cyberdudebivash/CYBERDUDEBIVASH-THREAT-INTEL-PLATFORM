"use client";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string;
  trend?: string;
  status?: "success" | "warning" | "danger" | "info";
}

const STATUS_STYLES = {
  success: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  warning: "text-amber-400 border-amber-500/20 bg-amber-500/5",
  danger: "text-red-400 border-red-500/20 bg-red-500/5",
  info: "text-cyan-400 border-cyan-500/20 bg-cyan-500/5",
};

export function MetricCard({ label, value, trend, status = "info" }: MetricCardProps) {
  const trendUp = trend?.startsWith("+");
  const trendDown = trend?.startsWith("-");

  return (
    <div className={`rounded-xl border p-4 ${STATUS_STYLES[status]}`}>
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-xl font-bold text-white">{value}</p>
      {trend && (
        <div className="flex items-center gap-1 mt-1">
          {trendUp ? <TrendingUp size={12} className="text-emerald-400" /> :
           trendDown ? <TrendingDown size={12} className="text-red-400" /> :
           <Minus size={12} className="text-gray-500" />}
          <span className={`text-xs ${trendUp ? "text-emerald-400" : trendDown ? "text-red-400" : "text-gray-500"}`}>{trend}</span>
        </div>
      )}
    </div>
  );
}
