"use client";
import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { ThreatOverview } from "@/components/dashboard/ThreatOverview";
import { AlertFeed } from "@/components/dashboard/AlertFeed";
import { ThreatGlobe } from "@/components/dashboard/ThreatGlobe";
import { IntelFeed } from "@/components/intel/IntelFeed";
import { MetricCard } from "@/components/ui/MetricCard";
import { useAuthStore } from "@/store/authStore";

const PLATFORM_METRICS = [
  { label: "Active IOCs", value: "2.4M", trend: "+12%", status: "warning" },
  { label: "Threats Blocked (24h)", value: "47,832", trend: "+8%", status: "success" },
  { label: "AI Analyses Run", value: "284K", trend: "+23%", status: "info" },
  { label: "Avg Triage Time", value: "0.3h", trend: "-18%", status: "success" },
  { label: "Critical Alerts", value: "3", trend: "0%", status: "danger" },
  { label: "Platform Uptime", value: "99.99%", trend: "", status: "success" },
];

export default function HomePage() {
  const { user, tier } = useAuthStore();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gradient">SENTINEL APEX</h1>
            <p className="text-gray-400 mt-1">AI-Native Cyber Intelligence Platform — {tier?.toUpperCase() ?? "ENTERPRISE"} TIER</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              ● LIVE
            </span>
            <span className="text-xs text-gray-500">v161.4 | {new Date().toUTCString()}</span>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        {PLATFORM_METRICS.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-6">
        {/* Threat Globe + Overview */}
        <div className="col-span-12 lg:col-span-8">
          <ThreatOverview />
        </div>
        <div className="col-span-12 lg:col-span-4">
          <AlertFeed />
        </div>

        {/* Intel Feed */}
        <div className="col-span-12">
          <IntelFeed />
        </div>
      </div>
    </DashboardLayout>
  );
}
