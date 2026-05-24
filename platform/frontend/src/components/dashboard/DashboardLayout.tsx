"use client";
import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert, Brain, Globe, Eye, TrendingUp, Zap, Settings,
  LayoutDashboard, Bell, Search, ChevronLeft, ChevronRight,
  CreditCard, Users, Activity, Database, Lock, FileText
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/intelligence", label: "Intelligence", icon: Brain },
  { href: "/soc", label: "AI SOC", icon: ShieldAlert },
  { href: "/agentshield", label: "AgentShield", icon: Lock },
  { href: "/surfacewatch", label: "SurfaceWatch", icon: Globe },
  { href: "/exec-risk", label: "Executive Risk", icon: TrendingUp },
  { href: "/exchange", label: "Intel Exchange", icon: Database },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/billing", label: "Billing", icon: CreditCard },
  { href: "/settings", label: "Settings", icon: Settings },
];

interface DashboardLayoutProps { children: React.ReactNode; }

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const [collapsed, setCollapsed] = useState(false);
  const pathname = usePathname();

  return (
    <div className="min-h-screen flex bg-gray-950">
      {/* Sidebar */}
      <aside className={`${collapsed ? "w-16" : "w-64"} flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-300`}>
        {/* Logo */}
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          {!collapsed && (
            <div>
              <span className="text-sm font-bold text-cyan-400">SENTINEL APEX</span>
              <span className="block text-xs text-gray-500">CYBERDUDEBIVASH®</span>
            </div>
          )}
          <button onClick={() => setCollapsed(!collapsed)} className="p-1.5 rounded-lg hover:bg-gray-800 text-gray-400">
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = pathname === href;
            return (
              <Link key={href} href={href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all
                  ${active ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20" : "text-gray-400 hover:bg-gray-800 hover:text-gray-100"}`}>
                <Icon size={18} className={active ? "text-cyan-400" : ""} />
                {!collapsed && <span>{label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Tier Badge */}
        {!collapsed && (
          <div className="p-4 border-t border-gray-800">
            <div className="px-3 py-2 rounded-lg bg-violet-500/10 border border-violet-500/20">
              <span className="text-xs font-semibold text-violet-400">ENTERPRISE TIER</span>
              <p className="text-xs text-gray-500 mt-0.5">Unlimited API • AI SOC • All Modules</p>
            </div>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="h-14 bg-gray-900/80 border-b border-gray-800 flex items-center px-6 gap-4 backdrop-blur sticky top-0 z-40">
          <div className="flex-1 relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input type="text" placeholder="Search threats, IOCs, advisories..."
              className="w-full max-w-md bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
          </div>
          <button className="relative p-2 rounded-lg hover:bg-gray-800 text-gray-400">
            <Bell size={18} />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
              <span className="text-xs font-bold text-cyan-400">CDB</span>
            </div>
            <span className="text-sm text-gray-300">CYBERDUDEBIVASH</span>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6">{children}</div>
      </main>
    </div>
  );
}
