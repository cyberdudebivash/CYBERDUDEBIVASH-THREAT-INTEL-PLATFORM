import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "404 — Intelligence Resource Not Found",
  description: "The threat intelligence resource you requested was not found on CYBERDUDEBIVASH® SENTINEL APEX.",
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col items-center justify-center px-4">
      {/* Glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative text-center max-w-lg">
        {/* Brand */}
        <Link href="/" className="inline-flex items-center gap-2 mb-8">
          <span className="text-sm font-bold text-cyan-400 tracking-wider">SENTINEL APEX</span>
          <span className="text-xs text-gray-500">by CYBERDUDEBIVASH®</span>
        </Link>

        {/* 404 */}
        <div className="mb-6">
          <p className="text-8xl font-black text-gray-800 select-none">404</p>
          <div className="-mt-4">
            <span className="inline-flex px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold">
              INTEL RESOURCE NOT FOUND
            </span>
          </div>
        </div>

        <h1 className="text-2xl font-bold text-white mb-3">
          Resource Not Found
        </h1>
        <p className="text-gray-400 text-sm leading-relaxed mb-8">
          The threat intelligence resource, IOC, or platform page you requested
          does not exist or has been removed from the active feed. Use the
          navigation below to return to the platform.
        </p>

        {/* Quick links */}
        <div className="grid grid-cols-2 gap-3 mb-8">
          {[
            { href: "/threat-actors", label: "Threat Actors" },
            { href: "/ransomware", label: "Ransomware Groups" },
            { href: "/cves", label: "CVE Intelligence" },
            { href: "/iocs", label: "IOC Feed" },
          ].map(({ href, label }) => (
            <Link
              key={href}
              href={href}
              className="px-4 py-2.5 rounded-lg bg-gray-900/60 border border-gray-800 text-sm text-gray-300 hover:text-white hover:border-gray-700 transition-colors"
            >
              {label}
            </Link>
          ))}
        </div>

        <Link
          href="/"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm font-semibold hover:bg-cyan-500/20 transition-colors"
        >
          ← Return to Dashboard
        </Link>

        <p className="mt-8 text-xs text-gray-600">
          © 2026 CYBERDUDEBIVASH PRIVATE LIMITED · TLP:GREEN
        </p>
      </div>
    </div>
  );
}
