import Link from "next/link";
import type { ReactNode } from "react";
import { MobileNav } from "./MobileNav";

interface Crumb {
  label: string;
  href?: string;
}

interface IntelPageLayoutProps {
  children: ReactNode;
  breadcrumbs?: Crumb[];
}

export function IntelPageLayout({ children, breadcrumbs }: IntelPageLayoutProps) {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Top nav */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-sm font-bold text-cyan-400 tracking-wider">SENTINEL APEX</span>
            <span className="text-xs text-gray-500">by CYBERDUDEBIVASH®</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6 text-sm">
            <Link href="/threat-actors" className="text-gray-400 hover:text-gray-100 transition-colors">Threat Actors</Link>
            <Link href="/ransomware" className="text-gray-400 hover:text-gray-100 transition-colors">Ransomware</Link>
            <Link href="/cves" className="text-gray-400 hover:text-gray-100 transition-colors">CVE Intel</Link>
            <Link href="/iocs" className="text-gray-400 hover:text-gray-100 transition-colors">IOC Feed</Link>
            <Link href="/blog" className="text-gray-400 hover:text-gray-100 transition-colors">Blog</Link>
            <Link href="/playground" className="text-gray-400 hover:text-gray-100 transition-colors">Playground</Link>
            <Link href="/partners" className="text-gray-400 hover:text-gray-100 transition-colors">Partners</Link>
            <Link
              href="/"
              className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold hover:bg-cyan-500/20 transition-colors"
            >
              Launch Platform
            </Link>
          </nav>
          <MobileNav />
        </div>
      </header>

      {/* Breadcrumbs */}
      {breadcrumbs && breadcrumbs.length > 0 && (
        <div className="border-b border-gray-800/50 bg-gray-900/40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-10 flex items-center gap-2 text-xs text-gray-500">
            <Link href="/" className="hover:text-gray-300 transition-colors">Home</Link>
            {breadcrumbs.map((crumb, i) => (
              <span key={i} className="flex items-center gap-2">
                <span>/</span>
                {crumb.href ? (
                  <Link href={crumb.href} className="hover:text-gray-300 transition-colors">{crumb.label}</Link>
                ) : (
                  <span className="text-gray-300">{crumb.label}</span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Main */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">{children}</main>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-900/40 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-sm">
            <div>
              <p className="text-xs font-semibold text-cyan-400 mb-3 uppercase tracking-wider">Intelligence</p>
              <ul className="space-y-1.5">
                <li><Link href="/threat-actors" className="text-gray-500 hover:text-gray-300">Threat Actors</Link></li>
                <li><Link href="/ransomware" className="text-gray-500 hover:text-gray-300">Ransomware Groups</Link></li>
                <li><Link href="/cves" className="text-gray-500 hover:text-gray-300">CVE Intelligence</Link></li>
                <li><Link href="/iocs" className="text-gray-500 hover:text-gray-300">IOC Feed</Link></li>
                <li><Link href="/blog" className="text-gray-500 hover:text-gray-300">Intel Blog</Link></li>
                <li><Link href="/playground" className="text-gray-500 hover:text-gray-300">Free Playground</Link></li>
                <li><Link href="/threats.html" className="text-gray-500 hover:text-gray-300">Threat Hub</Link></li>
              </ul>
            </div>
            <div>
              <p className="text-xs font-semibold text-cyan-400 mb-3 uppercase tracking-wider">Platform</p>
              <ul className="space-y-1.5">
                <li><Link href="/iocs.html" className="text-gray-500 hover:text-gray-300">IOC Feeds</Link></li>
                <li><Link href="/kev.html" className="text-gray-500 hover:text-gray-300">CISA KEV</Link></li>
                <li><Link href="/advisories.html" className="text-gray-500 hover:text-gray-300">Advisories</Link></li>
                <li><Link href="/vulnerabilities.html" className="text-gray-500 hover:text-gray-300">Vulnerabilities</Link></li>
                <li><Link href="/partners" className="text-gray-500 hover:text-gray-300">Partner Program</Link></li>
                <li><Link href="/changelog" className="text-gray-500 hover:text-gray-300">Changelog</Link></li>
                <li><Link href="/newsletter" className="text-gray-500 hover:text-gray-300">Newsletter</Link></li>
              </ul>
            </div>
            <div>
              <p className="text-xs font-semibold text-cyan-400 mb-3 uppercase tracking-wider">About</p>
              <ul className="space-y-1.5">
                <li><Link href="/about.html" className="text-gray-500 hover:text-gray-300">About</Link></li>
                <li><Link href="/methodology.html" className="text-gray-500 hover:text-gray-300">Methodology</Link></li>
                <li><Link href="/editorial-policy.html" className="text-gray-500 hover:text-gray-300">Editorial Policy</Link></li>
              </ul>
            </div>
            <div>
              <p className="text-xs font-semibold text-cyan-400 mb-3 uppercase tracking-wider">CYBERDUDEBIVASH®</p>
              <p className="text-gray-600 text-xs leading-relaxed">
                AI-native threat intelligence platform. Real-time CVE, IOC, and APT intelligence.
                Founded by Bivash Kumar Nayak, Jajpur Road, Odisha, India.
              </p>
            </div>
          </div>
          <div className="mt-8 pt-6 border-t border-gray-800 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-gray-600">
            <p>© 2026 CYBERDUDEBIVASH PRIVATE LIMITED. All rights reserved.</p>
            <p>Intelligence data is TLP:GREEN unless otherwise marked.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
