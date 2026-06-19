"use client";
import { useState } from "react";
import Link from "next/link";

const NAV_LINKS = [
  { href: "/threat-actors", label: "Threat Actors" },
  { href: "/ransomware", label: "Ransomware" },
  { href: "/cves", label: "CVE Intel" },
  { href: "/iocs", label: "IOC Feed" },
  { href: "/blog", label: "Blog" },
  { href: "/playground", label: "Free Playground" },
  { href: "/partners", label: "Partners" },
  { href: "/threats.html", label: "Threat Hub" },
];

export function MobileNav() {
  const [open, setOpen] = useState(false);

  return (
    <div className="md:hidden">
      <button
        onClick={() => setOpen(!open)}
        className="p-2 rounded-lg text-gray-400 hover:text-gray-100 hover:bg-gray-800 transition-colors"
        aria-label="Toggle navigation"
        aria-expanded={open}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          {open ? (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          )}
        </svg>
      </button>

      {open && (
        <div className="absolute top-14 left-0 right-0 bg-gray-900 border-b border-gray-800 z-50 shadow-xl">
          <nav className="max-w-7xl mx-auto px-4 py-3 flex flex-col gap-1">
            {NAV_LINKS.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className="px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-800 transition-colors"
              >
                {label}
              </Link>
            ))}
            <Link
              href="/"
              onClick={() => setOpen(false)}
              className="mt-1 px-3 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm font-semibold hover:bg-cyan-500/20 transition-colors"
            >
              Launch Platform
            </Link>
          </nav>
        </div>
      )}
    </div>
  );
}
