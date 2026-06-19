import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "MSSP & Reseller Partner Program — SENTINEL APEX Threat Intelligence | CYBERDUDEBIVASH",
  description:
    "Join the SENTINEL APEX partner ecosystem. MSSP, VAR, and reseller programs with white-label options, volume licensing, and dedicated technical support. Built for managed security service providers.",
  keywords: [
    "MSSP threat intelligence partner", "threat intel reseller", "SENTINEL APEX partner program",
    "CYBERDUDEBIVASH partner", "managed security threat intel", "white-label threat intelligence",
    "threat intel MSSP program", "security reseller program", "MDR threat intelligence",
    "SOC-as-a-service threat intel", "threat intel partner India", "channel partner cybersecurity",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/partners" },
  openGraph: {
    title: "MSSP & Partner Program — SENTINEL APEX Threat Intelligence",
    description: "White-label threat intelligence for MSSPs. Volume licensing, technical support, and partner portal.",
    url: "https://intel.cyberdudebivash.com/partners",
  },
};

const schema = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  "name": "SENTINEL APEX MSSP & Partner Program",
  "description": "Partner program for MSSPs, VARs, and resellers to deliver SENTINEL APEX threat intelligence to their customers.",
  "url": "https://intel.cyberdudebivash.com/partners",
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
};

const PARTNER_TIERS = [
  {
    name: "Referral Partner",
    icon: "🤝",
    commission: "15% recurring",
    minCustomers: "None",
    whiteLabel: false,
    portal: false,
    support: "Self-serve",
    highlights: [
      "Unique referral link",
      "15% recurring commission",
      "Co-marketing materials",
      "Partner badge",
    ],
    cta: "Apply Now",
    ctaHref: "/contact.html",
  },
  {
    name: "MSSP Partner",
    icon: "🏢",
    commission: "25% recurring + volume discounts",
    minCustomers: "3+ managed customers",
    whiteLabel: true,
    portal: true,
    support: "Priority email + Slack",
    highlights: [
      "Multi-tenant customer management",
      "White-label API endpoints",
      "25% recurring + volume pricing",
      "Partner success manager",
      "Joint go-to-market support",
      "Early access to new features",
    ],
    cta: "Apply for MSSP Tier",
    ctaHref: "/contact.html",
    featured: true,
  },
  {
    name: "Strategic Alliance",
    icon: "🌐",
    commission: "Custom terms",
    minCustomers: "10+ or $100K+ ARR",
    whiteLabel: true,
    portal: true,
    support: "Dedicated CSM + SLA",
    highlights: [
      "Custom SLA and pricing",
      "OEM / white-label platform",
      "Co-branded integrations",
      "Joint product roadmap input",
      "Executive sponsorship",
      "Revenue sharing model",
    ],
    cta: "Contact Partnership Team",
    ctaHref: "/contact.html",
  },
];

const MSSP_CAPABILITIES = [
  {
    icon: "🏗️",
    title: "Multi-Tenant Architecture",
    desc: "Manage threat intelligence for dozens of customers from a single pane. Isolated customer environments with per-customer API keys and reporting.",
  },
  {
    icon: "🎨",
    title: "White-Label API",
    desc: "Serve intelligence under your own brand. Custom API endpoints, branded exports, and co-branded reports that reinforce your MSSP's value.",
  },
  {
    icon: "📈",
    title: "Volume Licensing",
    desc: "Per-customer or per-seat licensing models that make it margin-positive at any scale. Starts at 3 customers, no upper limit.",
  },
  {
    icon: "📊",
    title: "Customer Reporting",
    desc: "Automated weekly threat digests and monthly intelligence reports for your customers. Branded PDF exports ready to deliver.",
  },
  {
    icon: "🔌",
    title: "SIEM Integration Support",
    desc: "Technical pre-sales support for customer SIEM integrations — Splunk, Sentinel, Elastic, QRadar. We help you win deals.",
  },
  {
    icon: "⚡",
    title: "Priority Support",
    desc: "Dedicated Slack channel with 4-hour SLA for MSSP partners. Escalation path to engineering for customer-critical issues.",
  },
];

const IDEAL_PARTNERS = [
  "Managed Detection & Response (MDR) providers",
  "Managed Security Service Providers (MSSPs)",
  "Security Operations Center as a Service (SOCaaS)",
  "Value-Added Resellers (VARs) with security practices",
  "Incident Response firms",
  "Cybersecurity consulting practices",
  "Regional telcos with security divisions",
  "System integrators (SIs) with enterprise customers",
];

const PROCESS = [
  { step: "01", title: "Apply", desc: "Submit partner application. We review within 2 business days." },
  { step: "02", title: "Onboard", desc: "Partner portal access, API credentials, and training session." },
  { step: "03", title: "Integrate", desc: "Deploy threat intel into your SIEM stack or white-label API." },
  { step: "04", title: "Earn", desc: "Commission paid monthly. Volume discounts kick in at 3+ customers." },
];

export default function PartnersPage() {
  return (
    <IntelPageLayout breadcrumbs={[{ label: "Partners" }]}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />

      {/* Hero */}
      <div className="text-center max-w-4xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          MSSP · VAR · RESELLER · STRATEGIC ALLIANCE
        </div>
        <h1 className="text-5xl font-bold text-white mb-6 leading-tight">
          Partner with<br />
          <span className="text-emerald-400">SENTINEL APEX</span>
        </h1>
        <p className="text-xl text-gray-400 leading-relaxed mb-8">
          Deliver AI-native threat intelligence to your customers under your brand.
          White-label API, multi-tenant management, and margin-positive licensing for MSSPs,
          MDR providers, and security resellers.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/contact.html"
            className="px-8 py-3.5 rounded-xl bg-emerald-500 text-gray-950 font-bold text-sm hover:bg-emerald-400 transition-colors"
          >
            Apply to Partner Program →
          </Link>
          <Link
            href="/playground"
            className="px-8 py-3.5 rounded-xl bg-gray-800 border border-gray-700 text-gray-200 font-semibold text-sm hover:bg-gray-700 transition-colors"
          >
            See Platform Demo
          </Link>
        </div>
      </div>

      {/* Partner Tiers */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Partner Tiers</h2>
        <p className="text-gray-500 text-center mb-10">From referral commissions to full white-label OEM arrangements</p>
        <div className="grid md:grid-cols-3 gap-6">
          {PARTNER_TIERS.map((tier) => (
            <div key={tier.name} className={`bg-gray-900/40 border rounded-2xl p-6 flex flex-col ${
              tier.featured ? "border-emerald-500/50 shadow-lg shadow-emerald-500/10" : "border-gray-800"
            }`}>
              {tier.featured && (
                <p className="text-xs font-semibold text-emerald-400 mb-2">MOST POPULAR</p>
              )}
              <div className="flex items-center gap-3 mb-4">
                <span className="text-2xl">{tier.icon}</span>
                <p className="text-lg font-bold text-white">{tier.name}</p>
              </div>
              <div className="mb-5 space-y-1">
                <p className="text-xs text-gray-500">Commission: <span className="text-emerald-400 font-semibold">{tier.commission}</span></p>
                <p className="text-xs text-gray-500">Min customers: <span className="text-gray-300">{tier.minCustomers}</span></p>
                <p className="text-xs text-gray-500">Support: <span className="text-gray-300">{tier.support}</span></p>
              </div>
              <ul className="space-y-2 flex-1">
                {tier.highlights.map((h) => (
                  <li key={h} className="flex items-start gap-2 text-xs text-gray-400">
                    <span className="text-emerald-400 mt-0.5">✓</span>{h}
                  </li>
                ))}
              </ul>
              <Link
                href={tier.ctaHref}
                className={`mt-6 block text-center py-2.5 rounded-lg text-xs font-semibold transition-colors ${
                  tier.featured
                    ? "bg-emerald-500 text-gray-950 hover:bg-emerald-400"
                    : "bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700"
                }`}
              >
                {tier.cta}
              </Link>
            </div>
          ))}
        </div>
      </div>

      {/* MSSP Capabilities */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">Built for MSSP Delivery</h2>
        <p className="text-gray-500 text-center mb-10">Technical architecture designed for managed service providers</p>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {MSSP_CAPABILITIES.map((cap) => (
            <div key={cap.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              <p className="text-2xl mb-3">{cap.icon}</p>
              <h3 className="text-sm font-semibold text-white mb-2">{cap.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Ideal Partners */}
      <div className="mb-16 max-w-2xl mx-auto">
        <h2 className="text-2xl font-bold text-white text-center mb-8">Ideal Partner Types</h2>
        <div className="grid sm:grid-cols-2 gap-3">
          {IDEAL_PARTNERS.map((p) => (
            <div key={p} className="flex items-center gap-2 text-sm text-gray-400 bg-gray-900/40 border border-gray-800 rounded-lg px-4 py-3">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
              {p}
            </div>
          ))}
        </div>
      </div>

      {/* Process */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-8">How to Become a Partner</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-3xl mx-auto">
          {PROCESS.map((p) => (
            <div key={p.step} className="bg-gray-900/40 border border-gray-800 rounded-xl p-5 text-center">
              <p className="text-3xl font-bold text-gray-800 mb-2">{p.step}</p>
              <p className="text-sm font-semibold text-white mb-1">{p.title}</p>
              <p className="text-xs text-gray-500">{p.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="text-center bg-gradient-to-r from-emerald-500/10 via-gray-900/40 to-emerald-500/10 border border-emerald-500/20 rounded-2xl p-12">
        <h2 className="text-3xl font-bold text-white mb-4">Ready to Build a Threat Intel Practice?</h2>
        <p className="text-gray-400 mb-8 max-w-xl mx-auto">
          Join our partner ecosystem. Deliver enterprise-grade threat intelligence to your customers
          with our white-label API and multi-tenant platform.
        </p>
        <Link
          href="/contact.html"
          className="px-8 py-3.5 rounded-xl bg-emerald-500 text-gray-950 font-bold text-sm hover:bg-emerald-400 transition-colors"
        >
          Apply to Partner Program →
        </Link>
        <p className="text-xs text-gray-600 mt-4">Applications reviewed within 2 business days · iambivash.bn@gmail.com</p>
      </div>
    </IntelPageLayout>
  );
}
