"use client";
import { useState } from "react";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

const SAMPLE_TOPICS = [
  { icon: "🔴", title: "Critical CVEs", desc: "Top 5 newly disclosed vulnerabilities with CISA KEV status" },
  { icon: "🕵️", title: "APT Campaign Updates", desc: "Active nation-state campaigns tracked this week" },
  { icon: "💰", title: "Ransomware Tracker", desc: "New victims, negotiation intel, and group activity" },
  { icon: "🌐", title: "IOC Spotlight", desc: "High-confidence C2 infrastructure and malware hashes" },
  { icon: "🗺️", title: "MITRE ATT&CK Digest", desc: "TTP trends across observed threat campaigns" },
  { icon: "📦", title: "STIX Bundle", desc: "Machine-readable summary for SIEM ingestion (Pro subscribers)" },
];

const TESTIMONIALS = [
  {
    quote: "The weekly SENTINEL digest replaced three separate threat feeds for our team. One email, everything we need for our Monday morning SOC briefing.",
    role: "SOC Manager, Indian FinTech",
  },
  {
    quote: "MITRE ATT&CK mapping in the digest is a huge time saver. We go from intel to detection rule in under an hour.",
    role: "Detection Engineer, MSSP",
  },
  {
    quote: "The CVE section with KEV flags is the most useful thing in my inbox every week. Our patch prioritization is now data-driven.",
    role: "CISO, SaaS Company",
  },
];

export default function NewsletterPage() {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email) return;
    setLoading(true);
    // Simulate async subscription — replace with real API call
    setTimeout(() => {
      setLoading(false);
      setSubmitted(true);
    }, 800);
  }

  return (
    <IntelPageLayout breadcrumbs={[{ label: "Newsletter" }]}>
      {/* Hero */}
      <div className="text-center max-w-3xl mx-auto mb-12">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          EVERY FRIDAY — FREE — TLP:GREEN
        </div>
        <h1 className="text-4xl font-bold text-white mb-5">
          Weekly Threat Intelligence Digest
        </h1>
        <p className="text-lg text-gray-400 leading-relaxed">
          Top CVEs, active APT campaigns, ransomware tracker, and high-confidence IOC spotlight —
          delivered every Friday. Used by SOC analysts, CISOs, and incident responders across India and beyond.
        </p>
      </div>

      {/* Subscription Form */}
      <div className="max-w-lg mx-auto mb-16">
        {submitted ? (
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-10 text-center">
            <p className="text-4xl mb-4">✅</p>
            <h2 className="text-xl font-bold text-white mb-2">You&apos;re on the list!</h2>
            <p className="text-gray-400 text-sm">
              Welcome to the SENTINEL APEX weekly digest. Your first edition arrives this Friday.
              Check your spam folder if you don&apos;t see it.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="bg-gray-900/60 border border-gray-800 rounded-2xl p-8">
            <h2 className="text-lg font-bold text-white mb-6">Subscribe — Free</h2>
            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-xs text-gray-500 mb-1.5">Work Email *</label>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@company.com"
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>
              <div>
                <label htmlFor="role" className="block text-xs text-gray-500 mb-1.5">Your Role (optional)</label>
                <select
                  id="role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="">Select role…</option>
                  <option value="soc-analyst">SOC Analyst</option>
                  <option value="ir-engineer">Incident Responder</option>
                  <option value="ciso">CISO / Security Leader</option>
                  <option value="cti">CTI Analyst</option>
                  <option value="detection">Detection Engineer</option>
                  <option value="mssp">MSSP / MDR Provider</option>
                  <option value="student">Student / Researcher</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl bg-cyan-500 text-gray-950 font-bold text-sm hover:bg-cyan-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? "Subscribing…" : "Subscribe — It's Free →"}
              </button>
            </div>
            <p className="text-xs text-gray-600 mt-4 text-center">
              No spam. Unsubscribe anytime. TLP:GREEN data only.
            </p>
          </form>
        )}
      </div>

      {/* What&apos;s Inside */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-3">What&apos;s in Every Edition</h2>
        <p className="text-gray-500 text-center mb-10">Curated intelligence, not a news aggregator</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {SAMPLE_TOPICS.map((t) => (
            <div key={t.title} className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
              <p className="text-2xl mb-3">{t.icon}</p>
              <p className="text-sm font-semibold text-white mb-1">{t.title}</p>
              <p className="text-xs text-gray-500">{t.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Social Proof */}
      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white text-center mb-10">What Subscribers Say</h2>
        <div className="grid md:grid-cols-3 gap-6">
          {TESTIMONIALS.map((t) => (
            <div key={t.role} className="bg-gray-900/40 border border-gray-800 rounded-xl p-6">
              <p className="text-gray-400 text-sm leading-relaxed mb-4">&ldquo;{t.quote}&rdquo;</p>
              <p className="text-xs text-gray-600">— {t.role}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-16 max-w-2xl mx-auto text-center">
        {[
          { value: "Every Friday", label: "Delivery Schedule" },
          { value: "Free", label: "Forever on Basic Tier" },
          { value: "TLP:GREEN", label: "Classification" },
          { value: "<5 min", label: "Read Time" },
        ].map((s) => (
          <div key={s.label} className="bg-gray-900/40 border border-gray-800 rounded-xl p-4">
            <p className="text-sm font-bold text-cyan-400 mb-1">{s.value}</p>
            <p className="text-xs text-gray-600">{s.label}</p>
          </div>
        ))}
      </div>
    </IntelPageLayout>
  );
}
