import type { Metadata } from "next";
import Link from "next/link";
import { IntelPageLayout } from "@/components/intel-pages/IntelPageLayout";

export const metadata: Metadata = {
  title: "Threat Intelligence Blog — Research & Analysis",
  description:
    "CYBERDUDEBIVASH® SENTINEL APEX threat intelligence blog — in-depth CVE research, APT campaign analysis, ransomware reports, ICS/OT advisories, and malware reverse-engineering by Bivash Kumar Nayak.",
  keywords: [
    "threat intelligence blog", "cybersecurity research", "CVE analysis", "APT report",
    "ransomware research", "ICS OT advisory", "malware analysis", "SENTINEL APEX blog",
    "CyberDudeBivash", "Bivash Kumar Nayak", "cybersecurity India",
  ],
  alternates: { canonical: "https://intel.cyberdudebivash.com/blog" },
  openGraph: {
    title: "Threat Intelligence Blog | CYBERDUDEBIVASH® SENTINEL APEX",
    description: "In-depth threat intel research — CVE analysis, APT campaigns, ransomware, ICS/OT advisories.",
    url: "https://intel.cyberdudebivash.com/blog",
  },
};

interface BlogPost {
  slug: string;
  title: string;
  date: string;
  category: string;
  excerpt: string;
  externalPath: string;
  tags: string[];
}

const BLOG_POSTS: BlogPost[] = [
  {
    slug: "ivanti-epmm-cve-2026-6973-rce",
    title: "Ivanti EPMM CVE-2026-6973: RCE Under Active Exploitation Grants Admin-Level Access",
    date: "2026-05-20",
    category: "CVE Analysis",
    excerpt:
      "Critical unauthenticated remote code execution vulnerability in Ivanti Endpoint Manager Mobile (EPMM) actively exploited in the wild. The flaw grants attackers admin-level access to MDM infrastructure managing thousands of enterprise mobile devices.",
    externalPath: "/blog/2026/05/ivanti-epmm-cve-2026-6973-rce-under-active-exploitation-grants-admin-level-acces.html",
    tags: ["CVE-2026-6973", "Ivanti", "EPMM", "RCE", "MDM", "zero-day"],
  },
  {
    slug: "oceanlotus-pypi-zichatbot-malware",
    title: "OceanLotus Suspected of Using PyPI to Deliver ZiChatBot Malware",
    date: "2026-05-18",
    category: "APT Intelligence",
    excerpt:
      "APT32 (OceanLotus), a Vietnamese state-sponsored threat group, is suspected of publishing malicious Python packages to PyPI that deliver the ZiChatBot information-stealer. The campaign targets developers and organizations in Southeast Asia.",
    externalPath: "/blog/2026/05/oceanlotus-suspected-of-using-pypi-to-deliver-zichatbot-malware.html",
    tags: ["OceanLotus", "APT32", "PyPI", "supply-chain", "Python", "malware"],
  },
  {
    slug: "official-jdownloader-site-served-malware",
    title: "Official JDownloader Site Served Malware to Windows and Linux Users",
    date: "2026-05-15",
    category: "Supply Chain",
    excerpt:
      "The official JDownloader download portal was compromised between May 2026 dates to serve trojanized installers embedding information-stealing malware to both Windows and Linux users — a significant supply-chain incident affecting millions of potential downloads.",
    externalPath: "/blog/2026/05/official-jdownloader-site-served-malware-to-windows-and-linux-users-between-may-.html",
    tags: ["JDownloader", "supply-chain", "trojanized-installer", "info-stealer"],
  },
  {
    slug: "hackers-plugx-dll-sideloading-fake-claude-malware",
    title: "Hackers Use PlugX-Like DLL Sideloading Chain in Fake Claude Malware Campaign",
    date: "2026-05-12",
    category: "Malware Analysis",
    excerpt:
      "A new malware campaign distributes trojanized Anthropic Claude AI applications bundled with a PlugX-variant RAT using DLL sideloading. The sophisticated multi-stage chain achieves persistence and espionage capabilities on victim systems.",
    externalPath: "/blog/2026/05/hackers-use-plugx-like-dll-sideloading-chain-in-fake-claude-malware-campaign.html",
    tags: ["PlugX", "DLL-sideloading", "Claude", "AI-lure", "RAT", "China"],
  },
  {
    slug: "may-2026-threat-intelligence-report",
    title: "11th May 2026 Threat Intelligence Situation Report",
    date: "2026-05-11",
    category: "Weekly Report",
    excerpt:
      "SENTINEL APEX weekly threat intelligence situation report for May 11, 2026. Covers active ransomware campaigns, newly published KEV entries, critical CVEs, APT activity observed globally, and recommended defensive mitigations.",
    externalPath: "/blog/2026/05/11th-may-threat-intelligence-report.html",
    tags: ["weekly-report", "situational-awareness", "SITREP", "ransomware", "CVE", "APT"],
  },
  {
    slug: "hackers-weaponized-jpeg-trojanized-screenconnect",
    title: "Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware",
    date: "2026-05-09",
    category: "Malware Analysis",
    excerpt:
      "A sophisticated campaign weaponizes JPEG image files embedded with malicious code to deploy trojanized ScreenConnect remote access software. The attack chain exploits image file processing to bypass security controls and establish persistent remote access.",
    externalPath: "/blog/2026/05/hackers-use-weaponized-jpeg-file-to-deploy-trojanized-screenconnect-malware.html",
    tags: ["ScreenConnect", "JPEG", "steganography", "RAT", "RMM-abuse"],
  },
  {
    slug: "hackers-fake-deepseek-github-malware",
    title: "Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware",
    date: "2026-05-07",
    category: "Threat Campaign",
    excerpt:
      "Threat actors have created convincing fake GitHub repositories impersonating DeepSeek AI terminal-UI (TUI) tools to deliver information-stealing malware. The campaign exploits developer interest in AI tooling to compromise developer workstations.",
    externalPath: "/blog/2026/05/hackers-use-fake-deepseek-tui-github-repositories-to-deliver-malware.html",
    tags: ["DeepSeek", "GitHub", "fake-repo", "info-stealer", "developer-targeting", "AI-lure"],
  },
  {
    slug: "new-cpanel-vulnerabilities-file-access-rce",
    title: "New cPanel Vulnerabilities Could Allow File Access and Remote Code Execution",
    date: "2026-05-05",
    category: "CVE Analysis",
    excerpt:
      "Newly disclosed security vulnerabilities in cPanel & WHM could allow authenticated and unauthenticated attackers to access arbitrary files and execute remote code. Millions of hosting accounts may be impacted across shared hosting providers.",
    externalPath: "/blog/2026/05/new-cpanel-vulnerabilities-could-allow-file-access-and-remote-code-execution.html",
    tags: ["cPanel", "WHM", "RCE", "file-disclosure", "web-hosting", "CVE"],
  },
  {
    slug: "hitachi-energy-pcm600-advisory",
    title: "Hitachi Energy PCM600 ICS Advisory — Critical Vulnerabilities in Power Control",
    date: "2026-05-02",
    category: "ICS/OT Advisory",
    excerpt:
      "SENTINEL APEX analysis of critical vulnerabilities in Hitachi Energy PCM600 power control and management software used in electrical substations and grid infrastructure. Exploitation could enable unauthorized control of protection relay configurations.",
    externalPath: "/blog/2026/05/hitachi-energy-pcm600.html",
    tags: ["ICS", "OT", "Hitachi", "PCM600", "SCADA", "power-grid", "energy"],
  },
  {
    slug: "abb-edgenius-management-portal-advisory",
    title: "ABB Edgenius Management Portal — ICS Security Advisory",
    date: "2026-04-28",
    category: "ICS/OT Advisory",
    excerpt:
      "Security advisory covering vulnerabilities in the ABB Edgenius industrial management portal. The platform manages edge computing and IoT devices in critical infrastructure environments including manufacturing, energy, and utilities.",
    externalPath: "/blog/2026/04/abb-edgenius-management-portal.html",
    tags: ["ABB", "Edgenius", "ICS", "OT", "edge-computing", "manufacturing"],
  },
  {
    slug: "cve-2025-68670-xrdp-rce",
    title: "CVE-2025-68670: Discovering an RCE Vulnerability in xRDP",
    date: "2026-05-01",
    category: "CVE Analysis",
    excerpt:
      "In-depth technical analysis of CVE-2025-68670, a critical remote code execution vulnerability discovered in xRDP — the open-source RDP server for Linux. The flaw enables unauthenticated pre-authentication code execution on exposed Linux systems.",
    externalPath: "/blog/2026/05/cve-2025-68670-discovering-an-rce-vulnerability-in-xrdp.html",
    tags: ["CVE-2025-68670", "xRDP", "RCE", "Linux", "pre-auth", "remote-desktop"],
  },
];

const CATEGORY_COLORS: Record<string, string> = {
  "CVE Analysis": "bg-red-500/10 text-red-400 border-red-500/20",
  "APT Intelligence": "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  "Supply Chain": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "Malware Analysis": "bg-purple-500/10 text-purple-400 border-purple-500/20",
  "Weekly Report": "bg-blue-500/10 text-blue-400 border-blue-500/20",
  "Threat Campaign": "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  "ICS/OT Advisory": "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
};

const blogListSchema = {
  "@context": "https://schema.org",
  "@type": "Blog",
  "name": "CYBERDUDEBIVASH® SENTINEL APEX Threat Intelligence Blog",
  "description": "In-depth threat intelligence research including CVE analysis, APT campaigns, ransomware, ICS/OT advisories, and malware reverse-engineering.",
  "url": "https://intel.cyberdudebivash.com/blog",
  "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
  "blogPost": BLOG_POSTS.map((p) => ({
    "@type": "BlogPosting",
    "headline": p.title,
    "description": p.excerpt,
    "url": `https://intel.cyberdudebivash.com${p.externalPath}`,
    "datePublished": p.date,
    "author": { "@type": "Organization", "name": "CYBERDUDEBIVASH PRIVATE LIMITED" },
    "keywords": p.tags.join(", "),
  })),
};

export default function BlogPage() {
  const sorted = [...BLOG_POSTS].sort((a, b) => b.date.localeCompare(a.date));

  return (
    <IntelPageLayout breadcrumbs={[{ label: "Blog" }]}>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(blogListSchema) }}
      />

      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          THREAT INTELLIGENCE RESEARCH
        </div>
        <h1 className="text-4xl font-bold text-white mb-3">
          Intel Blog
        </h1>
        <p className="text-gray-400 text-lg max-w-3xl leading-relaxed">
          In-depth research, CVE analysis, APT campaign intelligence, and ICS/OT advisories
          from the CYBERDUDEBIVASH® SENTINEL APEX research team — published as TLP:GREEN for
          the global security community.
        </p>
      </div>

      {/* Blog grid */}
      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-5">
        {sorted.map((post) => {
          const categoryStyle = CATEGORY_COLORS[post.category] ?? "bg-gray-800 text-gray-400 border-gray-700";
          return (
            <article
              key={post.slug}
              className="bg-gray-900/40 border border-gray-800 rounded-xl overflow-hidden hover:border-gray-700 transition-colors flex flex-col"
            >
              <div className="p-5 flex flex-col flex-1">
                <div className="flex items-center justify-between mb-3">
                  <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium border ${categoryStyle}`}>
                    {post.category}
                  </span>
                  <time className="text-xs text-gray-600">{post.date}</time>
                </div>
                <h2 className="text-base font-semibold text-gray-100 leading-snug mb-2 hover:text-cyan-300 transition-colors">
                  <a href={post.externalPath}>{post.title}</a>
                </h2>
                <p className="text-sm text-gray-500 leading-relaxed flex-1">{post.excerpt}</p>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {post.tags.slice(0, 4).map((tag) => (
                    <span
                      key={tag}
                      className="px-1.5 py-0.5 rounded text-xs bg-gray-800 text-gray-500 border border-gray-700/50"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
                <a
                  href={post.externalPath}
                  className="mt-4 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  Read Analysis →
                </a>
              </div>
            </article>
          );
        })}
      </div>

      {/* Categories legend */}
      <div className="mt-12 bg-gray-900/40 border border-gray-800 rounded-xl p-6">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Research Categories</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(CATEGORY_COLORS).map(([cat, style]) => (
            <div key={cat} className={`px-3 py-2 rounded-lg border text-xs font-medium text-center ${style}`}>
              {cat}
            </div>
          ))}
        </div>
      </div>
    </IntelPageLayout>
  );
}
