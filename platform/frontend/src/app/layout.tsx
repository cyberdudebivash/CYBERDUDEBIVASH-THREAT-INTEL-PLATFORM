import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { QueryProvider } from "@/components/providers/QueryProvider";
import { AuthProvider } from "@/components/providers/AuthProvider";
import { TelemetryProvider } from "@/components/providers/TelemetryProvider";

const inter = Inter({ subsets: ["latin"] });

// PRODUCTION-TRUTH FIX (release hardening -- revenue mandate): was
// "https://intel.cyberdudebivash.com" -- the domain of this repo's existing,
// separately-hosted, already-live static site (confirmed via curl: that
// site's /cves is a different, non-Next.js page; /blog, /threat-actors/*,
// /playground -- all real routes in *this* app -- 404 there). Deploying
// this app's canonical URLs/OpenGraph/sitemap under that same domain would
// claim a domain it doesn't run on and collide with real, live, indexed
// paths. Points at the new subdomain this app is actually being deployed
// to; update here if that subdomain changes before going live.
const BASE_URL = "https://app.cyberdudebivash.com";

export const metadata: Metadata = {
  metadataBase: new URL(BASE_URL),
  title: {
    default: "CYBERDUDEBIVASH® SENTINEL APEX | AI-Native Threat Intelligence Platform",
    template: "%s | SENTINEL APEX — CYBERDUDEBIVASH",
  },
  description:
    "CYBERDUDEBIVASH® SENTINEL APEX — Enterprise AI-native cyber threat intelligence platform. Real-time CVE tracking, CISA KEV, STIX 2.1, MITRE ATT&CK mapping, IOC feeds, ransomware intelligence, and autonomous SOC. Founded by Bivash Kumar Nayak.",
  keywords: [
    "threat intelligence platform",
    "cybersecurity SaaS",
    "CTI feed",
    "IOC feed",
    "STIX 2.1",
    "TAXII 2.1",
    "MITRE ATT&CK",
    "CVE intelligence",
    "EPSS enrichment",
    "KEV tracking",
    "CISA KEV",
    "MISP export",
    "Sigma rules",
    "YARA rules",
    "SOC platform",
    "SIEM integration",
    "threat hunting",
    "zero-day detection",
    "ransomware intelligence",
    "APT tracking",
    "dark web monitoring",
    "threat actor profiles",
    "vulnerability intelligence",
    "AI cybersecurity",
    "autonomous SOC",
    "SENTINEL APEX",
    "CyberDudeBivash",
    "Bivash Kumar Nayak",
    "India cybersecurity",
    "enterprise security platform",
  ],
  authors: [{ name: "Bivash Kumar Nayak", url: "https://www.linkedin.com/in/bivash-kumar-nayak/" }],
  creator: "BIVASHA KUMAR NAYAK trading as CYBERDUDEBIVASH(R)",
  publisher: "BIVASHA KUMAR NAYAK trading as CYBERDUDEBIVASH(R)",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-snippet": -1,
      "max-image-preview": "large",
      "max-video-preview": -1,
    },
  },
  alternates: {
    canonical: BASE_URL,
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: BASE_URL,
    siteName: "CYBERDUDEBIVASH® SENTINEL APEX",
    title: "CYBERDUDEBIVASH® SENTINEL APEX | AI-Native Threat Intelligence Platform",
    description:
      "Enterprise AI-native cyber threat intelligence — real-time CVE tracking, CISA KEV, STIX 2.1, MITRE ATT&CK, IOC feeds, ransomware & APT intelligence. Free tier available.",
    images: [
      {
        url: `${BASE_URL}/assets/sentinel-apex-thumbnail.jpg`,
        width: 1200,
        height: 630,
        alt: "CYBERDUDEBIVASH SENTINEL APEX — AI-Powered Global Threat Intelligence Dashboard",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    site: "@CDBSENTINELAPEX",
    creator: "@CDBSENTINELAPEX",
    title: "CYBERDUDEBIVASH® SENTINEL APEX | AI-Native Threat Intelligence",
    description:
      "Real-time threat intelligence — CVE tracking, CISA KEV, STIX 2.1, MITRE ATT&CK, IOC feeds, ransomware intel. Free tier at intel.cyberdudebivash.com",
    images: [`${BASE_URL}/assets/sentinel-apex-thumbnail.jpg`],
  },
  verification: {
    other: {
      "msvalidate.01": "BingSiteAuth",
    },
  },
};

const organizationSchema = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": "https://cyberdudebivash.com/#organization",
      "name": "BIVASHA KUMAR NAYAK trading as CYBERDUDEBIVASH(R)",
      "alternateName": ["CyberDudeBivash", "CYBERDUDEBIVASH"],
      "url": "https://cyberdudebivash.com/",
      "logo": {
        "@type": "ImageObject",
        "url": `${BASE_URL}/assets/logo.png`,
        "width": 512,
        "height": 512,
      },
      "description":
        "BIVASHA KUMAR NAYAK trading as CYBERDUDEBIVASH(R) is a global cybersecurity innovation company based in Jajpur, Odisha, India. We build next-generation AI-driven threat intelligence, SOC automation, and defensive security platforms.",
      "founder": {
        "@type": "Person",
        "@id": "https://www.linkedin.com/in/bivash-kumar-nayak/#person",
        "name": "Bivash Kumar Nayak",
        "jobTitle": "Founder & CEO",
        "url": "https://www.linkedin.com/in/bivash-kumar-nayak/",
        "sameAs": [
          "https://www.linkedin.com/in/bivash-kumar-nayak/",
          "https://github.com/cyberdudebivash",
        ],
      },
      "address": {
        "@type": "PostalAddress",
        "addressLocality": "Jajpur Road",
        "addressRegion": "Odisha",
        "addressCountry": "IN",
      },
      "sameAs": [
        "https://x.com/CDBSENTINELAPEX",
        "https://www.linkedin.com/company/cyberdudebivash/",
        "https://github.com/cyberdudebivash",
        "https://www.facebook.com/cyberdudebivash",
        "https://www.instagram.com/cyberdudebivash_official/",
        "https://medium.com/@cyberdudebivash",
        "https://cyberdudebivash.com/",
        "https://cyberdudebivash.in/",
      ],
      "contactPoint": {
        "@type": "ContactPoint",
        "contactType": "customer support",
        "url": `${BASE_URL}/contact-enterprise.html`,
        "availableLanguage": "English",
      },
    },
    {
      "@type": "WebSite",
      "@id": `${BASE_URL}/#website`,
      "url": BASE_URL,
      "name": "CYBERDUDEBIVASH® SENTINEL APEX",
      "description":
        "AI-native enterprise threat intelligence platform delivering real-time CVE tracking, IOC feeds, STIX 2.1, MITRE ATT&CK mapping, EPSS scoring, and autonomous SOC capabilities.",
      "publisher": { "@id": "https://cyberdudebivash.com/#organization" },
      "potentialAction": {
        "@type": "SearchAction",
        "target": {
          "@type": "EntryPoint",
          "urlTemplate": `${BASE_URL}/threats?q={search_term_string}`,
        },
        "query-input": "required name=search_term_string",
      },
    },
    {
      "@type": "SoftwareApplication",
      "@id": `${BASE_URL}/#software`,
      "name": "CYBERDUDEBIVASH® SENTINEL APEX",
      "applicationCategory": "SecurityApplication",
      "applicationSubCategory": "Threat Intelligence Platform",
      "operatingSystem": "Web",
      "url": BASE_URL,
      "description":
        "Enterprise-grade AI threat intelligence platform with real-time CVE tracking, CISA KEV integration, STIX 2.1 export, MITRE ATT&CK v15 mapping, EPSS enrichment, IOC correlation, ransomware tracking, and autonomous SOC automation.",
      "author": { "@id": "https://cyberdudebivash.com/#organization" },
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD",
        "description": "Free tier available. Enterprise plans from $49/month.",
      },
      "featureList": [
        "Real-time CVE Intelligence with EPSS Scoring",
        "CISA Known Exploited Vulnerabilities (KEV) Tracking",
        "STIX 2.1 / TAXII 2.1 Export",
        "MITRE ATT&CK v15 Mapping",
        "IOC Correlation & Enrichment",
        "Ransomware Intelligence Feeds",
        "APT & Threat Actor Profiling",
        "Autonomous SOC Automation",
        "Dark Web Monitoring",
        "AI Campaign Clustering",
      ],
    },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        {/* Static-export equivalent of next.config.js's former headers() --
            see that file's comment. Only CSP and Referrer-Policy have a
            meta-tag form; X-Frame-Options/nosniff/Permissions-Policy/HSTS
            are HTTP-header-only and come from public/_headers on hosts
            that honor it (e.g. Cloudflare Pages). frame-ancestors is
            listed for documentation but browsers ignore it in meta
            delivery per spec -- real clickjacking protection needs the
            X-Frame-Options header from public/_headers. */}
        <meta
          httpEquiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src * data:; connect-src *; frame-ancestors 'none';"
        />
        <meta name="referrer" content="strict-origin-when-cross-origin" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationSchema) }}
        />
      </head>
      <body className={`${inter.className} bg-gray-950 text-gray-100 antialiased`}>
        <TelemetryProvider>
          <AuthProvider>
            <QueryProvider>
              {children}
            </QueryProvider>
          </AuthProvider>
        </TelemetryProvider>
      </body>
    </html>
  );
}
