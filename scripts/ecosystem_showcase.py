"""Owned CYBERDUDEBIVASH® ecosystem promotion, distinct from CTI evidence.

Public links are an operator-provided ecosystem catalog. This module never
asserts tested product availability, quotes conflicting plan prices, or
modifies threat assertions/entitlements/publication eligibility.
"""
from __future__ import annotations

from html import escape

OFFERINGS = {
    "intel": ("SENTINEL APEX™ Threat Intelligence", "Threat intelligence", "Explore source-linked advisories and structured intelligence options.", "https://intel.cyberdudebivash.com/"),
    "ai": ("SENTINEL APEX AI Security Hub™", "AI security and governance", "Discover AI application, agent security and governance engagement options.", "https://www.cyberdudebivash.in/"),
    "services": ("Enterprise Security Services", "Professional engagements", "Discuss authorized testing, response preparedness, and detection engineering.", "https://www.cyberdudebivash.com/services"),
    "tools": ("ThreatCore™ Defensive Tools", "Security tools and resources", "Browse SOC toolkits, security utilities and available licensing details.", "https://tools.cyberdudebivash.com/"),
    "academy": ("SENTINEL APEX™ Academy", "Education", "Browse practical security operations and AI security learning programs.", "https://academy.cyberdudebivash.com/"),
    "labs": ("SENTINEL APEX™ Labs & Store", "Applied labs and products", "Discover evaluation resources and technical labs.", "https://labs.cyberdudebivash.in/"),
    "research": ("SENTINEL APEX™ Research & Intel Factory", "Research and analysis", "Read technical advisories, research and security education.", "https://blog.cyberdudebivash.in/"),
    "trustx": ("TRUSTX™ Identity Security", "Private preview", "Explore identity-risk concepts and enquiry options; availability is restricted.", "https://trustx.cyberdudebivash.com/"),
    "swarms": ("SENTINEL APEX™ Agent Swarms", "Enquiry / access to confirm", "Explore AI-assisted threat investigation concepts subject to access authorization.", "https://intel.cyberdudebivash.com/swarm"),
}
PRODUCT_EXAMPLES = {
    "ai": ("AGENTGUARD PRO", "TrustGov AI™", "AI Security Red Team Professional Toolkit"),
    "ransomware": ("Fortress Lockdown", "Ransomware IOC Blocker", "SOC Incident Response Professional Toolkit"),
    "breach": ("LeakHunter", "GHOST-CHECK", "DPDP Audit & Readiness Professional Toolkit"),
    "cve": ("QuickScan", "ReconX", "Penetration Testing Reporting Toolkit"),
    "default": ("SOC Starter Bundle", "LeakHunter", "SovereignSOC"),
}
OFFERS = {
    "ai": ("ai", "services", "labs"),
    "ransomware": ("intel", "services", "tools"),
    "breach": ("services", "intel", "trustx"),
    "identity": ("trustx", "services", "intel"),
    "cve": ("intel", "tools", "services"),
    "malware": ("intel", "tools", "services"),
    "default": ("intel", "services", "academy"),
}


def relevant_offers(item: dict) -> tuple[str, str, str]:
    """Only selects catalogued offers, not claims inferred from source data."""
    text = " ".join(str(item.get(k) or "") for k in (
        "type", "threat_type", "category", "title",
    )).lower()
    if any(word in text for word in ("ai security", "llm", "prompt injection", "agent security", "mcp security")):
        return OFFERS["ai"]
    if "ransom" in text:
        return OFFERS["ransomware"]
    if any(word in text for word in ("data breach", "credential leak", "exfiltrat")):
        return OFFERS["breach"]
    if any(word in text for word in ("identity", "privileged access", "account takeover")):
        return OFFERS["identity"]
    if "cve-" in text or "vulnerability" in text or "zero-day" in text:
        return OFFERS["cve"]
    if "malware" in text:
        return OFFERS["malware"]
    return OFFERS["default"]


def render_ecosystem_showcase(item: dict) -> str:
    """One post-editorial commercial section; content is predefined and safe."""
    def card(key: str) -> str:
        name, label, desc, url = OFFERINGS[key]
        return (
            "<article class='cdb-eco-card'><span class='cdb-eco-label'>"
            + escape(label) + "</span><h3>" + escape(name) + "</h3><p>"
            + escape(desc) + "</p><a href='" + escape(url, quote=True)
            + "' target='_blank' rel='noopener noreferrer'>Explore official offering &rarr;</a></article>"
        )

    recommendations = relevant_offers(item)
    kind = next((key for key, offers in OFFERS.items() if offers == recommendations), "default")
    product_names = PRODUCT_EXAMPLES.get(kind, PRODUCT_EXAMPLES["default"])
    products = " &middot; ".join(escape(name) for name in product_names)
    directory = "".join(
        "<li><a href='" + escape(url, quote=True) + "' target='_blank' rel='noopener noreferrer'>"
        + escape(name) + "</a><span>" + escape(label) + "</span></li>"
        for name, label, _, url in OFFERINGS.values()
    )
    return (
        "<section id='cdb-ecosystem-promotion' class='cdb-eco-showcase'"
        " data-cdb-owned-promotion='v1' aria-label='CYBERDUDEBIVASH ecosystem promotional offers'>"
        "<header><span class='cdb-eco-overline'>ECOSYSTEM PROMOTION &middot; OWNED SERVICES &amp; PLATFORMS</span>"
        "<h2>Extend your defense with CYBERDUDEBIVASH&reg; ECOSYSTEM</h2>"
        "<p>Discover connected intelligence, AI security, professional services, "
        "defensive tools, labs and training. Select a relevant next step for your team.</p>"
        "<p class='cdb-eco-summary'>Public directory listing (Oct 2026): 11 platforms &middot; "
        "13 services &middot; 43 products &middot; 2 APIs. Listings do not establish current availability.</p>"
        "</header>"
        "<div class='cdb-eco-cards'>" + "".join(map(card, recommendations)) + "</div>"
        "<div class='cdb-eco-products'><strong>Relevant catalog products:</strong> "
        + products + " &mdash; <a href='https://tools.cyberdudebivash.com/' target='_blank'"
        " rel='noopener noreferrer'>Explore current listings &rarr;</a></div>"
        "<div class='cdb-eco-actions'>"
        "<a class='cdb-eco-primary' href='https://www.cyberdudebivash.com/ecosystem'"
        " target='_blank' rel='noopener noreferrer'>Browse complete ecosystem &rarr;</a>"
        "<a href='mailto:contact@cyberdudebivash.in?subject=Enterprise%20Security%20Enquiry'>"
        "Request an enterprise consultation &rarr;</a></div>"
        "<details><summary>Explore all listed platforms and portals</summary><ul>"
        + directory + "</ul></details>"
        "<p class='cdb-eco-disclosure'><strong>Commercial disclosure:</strong> "
        "This is a promotion of CYBERDUDEBIVASH-owned offerings, separate from the "
        "threat intelligence findings. Pricing, scope, functionality, availability and "
        "checkout are subject to confirmation on each official page or written proposal. "
        "Private previews are not generally available. Authorized security testing "
        "requires written permission. Buying a service does not alter CTI confidence.</p>"
        "</section>"
    )


ECOSYSTEM_CSS = """
.cdb-eco-showcase{color:#eaf3fa;background:linear-gradient(135deg,#112e43,#0b2133);border:1px solid #53758c;border-radius:14px;margin:44px 0 25px;padding:clamp(18px,2.7vw,32px);font:400 14px/1.7 system-ui,sans-serif}
.cdb-eco-showcase *{box-sizing:border-box}
.cdb-eco-overline{display:block;font:800 11px/1.5 system-ui,sans-serif;color:#a8e6f1;letter-spacing:.12em}
.cdb-eco-showcase h2{font-size:clamp(21px,2.5vw,30px)!important;color:#fff!important;line-height:1.2!important;margin:12px 0!important}
.cdb-eco-showcase header p{color:#d5e5ef;line-height:1.75;max-width:70ch}
.cdb-eco-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:21px 0}
.cdb-eco-card{border:1px solid #4c6b82;background:#18374b;border-radius:10px;padding:18px;display:flex;flex-direction:column;gap:9px;min-width:0}
.cdb-eco-label{font-size:11px;letter-spacing:.07em;color:#c2e5ec;text-transform:uppercase;font-weight:800}
.cdb-eco-card h3{font-size:17px!important;color:#fff!important;line-height:1.3!important;margin:0!important}
.cdb-eco-card p{font-size:13px!important;color:#d8e5ee!important;flex:1;line-height:1.7!important;margin:0!important}
.cdb-eco-showcase a{color:#b0ebf4;text-decoration:underline;text-underline-offset:3px;overflow-wrap:anywhere}
.cdb-eco-card a{display:inline-flex;align-items:center;min-height:44px;font-weight:800;font-size:13px}
.cdb-eco-summary{font-size:12px!important;color:#d6e6f0!important;margin-top:12px!important}
.cdb-eco-products{padding:12px 14px;border:1px solid #53758c;border-radius:8px;background:#19374a;color:#dfebf2;font-size:13px;line-height:1.7}
.cdb-eco-actions{display:flex;gap:12px;flex-wrap:wrap;margin:15px 0}
.cdb-eco-actions a{display:inline-flex;align-items:center;justify-content:center;min-height:44px;border-radius:8px;padding:10px 14px;border:1px solid #7394a9;font-size:13px;text-align:center;font-weight:800}
.cdb-eco-actions .cdb-eco-primary{background:#a1e8e7;color:#102b39!important}
.cdb-eco-showcase details{margin-top:16px;border-top:1px solid #557187;padding-top:10px}
.cdb-eco-showcase summary{cursor:pointer;min-height:44px;display:flex;align-items:center;font-size:13px;font-weight:800;color:#e2f0f9}
.cdb-eco-showcase details ul{list-style:none;padding:8px 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.cdb-eco-showcase details li span{display:block;color:#cadce8;font-size:11px}
.cdb-eco-disclosure{font-size:12px!important;color:#d5e4f0!important;border-top:1px solid #4f6d84;margin-top:18px!important;padding-top:13px!important;line-height:1.7!important}
.cdb-eco-showcase :where(a,summary):focus-visible{outline:3px solid #ffda80!important;outline-offset:4px!important}
@media(max-width:880px){.cdb-eco-cards{grid-template-columns:1fr 1fr}.cdb-eco-card:last-child{grid-column:span 2}}
@media(max-width:540px){.cdb-eco-cards,.cdb-eco-showcase details ul{grid-template-columns:1fr}.cdb-eco-card:last-child{grid-column:auto}.cdb-eco-actions a{width:100%}}
@media(prefers-reduced-motion:reduce){.cdb-eco-showcase *{animation:none!important;transition:none!important}}
@media print{.cdb-eco-showcase{background:#fff!important;color:#111!important;border:1px solid #999!important;box-shadow:none!important;break-inside:avoid-page}.cdb-eco-showcase :where(h2,h3,p,span){color:#111!important}.cdb-eco-card{background:#fff!important;border-color:#bbb!important;break-inside:avoid-page}.cdb-eco-showcase a{color:#173d57!important;text-decoration:underline!important}.cdb-eco-showcase details{display:none!important}}
"""
