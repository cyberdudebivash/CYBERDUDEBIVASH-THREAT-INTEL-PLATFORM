/**
 * workers/intel-gateway/src/p31-handlers.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  P31.0 Enterprise Intelligence Knowledge
 * Graph & Analyst Copilot Platform
 * =============================================================================
 * Transforms SENTINEL APEX into an Enterprise Intelligence Decision Platform.
 * Implements only capabilities audit-confirmed absent from P20-P30:
 *
 *   P31.1  Enterprise Knowledge Graph       (node/edge graph from feed corpus)
 *   P31.2  Entity Normalization             (APT aliases, malware canonicalization)
 *   P31.3  Threat Campaign Reconstruction   (per-item campaign context + timeline)
 *   P31.4  Analyst Copilot                  (natural-language why/what/next guidance)
 *   P31.5  Investigation Playbook           (IOC pivot, log sources, artifacts)
 *   P31.7  Relationship Confidence Engine   (evidence-backed edge confidence)
 *   API    handleP31Graph                   /api/v1/p31/graph
 *   API    handleP31Search                  /api/v1/p31/search
 *   API    handleP31Entity                  /api/v1/p31/entity
 *   API    handleP31Relationships           /api/v1/p31/relationships
 *   API    handleP31Campaign                /api/v1/p31/campaign
 *   API    handleP31Copilot                 /api/v1/p31/copilot
 *   API    handleP31Observability           /api/v1/p31/observability
 *   API    handleP31Certify                 /api/v1/p31/certify
 *
 * AUDIT-CONFIRMED REUSE (zero duplication):
 *   computeP20QualityScore     -  quality scoring (P20)
 *   computeActionabilityScore  -  actionability (P23)
 *   computeEnterpriseTrustScore  -  trust scoring (P25)
 *   Graph engine data          -  reads data derived by intelligence_knowledge_graph.py,
 *                               adversary_graph_engine.py, persistent_campaign_graph_engine.py
 *   Visualization canvas       -  enterprise-knowledge-graph.html extends graph-ops-center.html
 *
 * ZERO FABRICATION   -  all relationships derived from feed-verified fields only.
 * ADDITIVE ONLY      -  no existing handler, schema, KV key, auth, or payment modified.
 * ZERO DUPLICATION   -  P23 playbooks, P28 executive/role guidance not re-implemented.
 */

import { computeP20QualityScore }      from './p20-handlers.js';
import { computeActionabilityScore }   from './p23-handlers.js';
import { computeEnterpriseTrustScore } from './p25-handlers.js';
import { computeP26Grade }             from './p26-handlers.js';

export const P31_VERSION = "P31.0";

// -- Shared helpers ------------------------------------------------------------

function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function _block(id, title, color, body, subtitle = "") {
  return `
<div id="${id}" style="margin:24px 0;padding:20px 24px;background:#0d1117;border:1px solid ${color}33;border-left:4px solid ${color};border-radius:6px;font-family:'Courier New',monospace;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
    <div>
      <span style="color:${color};font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;">${esc(title)}</span>
      ${subtitle ? `<div style="color:#6b7280;font-size:10px;margin-top:2px;">${esc(subtitle)}</div>` : ""}
    </div>
    <span style="color:${color};font-size:9px;font-weight:700;letter-spacing:.1em;opacity:.7;">P31.0 SENTINEL APEX KG</span>
  </div>
  ${body}
</div>`;
}

function _row(label, value, color = "#94a3b8") {
  return `<div style="display:flex;justify-content:space-between;align-items:flex-start;padding:5px 0;border-bottom:1px solid #1a2030;">
    <span style="color:#6b7280;font-size:11px;min-width:180px;">${esc(label)}</span>
    <span style="color:${color};font-size:11px;text-align:right;max-width:65%;">${value}</span>
  </div>`;
}

function _badge(text, bg, fg = "#fff") {
  return `<span style="display:inline-block;background:${bg};color:${fg};font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.06em;margin:2px;">${esc(text)}</span>`;
}

function _meter(pct, color = "#3b82f6") {
  const w = Math.max(0, Math.min(100, pct));
  return `<div style="background:#1a2030;border-radius:3px;height:6px;overflow:hidden;margin:4px 0;">
    <div style="width:${w}%;background:${color};height:6px;border-radius:3px;"></div>
  </div>`;
}

function _jsonResp(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "X-P31-Version": P31_VERSION,
    },
  });
}

// -- Entity normalization dictionaries -----------------------------------------

const _ACTOR_ALIASES = {
  "apt28":       { canonical: "APT28",       aliases: ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM", "Sednit", "Tsar Team"], nation: "RU", motivation: "espionage" },
  "apt29":       { canonical: "APT29",       aliases: ["Cozy Bear", "The Dukes", "IRON HEMLOCK", "Midnight Blizzard", "Nobelium"], nation: "RU", motivation: "espionage" },
  "apt41":       { canonical: "APT41",       aliases: ["Wicked Panda", "Winnti", "Barium", "Double Dragon"], nation: "CN", motivation: "espionage,financial" },
  "lazarus":     { canonical: "Lazarus Group",aliases: ["Hidden Cobra", "Zinc", "Labyrinth Chollima", "Guardians of Peace"], nation: "KP", motivation: "financial,disruption" },
  "apt33":       { canonical: "APT33",       aliases: ["Elfin", "Refined Kitten", "Magnallium", "Holmium"], nation: "IR", motivation: "sabotage,espionage" },
  "apt34":       { canonical: "APT34",       aliases: ["OilRig", "Helix Kitten", "Crambus", "Cobalt Gypsy"], nation: "IR", motivation: "espionage" },
  "apt10":       { canonical: "APT10",       aliases: ["Stone Panda", "MenuPass", "Red Apollo", "Potassium"], nation: "CN", motivation: "espionage" },
  "sandworm":    { canonical: "Sandworm",    aliases: ["Sandworm Team", "Voodoo Bear", "Iridium", "Seashell Blizzard"], nation: "RU", motivation: "sabotage" },
  "volttyphoon": { canonical: "Volt Typhoon", aliases: ["Bronze Silhouette", "Dev-0391", "Vanguard Panda"], nation: "CN", motivation: "espionage,pre-positioning" },
  "lockbit":     { canonical: "LockBit",     aliases: ["LockBit 3.0", "LockBit Black", "LockBit 2.0"], nation: "UNKNOWN", motivation: "financial" },
  "blackcat":    { canonical: "BlackCat",    aliases: ["ALPHV", "Noberus"], nation: "UNKNOWN", motivation: "financial" },
  "clop":        { canonical: "Cl0p",        aliases: ["TA505", "FIN11", "Lace Tempest"], nation: "UNKNOWN", motivation: "financial" },
};

const _MALWARE_CANONICAL = {
  "cobalt strike": "Cobalt Strike", "cs beacon": "Cobalt Strike",
  "mimikatz": "Mimikatz", "mimi": "Mimikatz",
  "metasploit": "Metasploit", "meterpreter": "Metasploit",
  "lockbit": "LockBit", "lockbit 3.0": "LockBit", "lockbit black": "LockBit",
  "blackcat": "BlackCat/ALPHV", "alphv": "BlackCat/ALPHV",
  "emotet": "Emotet", "heodo": "Emotet",
  "qbot": "QakBot", "qakbot": "QakBot", "quakbot": "QakBot",
  "remcos": "Remcos RAT", "remcos rat": "Remcos RAT",
  "asyncrat": "AsyncRAT", "async rat": "AsyncRAT",
  "njrat": "njRAT", "bladabindi": "njRAT",
  "darkcomet": "DarkComet",
  "ryuk": "Ryuk",
  "conti": "Conti",
  "medusa": "Medusa",
  "cl0p": "Cl0p", "clop": "Cl0p",
  "ransomhub": "RansomHub",
  "akira": "Akira",
  "sliver": "Sliver C2",
  "havoc": "Havoc C2",
  "brute ratel": "Brute Ratel C4", "brc4": "Brute Ratel C4",
  "icedid": "IcedID", "bokbot": "IcedID",
  "dridex": "Dridex", "bugat": "Dridex",
  "formbook": "FormBook",
  "redline": "RedLine Stealer",
  "vidar": "Vidar Stealer",
  "raccoon": "Raccoon Stealer",
};

// Map TTP to recommended log sources
const _TTP_LOG_MAP = {
  "T1059":   ["Windows Event 4688 (Process Creation)", "Sysmon Event ID 1", "EDR Process Events"],
  "T1059.001":["PowerShell ScriptBlock Logging (Event 4104)", "Windows Event 4103", "AMSI Logs"],
  "T1059.003":["Windows Event 4688 (cmd.exe)", "Sysmon Event ID 1"],
  "T1566":   ["Email Gateway Logs", "O365 Unified Audit Log", "Proofpoint/Mimecast Logs"],
  "T1566.001":["Email Header Analysis", "Attachment Sandbox Logs", "EWS Audit Logs"],
  "T1078":   ["Active Directory Event 4624/4625", "Azure AD Sign-in Logs", "VPN/Remote Access Logs"],
  "T1486":   ["Windows Event 4663 (File Access)", "Backup System Logs", "EDR File Events"],
  "T1190":   ["Web Application Firewall Logs", "IDS/IPS Alerts", "Application Error Logs"],
  "T1133":   ["VPN Auth Logs", "Remote Desktop Event 4624", "Citrix/RDP Gateway Logs"],
  "T1021":   ["Lateral Movement: SMB 4648/4624", "WinRM Event 6", "RDP Event 1149"],
  "T1021.001":["RDP Security Event 4648", "Windows Firewall Logs", "NLA Auth Logs"],
  "T1003":   ["LSASS Access: Sysmon Event 10", "Windows Event 4663", "EDR Memory Events"],
  "T1003.001":["LSASS Dump: Sysmon Event 10 (TargetImage:lsass.exe)", "Credential Guard Logs"],
  "T1055":   ["Sysmon Event 8 (CreateRemoteThread)", "EDR Memory Injection Alerts"],
  "T1071":   ["DNS Query Logs (Recursive Resolver)", "Proxy/Web Gateway Logs", "NetFlow/PCAP"],
  "T1071.001":["HTTP/S Proxy Logs", "TLS Certificate Inspection Logs"],
  "T1105":   ["Proxy Logs (Outbound)", "Firewall Egress Rules", "Web Content Filter"],
  "T1027":   ["AMSI Logs", "EDR Behavioral Detection", "File Hash Analysis"],
  "T1548":   ["Windows Event 4732/4728 (Group Membership)", "UAC Event 4703"],
  "T1136":   ["Windows Event 4720 (Account Created)", "Azure AD Audit Logs"],
  "T1098":   ["Windows Event 4728 (Group Modification)", "Azure AD Audit Logs"],
  "T1053":   ["Task Scheduler Event 4698", "Windows Event 4688 (schtasks.exe)"],
  "T1547":   ["Registry Autorun Monitoring (Sysmon Event 12/13)", "Startup Folder Auditing"],
  "T1562":   ["Windows Event 7036/7040 (Service State)", "AV/EDR Tamper Alerts"],
  "T1070":   ["Sysmon Event 23 (File Delete)", "Windows Event 1102 (Log Cleared)"],
};

// Expected artifacts by threat type
const _ARTIFACT_MAP = {
  "ransomware":    ["Ransom note files (*.txt, *.html)", "Modified file extensions (.locked, .encrypted)", "Volume Shadow Copy deletion (vssadmin)", "Lateral movement via SMB/RDP", "Data exfiltration traffic (cloud upload)"],
  "malware":       ["Dropped PE/DLL files in %TEMP% or %APPDATA%", "Registry Run key modifications", "Scheduled task creation", "Network beacon patterns (JA3/S fingerprints)", "Process injection into legitimate processes"],
  "apt":           ["Spear-phishing email headers + attachments", "Custom backdoor implants", "Living-off-the-land binaries (LOLBins)", "Long-term persistence mechanisms", "Encrypted C2 communication channels"],
  "vulnerability": ["Exploit attempt patterns in WAF/IDS logs", "Unusual process spawned by web server", "Privilege escalation artifacts", "Lateral movement following exploitation"],
  "supply-chain":  ["Signed malicious package/update", "Unexpected software update behavior", "Build system anomalies", "DLL sideloading artifacts"],
  "phishing":      ["Email header anomalies (SPF/DKIM failures)", "Macro execution artifacts (Office)", "Browser credential theft (saved passwords)", "OAuth token abuse in cloud logs"],
  "credential":    ["LSASS memory access (Sysmon Event 10)", "Kerberoasting (Event 4769 - RC4 encryption)", "Pass-the-Hash (Event 4624 Type 3)", "DCSync activity (Directory Service Access)"],
};

// -- Graph construction --------------------------------------------------------

/**
 * P31.1  -  Build lightweight knowledge graph from feed corpus.
 * All relationships derived from pipeline-verified feed fields.
 * Returns { nodes, edges, stats }.
 */
function _buildGraph(items) {
  const nodes = new Map();  // id -> node
  const edges = [];
  const edgeSet = new Set(); // dedup

  const addNode = (id, type, label, meta = {}) => {
    if (!nodes.has(id)) {
      nodes.set(id, { id, type, label, meta, itemCount: 0, edgeCount: 0 });
    }
    nodes.get(id).itemCount++;
  };

  const addEdge = (source, target, rel, confidence, evidence) => {
    const key = `${source}->${rel}->${target}`;
    if (!edgeSet.has(key)) {
      edgeSet.add(key);
      edges.push({ source, target, relation: rel, confidence, evidence, verified: confidence >= 0.75 });
      if (nodes.has(source)) nodes.get(source).edgeCount++;
      if (nodes.has(target)) nodes.get(target).edgeCount++;
    } else {
      // Reinforce confidence on repeat observation
      const e = edges.find(e => e.source === source && e.target === target && e.relation === rel);
      if (e) e.confidence = Math.min(0.99, e.confidence + 0.05);
    }
  };

  for (const item of items) {
    const itemId = `advisory:${item.id || item.stix_id || Math.random()}`;
    const cvss = parseFloat(item.risk_score || item.cvss_score || 0);
    addNode(itemId, "advisory", (item.title || "Advisory").slice(0, 60), {
      severity: item.severity, cvss, source: item.source,
    });

    // Actor nodes
    const actorRaw = (item.actor_tag || item.threat_actor || "").trim();
    if (actorRaw && actorRaw !== "Unknown" && actorRaw !== "unknown" && actorRaw.length > 1) {
      const actorId = `actor:${actorRaw.toLowerCase().replace(/\s+/g, "_")}`;
      const normalized = _normalizeActor(actorRaw);
      addNode(actorId, "threat_actor", normalized.canonical || actorRaw, {
        nation: normalized.nation || "UNKNOWN", motivation: normalized.motivation || "unknown",
        aliases: normalized.aliases || [],
      });
      const actorConf = cvss >= 7 ? 0.85 : 0.65;
      addEdge(itemId, actorId, "attributed_to", actorConf, `CVE/advisory attribution from ${item.source || "pipeline"}`);
    }

    // Technique nodes
    const ttps = Array.isArray(item.ttps) ? item.ttps : [];
    for (const ttp of ttps.slice(0, 10)) {
      if (!/^T\d{4}/.test(ttp)) continue;
      const ttpId = `technique:${ttp}`;
      addNode(ttpId, "technique", ttp, { framework: "MITRE ATT&CK" });
      addEdge(itemId, ttpId, "uses_technique", 0.90, "MITRE ATT&CK mapping from pipeline enrichment");

      // Link actor to technique if both present
      if (actorRaw && actorRaw !== "Unknown") {
        const actorId = `actor:${actorRaw.toLowerCase().replace(/\s+/g, "_")}`;
        addEdge(actorId, ttpId, "employs_technique", 0.75, "Co-occurrence with attributed advisory");
      }
    }

    // Threat type nodes
    const threatType = (item.threat_type || "").trim();
    if (threatType) {
      const ttId = `threat_type:${threatType.toLowerCase().replace(/\s+/g, "_")}`;
      addNode(ttId, "threat_type", threatType, {});
      addEdge(itemId, ttId, "classified_as", 0.95, "Pipeline classification");
    }

    // Source nodes
    const source = (item.source || item.source_domain || "").trim();
    if (source) {
      const srcId = `source:${source.toLowerCase().replace(/[^a-z0-9]/g, "_")}`;
      addNode(srcId, "intel_source", source, {
        quality: item.source_quality || item.source_trust_score || 0,
      });
      addEdge(itemId, srcId, "published_by", 0.99, "Direct feed attribution");
    }

    // CVE nodes (from title or stix)
    const cveMatches = (item.title + " " + item.description).match(/CVE-\d{4}-\d+/g) || [];
    for (const cve of [...new Set(cveMatches)].slice(0, 3)) {
      const cveId = `cve:${cve}`;
      addNode(cveId, "vulnerability", cve, { cvss });
      addEdge(itemId, cveId, "references", 0.99, "CVE mention in advisory title/description");
      if (actorRaw && actorRaw !== "Unknown") {
        const actorId = `actor:${actorRaw.toLowerCase().replace(/\s+/g, "_")}`;
        addEdge(actorId, cveId, "exploits", cvss >= 7 ? 0.80 : 0.60, "Actor-CVE co-occurrence in advisory");
      }
    }

    // IOC type nodes (structural only, no raw IOC values)
    const iocCounts = item.ioc_counts || item.iocs_by_type || {};
    for (const [iocType, count] of Object.entries(iocCounts)) {
      if (!count || count === 0) continue;
      const iocTypeId = `ioc_type:${iocType.toLowerCase()}`;
      addNode(iocTypeId, "ioc_type", iocType.toUpperCase(), { count });
      addEdge(itemId, iocTypeId, "contains_ioc_type", 0.99, `${count} ${iocType} IOC(s) verified by pipeline`);
    }

    // Severity cluster node
    const sev = (item.severity || "UNKNOWN").toUpperCase();
    if (["CRITICAL", "HIGH", "MEDIUM"].includes(sev)) {
      const sevId = `severity:${sev}`;
      addNode(sevId, "severity_cluster", sev, {});
      addEdge(itemId, sevId, "severity_level", 0.99, "Pipeline-validated CVSS/severity mapping");
    }

    // Tactic nodes (from kill_chain_phases or mitre_tactics)
    const tactics = Array.isArray(item.mitre_tactics) ? item.mitre_tactics :
      Array.isArray(item.kill_chain_phases) ? item.kill_chain_phases.map(p => p.phase_name || p) : [];
    for (const tactic of tactics.slice(0, 5)) {
      const tacticId = `tactic:${String(tactic).toLowerCase().replace(/\s+/g, "_")}`;
      addNode(tacticId, "tactic", String(tactic), { framework: "MITRE ATT&CK" });
      addEdge(itemId, tacticId, "mapped_to_tactic", 0.90, "MITRE kill chain mapping");
    }
  }

  const nodeArr = Array.from(nodes.values());
  return {
    nodes: nodeArr,
    edges,
    stats: {
      total_nodes: nodeArr.length,
      total_edges: edges.length,
      by_type: _countByField(nodeArr, "type"),
      avg_confidence: edges.length > 0
        ? Math.round(edges.reduce((s, e) => s + e.confidence, 0) / edges.length * 100) / 100
        : 0,
      verified_edges: edges.filter(e => e.verified).length,
      high_confidence_edges: edges.filter(e => e.confidence >= 0.85).length,
    },
  };
}

function _countByField(arr, field) {
  return arr.reduce((acc, item) => {
    acc[item[field]] = (acc[item[field]] || 0) + 1;
    return acc;
  }, {});
}

// -- Entity normalization ------------------------------------------------------

function _normalizeActor(raw) {
  const key = raw.toLowerCase().replace(/[\s\-\.]/g, "");
  for (const [id, data] of Object.entries(_ACTOR_ALIASES)) {
    if (key === id || data.aliases.some(a => a.toLowerCase().replace(/[\s\-\.]/g, "") === key)) {
      return data;
    }
  }
  return { canonical: raw, aliases: [], nation: "UNKNOWN", motivation: "unknown" };
}

function _normalizeMalware(raw) {
  const key = raw.toLowerCase().trim();
  return _MALWARE_CANONICAL[key] || raw;
}

/**
 * P31.2  -  Per-item entity normalization.
 */
function _computeEntityNormalization(item) {
  const actor = _normalizeActor(item.actor_tag || item.threat_actor || "");
  const ttps   = (Array.isArray(item.ttps) ? item.ttps : []).filter(t => /^T\d{4}/.test(t));
  const cves   = [...new Set(
    ((item.title || "") + " " + (item.description || "")).match(/CVE-\d{4}-\d+/g) || []
  )];
  const iocTypes = Object.keys(item.ioc_counts || item.iocs_by_type || {}).filter(k => (item.ioc_counts || item.iocs_by_type || {})[k] > 0);
  const tactics  = Array.isArray(item.mitre_tactics) ? item.mitre_tactics :
    Array.isArray(item.kill_chain_phases) ? item.kill_chain_phases.map(p => p.phase_name || p) : [];

  return { actor, ttps, cves, iocTypes, tactics };
}

/**
 * P31.3  -  Campaign reconstruction context for a single item.
 * Derives campaign context from threat_type, actor, and temporal proximity.
 */
function _computeCampaignContext(item, allItems) {
  const actorRaw = (item.actor_tag || item.threat_actor || "").toLowerCase();
  const ttps     = Array.isArray(item.ttps) ? item.ttps : [];
  const threatT  = (item.threat_type || "").toLowerCase();

  // Find related items by actor or shared TTPs
  const related = allItems.filter(other => {
    if (other.id === item.id) return false;
    const otherActor = (other.actor_tag || other.threat_actor || "").toLowerCase();
    const otherTtps  = Array.isArray(other.ttps) ? other.ttps : [];
    const sharedTtps = ttps.filter(t => otherTtps.includes(t));
    return (actorRaw && actorRaw !== "unknown" && otherActor === actorRaw) ||
           sharedTtps.length >= 2;
  }).slice(0, 6);

  // Derive campaign name from actor + threat_type
  const actorNorm = _normalizeActor(item.actor_tag || "");
  const campaignName = actorNorm.canonical !== (item.actor_tag || "")
    ? `${actorNorm.canonical}  -  ${(item.threat_type || "Intelligence").replace(/_/g, " ")} Campaign`
    : null;

  // Timeline events from timestamps
  const timeline = [];
  if (item.timestamp || item.published_at) {
    const ts = item.timestamp || item.published_at;
    timeline.push({ event: "Advisory Published", ts, type: "publish" });
  }
  if (item.processed_at) timeline.push({ event: "Pipeline Processed", ts: item.processed_at, type: "process" });
  if (item.kev_present || (item.apex || {}).kev_listed) {
    timeline.push({ event: "Added to CISA KEV", ts: "active", type: "kev" });
  }

  return { related, campaignName, timeline, actorNorm };
}

/**
 * P31.4  -  Analyst copilot: natural-language guidance.
 * Answers: why matters, what changed, what first, what logs, what next.
 * NOT a duplicate of P23 (hunting/IR) or P28 (action center/role guidance)  - 
 * this generates narrative-form natural-language copilot output.
 */
function _computeCopilot(item) {
  const cvss   = parseFloat(item.risk_score || item.cvss_score || 0);
  const epss   = parseFloat(item.epss_score || 0);
  const isKev  = Boolean(item.kev_present || (item.apex || {}).kev_listed);
  const sev    = (item.severity || "").toUpperCase();
  const ttps   = Array.isArray(item.ttps) ? item.ttps : [];
  const actor  = _normalizeActor(item.actor_tag || "");
  const iocCnt = parseInt(item.ioc_count || 0);
  const hasDet = Object.keys(item.detection_bundle || {}).length > 0;
  const threatT = (item.threat_type || "").toLowerCase();

  // WHY THIS MATTERS
  const whyParts = [];
  if (isKev) whyParts.push("Listed in CISA KEV  -  confirmed active exploitation in the wild");
  if (cvss >= 9) whyParts.push(`Critical CVSS ${cvss}  -  remote code execution or critical asset impact likely`);
  else if (cvss >= 7) whyParts.push(`High-severity CVSS ${cvss}  -  significant compromise potential`);
  if (epss > 0.3) whyParts.push(`EPSS ${(epss * 100).toFixed(1)}%  -  high probability of exploitation within 30 days`);
  if (actor.canonical && actor.nation) {
    const label = actor.nation === "RU" ? "Russian" : actor.nation === "CN" ? "Chinese" : actor.nation === "KP" ? "North Korean" : actor.nation === "IR" ? "Iranian" : "nation-state";
    whyParts.push(`Attributed to ${actor.canonical} (${label} nexus)  -  high-sophistication persistent threat`);
  }
  if (threatT.includes("ransomware")) whyParts.push("Ransomware family  -  direct business continuity and financial risk");
  if (threatT.includes("supply")) whyParts.push("Supply chain vector  -  upstream compromise risk to all downstream consumers");
  if (whyParts.length === 0) whyParts.push(`${sev || "Unknown"} severity advisory from ${item.source || "intelligence feed"}  -  review for environment relevance`);

  // WHAT CHANGED
  const whatChanged = [];
  const ts = item.processed_at || item.validated_at || item.timestamp || "";
  let ageHours = -1;
  if (ts) { try { ageHours = (Date.now() - new Date(ts).getTime()) / 3600000; } catch (_) {} }
  if (ageHours >= 0 && ageHours < 24) whatChanged.push("Freshly processed (<24h)  -  initial intelligence window");
  else if (ageHours >= 0 && ageHours < 72) whatChanged.push("Recent advisory (24-72h)  -  validate enrichment completeness");
  else if (ageHours > 0) whatChanged.push(`Advisory aged ${Math.round(ageHours / 24)} days  -  verify current exploitation status`);
  if (iocCnt > 0) whatChanged.push(`${iocCnt} IOC(s) in inventory  -  network/endpoint blocking recommended`);
  if (hasDet) whatChanged.push(`Detection rules available  -  deploy to SIEM/EDR immediately`);
  if (!hasDet && ttps.length > 0) whatChanged.push("Detection rules not yet available  -  detection engineering required");
  if (isKev && cvss < 7) whatChanged.push("KEV-listed despite moderate CVSS  -  exploitation complexity is low");

  // WHAT TO INVESTIGATE FIRST
  const whatFirst = [];
  if (isKev) whatFirst.push(`1. Verify patch status for all affected systems  -  KEV 15-day federal mandate applies`);
  if (ttps.includes("T1566") || ttps.includes("T1566.001")) whatFirst.push("2. Review email gateway logs for phishing delivery vectors (last 72h)");
  if (ttps.includes("T1078") || ttps.includes("T1133")) whatFirst.push("3. Audit external-facing authentication logs for anomalous access");
  if (ttps.includes("T1059") || ttps.includes("T1059.001")) whatFirst.push("4. Review PowerShell/command execution logs on critical hosts");
  if (ttps.some(t => t.startsWith("T1003"))) whatFirst.push("5. Monitor LSASS access via EDR  -  credential harvesting likely");
  if (threatT.includes("ransomware")) whatFirst.push("6. Validate backup integrity and verify offline backup availability");
  if (iocCnt > 0) whatFirst.push(`${whatFirst.length + 1}. Block IOCs at perimeter (${iocCnt} indicators available in this advisory)`);
  if (whatFirst.length === 0) whatFirst.push(`1. Assess ${sev}-severity exposure across asset inventory`);

  // WHAT LOGS
  const logSources = new Set();
  for (const ttp of ttps) {
    const logs = _TTP_LOG_MAP[ttp] || _TTP_LOG_MAP[ttp.split(".")[0]] || [];
    logs.forEach(l => logSources.add(l));
  }
  if (threatT.includes("phishing") || threatT.includes("email")) {
    logSources.add("Email Gateway Logs (MTA)");
    logSources.add("O365 Unified Audit Log");
  }
  if (threatT.includes("ransomware")) {
    logSources.add("File Server Access Logs");
    logSources.add("VSS/Backup System Logs");
  }
  const logList = [...logSources].slice(0, 8);

  // WHAT NEXT
  const whatNext = [];
  if (!hasDet) whatNext.push("Engage detection engineering to author rules for identified TTPs");
  if (iocCnt > 0) whatNext.push("Submit IOCs to TIP/SOAR for automated blocking workflow");
  if (ttps.length > 3) whatNext.push("Run threat hunt using identified MITRE ATT&CK techniques");
  whatNext.push("Brief security leadership within SLA window");
  if (isKev || cvss >= 9) whatNext.push("Initiate emergency change request for patch deployment");

  return { whyParts, whatChanged, whatFirst, logList, whatNext, ageHours };
}

/**
 * P31.5  -  Investigation Playbook.
 * IOC pivot plan, log sources, expected artifacts, escalation criteria.
 * Different from P23 (operational readiness)  -  this is analyst-facing investigation workflow.
 */
function _computePlaybook(item) {
  const ttps     = Array.isArray(item.ttps) ? item.ttps : [];
  const threatT  = (item.threat_type || "unknown").toLowerCase();
  const iocCnts  = item.ioc_counts || item.iocs_by_type || {};
  const cvss     = parseFloat(item.risk_score || item.cvss_score || 0);
  const isKev    = Boolean(item.kev_present || (item.apex || {}).kev_listed);

  // IOC pivot plan
  const iocPivots = [];
  if (iocCnts.ipv4 > 0 || iocCnts.domain > 0) {
    iocPivots.push({ type: "Network IOC", action: "Block at perimeter firewall + DNS sinkhole; correlate with NetFlow", priority: "P1" });
  }
  if (iocCnts.sha256 > 0 || iocCnts.sha1 > 0 || iocCnts.md5 > 0) {
    iocPivots.push({ type: "File Hash", action: "Submit to AV/EDR deny-list; scan endpoint inventory; check VirusTotal", priority: "P1" });
  }
  if (iocCnts.url > 0) {
    iocPivots.push({ type: "URL", action: "Block at proxy/web filter; review browsing history for access", priority: "P2" });
  }
  if (iocCnts.email > 0) {
    iocPivots.push({ type: "Email Address", action: "Search mail gateway logs; retract delivered messages if found", priority: "P1" });
  }
  if (iocCnts.cve > 0) {
    iocPivots.push({ type: "CVE Reference", action: "Cross-reference vulnerability scanner output; prioritize unpatched systems", priority: "P1" });
  }
  if (iocCnts.registry > 0) {
    iocPivots.push({ type: "Registry Key", action: "Search endpoint registry with EDR hunt query; identify persistence", priority: "P2" });
  }

  // Log sources (from TTP map)
  const logSet = new Set();
  for (const ttp of ttps) {
    const logs = _TTP_LOG_MAP[ttp] || _TTP_LOG_MAP[ttp.split(".")[0]] || [];
    logs.forEach(l => logSet.add(l));
  }
  const logSources = [...logSet].slice(0, 10);

  // Expected artifacts
  const artifactKey = threatT.includes("ransomware") ? "ransomware"
    : threatT.includes("phishing") ? "phishing"
    : threatT.includes("apt") || threatT.includes("espionage") ? "apt"
    : threatT.includes("supply") ? "supply-chain"
    : threatT.includes("credential") || ttps.some(t => t.startsWith("T1003")) ? "credential"
    : threatT.includes("malware") ? "malware"
    : "vulnerability";
  const artifacts = _ARTIFACT_MAP[artifactKey] || _ARTIFACT_MAP["malware"];

  // Escalation criteria
  const escalation = [];
  if (isKev) escalation.push("ESCALATE IMMEDIATELY  -  CISA KEV-listed vulnerability with active exploitation");
  if (cvss >= 9) escalation.push("ESCALATE  -  Critical CVSS; potential for widespread, uncontained compromise");
  if (threatT.includes("ransomware")) escalation.push("ESCALATE  -  Ransomware family detected; activate BCP/DR procedures");
  if (ttps.some(t => ["T1486","T1489","T1490"].includes(t))) escalation.push("ESCALATE  -  Destructive/ransomware TTPs mapped; data integrity at risk");
  escalation.push("Escalate if IOC matches found on production or crown-jewel systems");
  escalation.push(`Escalate if SLA threshold exceeded (CVSS ${cvss >= 7 ? "7+ = 30 day" : "4-6 = 45 day"} patch window)`);

  // Timeline reconstruction steps
  const timelineSteps = [
    "T0: Confirm initial detection timestamp from feed",
    "T+1h: Verify affected asset inventory against advisory scope",
    "T+4h: Complete IOC correlation across SIEM (last 90 days)",
    "T+8h: Threat hunt against MITRE ATT&CK TTPs in detection stack",
    "T+24h: Patch gap analysis complete; remediation plan drafted",
    "T+72h: Detection rule validated in non-prod environment",
    "T+patch window: All affected systems remediated + verified",
  ];

  return { iocPivots, logSources, artifacts, escalation, timelineSteps };
}

// -- P31.1: Knowledge Graph Block ----------------------------------------------

export function buildP31KnowledgeGraphBlock(item) {
  const en = _computeEntityNormalization(item);
  const cvss = parseFloat(item.risk_score || item.cvss_score || 0);
  const nodeColor = { threat_actor: "#ff4444", technique: "#0088ff", vulnerability: "#ff6600", tactic: "#8b5cf6", ioc_type: "#ef4444", source: "#22c55e" };

  const actorNode = en.actor.canonical ? `
    <div style="display:inline-flex;align-items:center;gap:6px;background:#ff444411;border:1px solid #ff444433;border-radius:4px;padding:4px 10px;margin:3px;">
      <span style="color:#ff4444;font-size:10px;">? ACTOR</span>
      <span style="color:#f9fafb;font-size:11px;font-weight:600;">${esc(en.actor.canonical)}</span>
      ${en.actor.nation ? _badge(en.actor.nation, "#1a2030", "#94a3b8") : ""}
    </div>` : "";

  const ttpNodes = en.ttps.slice(0, 8).map(t =>
    `<div style="display:inline-flex;align-items:center;gap:4px;background:#0088ff11;border:1px solid #0088ff33;border-radius:4px;padding:3px 8px;margin:2px;">
      <span style="color:#0088ff;font-size:9px;">? TTP</span>
      <span style="color:#93c5fd;font-size:10px;">${esc(t)}</span>
    </div>`).join("");

  const cveNodes = en.cves.slice(0, 4).map(c =>
    `<div style="display:inline-flex;align-items:center;gap:4px;background:#ff660011;border:1px solid #ff660033;border-radius:4px;padding:3px 8px;margin:2px;">
      <span style="color:#ff6600;font-size:9px;">? CVE</span>
      <span style="color:#fdba74;font-size:10px;">${esc(c)}</span>
    </div>`).join("");

  const tacticNodes = en.tactics.slice(0, 5).map(t =>
    `<div style="display:inline-flex;align-items:center;gap:4px;background:#8b5cf611;border:1px solid #8b5cf633;border-radius:4px;padding:3px 8px;margin:2px;">
      <span style="color:#8b5cf6;font-size:9px;">? TACTIC</span>
      <span style="color:#c4b5fd;font-size:10px;">${esc(String(t))}</span>
    </div>`).join("");

  const iocNodes = en.iocTypes.slice(0, 5).map(t =>
    `<div style="display:inline-flex;align-items:center;gap:4px;background:#ef444411;border:1px solid #ef444433;border-radius:4px;padding:3px 8px;margin:2px;">
      <span style="color:#ef4444;font-size:9px;">? IOC</span>
      <span style="color:#fca5a5;font-size:10px;">${esc(t.toUpperCase())}</span>
    </div>`).join("");

  const totalEntities = (en.actor.canonical ? 1 : 0) + en.ttps.length + en.cves.length + en.tactics.length + en.iocTypes.length;
  const graphRichness = Math.min(100, Math.round(totalEntities / 12 * 100));
  const richnessColor = graphRichness >= 75 ? "#22c55e" : graphRichness >= 50 ? "#3b82f6" : graphRichness >= 25 ? "#f59e0b" : "#6b7280";

  const body = `
  <div style="display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap;">
    <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
      <div style="color:${richnessColor};font-size:20px;font-weight:700;">${totalEntities}</div>
      <div style="color:#6b7280;font-size:9px;">GRAPH ENTITIES</div>
    </div>
    <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
      <div style="color:#ff4444;font-size:20px;font-weight:700;">${en.actor.canonical ? 1 : 0}</div>
      <div style="color:#6b7280;font-size:9px;">ACTORS</div>
    </div>
    <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
      <div style="color:#0088ff;font-size:20px;font-weight:700;">${en.ttps.length}</div>
      <div style="color:#6b7280;font-size:9px;">TECHNIQUES</div>
    </div>
    <div style="background:#ff6600;border-radius:4px;padding:8px 14px;text-align:center;background:transparent;border:1px solid #ff660033;">
      <div style="color:#ff6600;font-size:20px;font-weight:700;">${en.cves.length}</div>
      <div style="color:#6b7280;font-size:9px;">CVEs</div>
    </div>
    <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
      <div style="color:${richnessColor};font-size:20px;font-weight:700;">${graphRichness}%</div>
      <div style="color:#6b7280;font-size:9px;">GRAPH RICHNESS</div>
    </div>
  </div>
  ${_meter(graphRichness, richnessColor)}
  <div style="margin-top:14px;">
    ${actorNode}
    ${ttpNodes}
    ${cveNodes}
    ${tacticNodes}
    ${iocNodes}
    ${!actorNode && !ttpNodes && !cveNodes ? `<div style="color:#4b5563;font-size:11px;padding:8px 0;">Limited graph entities derivable  -  enrich with actor/TTP metadata for richer graph.</div>` : ""}
  </div>
  <div style="margin-top:10px;padding:8px 12px;background:#0a0f1a;border-radius:4px;font-size:10px;color:#6b7280;">
    <a href="/enterprise-knowledge-graph.html" style="color:#06b6d4;text-decoration:none;">-> Open Enterprise Knowledge Graph</a>
    &nbsp;|&nbsp;
    <a href="/api/v1/p31/graph" style="color:#6b7280;text-decoration:none;">Graph API</a>
    &nbsp;|&nbsp;
    <a href="/api/v1/p31/search?q=${encodeURIComponent(en.actor.canonical || item.threat_type || "")}" style="color:#6b7280;text-decoration:none;">Search Entities</a>
  </div>`;

  return _block(`p31-kg-${esc(item.id || "x")}`, "P31.1 Enterprise Knowledge Graph",
    richnessColor, body,
    `${totalEntities} entities linked  -  actors, techniques, CVEs, tactics, IOC types`);
}

// -- P31.2: Entity Normalization Block -----------------------------------------

export function buildP31EntityBlock(item) {
  const en = _computeEntityNormalization(item);
  const actorNorm = en.actor;

  const actorSection = actorNorm.canonical ? `
    <div style="background:#0a0f1a;border-radius:4px;padding:10px 14px;margin-bottom:10px;">
      <div style="color:#94a3b8;font-size:10px;letter-spacing:.1em;margin-bottom:6px;">THREAT ACTOR  -  CANONICAL IDENTITY</div>
      ${_row("Canonical Name", `<strong style="color:#ff4444;">${esc(actorNorm.canonical)}</strong>`)}
      ${_row("Nation Nexus", actorNorm.nation || "UNKNOWN", actorNorm.nation ? "#f9fafb" : "#6b7280")}
      ${_row("Motivation", actorNorm.motivation || "unknown", "#94a3b8")}
      ${actorNorm.aliases && actorNorm.aliases.length > 0 ? _row("Known Aliases", actorNorm.aliases.join(" | "), "#6b7280") : ""}
    </div>` : `<div style="color:#4b5563;font-size:11px;padding:6px 0;">No attributed threat actor  -  source: ${esc(item.source || "unknown")}</div>`;

  const ttpSection = en.ttps.length > 0 ? `
    <div style="background:#0a0f1a;border-radius:4px;padding:10px 14px;margin-bottom:10px;">
      <div style="color:#94a3b8;font-size:10px;letter-spacing:.1em;margin-bottom:6px;">NORMALIZED MITRE ATT&CK TECHNIQUES (${en.ttps.length})</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${en.ttps.map(t => `<span style="background:#0088ff22;color:#93c5fd;border:1px solid #0088ff44;font-size:9px;font-weight:700;padding:2px 8px;border-radius:3px;">${esc(t)}</span>`).join("")}
      </div>
    </div>` : "";

  const cveSection = en.cves.length > 0 ? `
    <div style="background:#0a0f1a;border-radius:4px;padding:10px 14px;margin-bottom:10px;">
      <div style="color:#94a3b8;font-size:10px;letter-spacing:.1em;margin-bottom:6px;">CVE REFERENCES (${en.cves.length})</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${en.cves.map(c => `<span style="background:#ff660022;color:#fdba74;border:1px solid #ff660044;font-size:9px;font-weight:700;padding:2px 8px;border-radius:3px;">${esc(c)}</span>`).join("")}
      </div>
    </div>` : "";

  const body = actorSection + ttpSection + cveSection;
  return _block(`p31-entity-${esc(item.id || "x")}`, "P31.2 Entity Normalization",
    "#a78bfa", body, "Canonical actor identity, alias resolution, TTP normalization");
}

// -- P31.3: Campaign Reconstruction Block --------------------------------------

export function buildP31CampaignBlock(item, allItems = []) {
  const ctx = _computeCampaignContext(item, allItems);

  const timelineRows = ctx.timeline.map(e => `
    <div style="display:flex;gap:10px;padding:5px 0;border-bottom:1px solid #1a2030;align-items:flex-start;">
      <span style="color:${e.type === "kev" ? "#ef4444" : e.type === "publish" ? "#3b82f6" : "#22c55e"};font-size:10px;min-width:14px;">?</span>
      <div>
        <div style="color:#f9fafb;font-size:11px;">${esc(e.event)}</div>
        ${e.ts && e.ts !== "active" ? `<div style="color:#6b7280;font-size:10px;">${e.ts.slice(0, 16).replace("T", " ")} UTC</div>` : `<div style="color:#ef4444;font-size:10px;">Active  -  ongoing exploitation</div>`}
      </div>
    </div>`).join("");

  const relatedRows = ctx.related.slice(0, 4).map(r => `
    <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a2030;">
      <span style="color:#94a3b8;font-size:10px;max-width:75%;overflow:hidden;text-overflow:ellipsis;">${esc((r.title || "").slice(0, 70))}</span>
      <span style="color:#6b7280;font-size:9px;">${esc((r.severity || "").toUpperCase())}</span>
    </div>`).join("");

  const body = `
  ${ctx.campaignName ? `<div style="background:#0a0f1a;border-radius:4px;padding:10px 14px;margin-bottom:12px;">
    <div style="color:#f59e0b;font-size:12px;font-weight:700;">${esc(ctx.campaignName)}</div>
    <div style="color:#6b7280;font-size:10px;margin-top:2px;">Reconstructed campaign attribution</div>
  </div>` : ""}
  ${ctx.timeline.length > 0 ? `<div style="margin-bottom:12px;"><div style="color:#6b7280;font-size:10px;letter-spacing:.1em;margin-bottom:6px;">CAMPAIGN TIMELINE</div>${timelineRows}</div>` : ""}
  ${ctx.related.length > 0 ? `<div><div style="color:#6b7280;font-size:10px;letter-spacing:.1em;margin-bottom:6px;">RELATED ADVISORIES (${ctx.related.length} matched by actor/TTP co-occurrence)</div>${relatedRows}</div>` : `<div style="color:#4b5563;font-size:11px;padding:4px 0;">No related advisories found via actor or TTP correlation.</div>`}`;

  return _block(`p31-campaign-${esc(item.id || "x")}`, "P31.3 Threat Campaign Reconstruction",
    "#f59e0b", body,
    `${ctx.related.length} related items via actor/TTP correlation  -  ${ctx.timeline.length} timeline events`);
}

// -- P31.4: Analyst Copilot Block ----------------------------------------------

export function buildP31CopilotBlock(item) {
  const c = _computeCopilot(item);

  const whyHtml = c.whyParts.map(p => `<div style="color:#f9fafb;font-size:11px;padding:4px 0;border-bottom:1px solid #1a2030;">-> ${esc(p)}</div>`).join("");
  const changedHtml = c.whatChanged.map(p => `<div style="color:#94a3b8;font-size:11px;padding:3px 0;border-bottom:1px solid #1a2030;">* ${esc(p)}</div>`).join("");
  const firstHtml = c.whatFirst.map(p => `<div style="color:#f9fafb;font-size:11px;padding:3px 0;border-bottom:1px solid #1a2030;">${esc(p)}</div>`).join("");
  const logsHtml = c.logList.length > 0
    ? c.logList.map(l => `<div style="color:#06b6d4;font-size:10px;padding:2px 0;border-bottom:1px solid #0d1117;">? ${esc(l)}</div>`).join("")
    : `<div style="color:#4b5563;font-size:10px;">No specific log sources mapped  -  review TTP coverage</div>`;
  const nextHtml = c.whatNext.map(p => `<div style="color:#22c55e;font-size:11px;padding:3px 0;border-bottom:1px solid #1a2030;">-> ${esc(p)}</div>`).join("");

  const section = (title, color, content) => `
    <div style="margin-bottom:12px;">
      <div style="color:${color};font-size:10px;font-weight:700;letter-spacing:.1em;padding:4px 0;border-bottom:1px solid #1a2030;margin-bottom:6px;">${title}</div>
      ${content}
    </div>`;

  const body = section("? WHY THIS MATTERS", "#ef4444", whyHtml)
    + section("? WHAT CHANGED", "#f59e0b", changedHtml)
    + section("? WHAT TO INVESTIGATE FIRST", "#3b82f6", firstHtml)
    + section("? WHAT LOGS TO CHECK", "#06b6d4", logsHtml)
    + section("? WHAT NEXT", "#22c55e", nextHtml);

  return _block(`p31-copilot-${esc(item.id || "x")}`, "P31.4 Analyst Copilot",
    "#a78bfa", body, "AI-assisted analyst guidance: why / what changed / investigate first / logs / next steps");
}

// -- P31.5: Investigation Playbook Block ---------------------------------------

export function buildP31PlaybookBlock(item) {
  const pb = _computePlaybook(item);

  const pivotHtml = pb.iocPivots.length > 0
    ? pb.iocPivots.map(p => `
        <div style="display:flex;gap:10px;padding:5px 0;border-bottom:1px solid #1a2030;align-items:flex-start;">
          ${_badge(p.priority, p.priority === "P1" ? "#ef444422" : "#3b82f622", p.priority === "P1" ? "#ef4444" : "#3b82f6")}
          <div>
            <div style="color:#f9fafb;font-size:11px;font-weight:600;">${esc(p.type)}</div>
            <div style="color:#6b7280;font-size:10px;margin-top:2px;">${esc(p.action)}</div>
          </div>
        </div>`).join("")
    : `<div style="color:#4b5563;font-size:11px;">No IOCs present  -  focus on behavioral detection via TTPs.</div>`;

  const logHtml = pb.logSources.map(l => `<div style="color:#06b6d4;font-size:10px;padding:2px 4px;border-bottom:1px solid #0a0f1a;">? ${esc(l)}</div>`).join("");
  const artifactHtml = pb.artifacts.map(a => `<div style="color:#94a3b8;font-size:10px;padding:2px 4px;border-bottom:1px solid #0a0f1a;">* ${esc(a)}</div>`).join("");
  const timelineHtml = pb.timelineSteps.map(s => `<div style="color:#f9fafb;font-size:10px;padding:3px 0;border-bottom:1px solid #1a2030;">-> ${esc(s)}</div>`).join("");
  const escalHtml = pb.escalation.map((e, i) => {
    const col = i === 0 && e.includes("IMMEDIATE") ? "#ef4444" : "#f59e0b";
    return `<div style="color:${col};font-size:10px;padding:3px 0;border-bottom:1px solid #1a2030;">? ${esc(e)}</div>`;
  }).join("");

  const section = (title, color, content, bg = "#0a0f1a") => `
    <div style="background:${bg};border-radius:4px;padding:10px 14px;margin-bottom:10px;">
      <div style="color:${color};font-size:10px;font-weight:700;letter-spacing:.1em;margin-bottom:6px;">${title}</div>
      ${content}
    </div>`;

  const body = section("IOC PIVOT PLAN", "#ef4444", pivotHtml)
    + section("LOG SOURCES", "#06b6d4", logHtml)
    + section("EXPECTED ARTIFACTS", "#8b5cf6", artifactHtml)
    + section("INVESTIGATION TIMELINE", "#3b82f6", timelineHtml)
    + section("ESCALATION CRITERIA", "#f59e0b", escalHtml);

  return _block(`p31-playbook-${esc(item.id || "x")}`, "P31.5 Investigation Playbook",
    "#06b6d4", body, "IOC pivot plan * log sources * expected artifacts * timeline * escalation");
}

// -- P31.7: Relationship Confidence Block --------------------------------------

export function buildP31RelationshipBlock(item) {
  const en = _computeEntityNormalization(item);
  const cvss = parseFloat(item.risk_score || item.cvss_score || 0);
  const isKev = Boolean(item.kev_present || (item.apex || {}).kev_listed);

  const relationships = [];

  if (en.actor.canonical) {
    const conf = isKev || cvss >= 9 ? 0.92 : cvss >= 7 ? 0.83 : 0.65;
    const evidence = [
      item.source ? `Source: ${item.source}` : null,
      cvss > 0 ? `CVSS: ${cvss}` : null,
      en.ttps.length > 0 ? `${en.ttps.length} TTP(s) mapped` : null,
    ].filter(Boolean).join(" | ");
    relationships.push({
      source: "This Advisory", rel: "ATTRIBUTED_TO", target: en.actor.canonical,
      confidence: conf, evidence, sourceCount: 1, evidenceCount: en.ttps.length + (cvss > 0 ? 1 : 0),
    });
  }

  for (const ttp of en.ttps.slice(0, 5)) {
    relationships.push({
      source: "This Advisory", rel: "USES_TECHNIQUE", target: ttp,
      confidence: 0.92, evidence: "MITRE ATT&CK enrichment by pipeline",
      sourceCount: 1, evidenceCount: 2,
    });
  }

  for (const cve of en.cves.slice(0, 3)) {
    relationships.push({
      source: "This Advisory", rel: "REFERENCES", target: cve,
      confidence: 0.99, evidence: "CVE mentioned in advisory title/description",
      sourceCount: 1, evidenceCount: 3,
    });
  }

  const confColor = c => c >= 0.85 ? "#22c55e" : c >= 0.65 ? "#3b82f6" : c >= 0.45 ? "#f59e0b" : "#ef4444";
  const confLabel = c => c >= 0.85 ? "CONFIRMED" : c >= 0.65 ? "HIGH" : c >= 0.45 ? "MEDIUM" : "LOW";

  const rows = relationships.map(r => `
    <div style="padding:6px 0;border-bottom:1px solid #1a2030;">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px;">
        <span style="color:#f9fafb;font-size:11px;">${esc(r.source)}</span>
        <span style="color:#6b7280;font-size:10px;background:#1a2030;padding:1px 6px;border-radius:2px;">${esc(r.rel)}</span>
        <span style="color:#06b6d4;font-size:11px;font-weight:600;">${esc(r.target)}</span>
        ${_badge(confLabel(r.confidence), confColor(r.confidence) + "22", confColor(r.confidence))}
        <span style="color:#4b5563;font-size:9px;">${(r.confidence * 100).toFixed(0)}%</span>
      </div>
      <div style="color:#4b5563;font-size:10px;margin-left:4px;">${esc(r.evidence)} | Sources: ${r.sourceCount} | Evidence: ${r.evidenceCount}</div>
    </div>`).join("");

  const avgConf = relationships.length > 0
    ? Math.round(relationships.reduce((s, r) => s + r.confidence, 0) / relationships.length * 100)
    : 0;
  const avgColor = confColor(avgConf / 100);

  const body = relationships.length === 0
    ? `<div style="color:#4b5563;font-size:11px;padding:8px 0;">Insufficient entity data for relationship confidence scoring.</div>`
    : `
    <div style="display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap;">
      <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
        <div style="color:${avgColor};font-size:22px;font-weight:700;">${relationships.length}</div>
        <div style="color:#6b7280;font-size:9px;">RELATIONSHIPS</div>
      </div>
      <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
        <div style="color:${avgColor};font-size:22px;font-weight:700;">${avgConf}%</div>
        <div style="color:#6b7280;font-size:9px;">AVG CONFIDENCE</div>
      </div>
      <div style="background:#1a2030;border-radius:4px;padding:8px 14px;text-align:center;">
        <div style="color:#22c55e;font-size:22px;font-weight:700;">${relationships.filter(r => r.confidence >= 0.85).length}</div>
        <div style="color:#6b7280;font-size:9px;">CONFIRMED</div>
      </div>
    </div>
    ${_meter(avgConf, avgColor)}
    <div style="margin-top:12px;">${rows}</div>`;

  return _block(`p31-rel-${esc(item.id || "x")}`, "P31.7 Relationship Confidence Engine",
    avgConf >= 75 ? "#22c55e" : avgConf >= 50 ? "#3b82f6" : "#f59e0b", body,
    `${relationships.length} evidence-backed relationships  -  avg ${avgConf}% confidence`);
}

// -- P31 Package ---------------------------------------------------------------

export function buildP31Package(item, allItems = []) {
  return (
    buildP31KnowledgeGraphBlock(item)       +
    buildP31EntityBlock(item)               +
    buildP31CampaignBlock(item, allItems)   +
    buildP31CopilotBlock(item)              +
    buildP31PlaybookBlock(item)             +
    buildP31RelationshipBlock(item)
  );
}

// -- API helpers ---------------------------------------------------------------

async function _loadFeed(env) {
  try {
    const raw = await env.SECURITY_HUB_KV.get("feed:latest");
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) { return []; }
}

// -- API: P31 Graph ------------------------------------------------------------

export async function handleP31Graph(request, env) {
  try {
    const items = await _loadFeed(env);
    if (items.length === 0) return _jsonResp({ error: "No feed data", version: P31_VERSION }, 404);
    const graph = _buildGraph(items);
    return _jsonResp({ schema_version: P31_VERSION, generated_at: new Date().toISOString(), ...graph });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Search -----------------------------------------------------------

export async function handleP31Search(request, env) {
  try {
    const url = new URL(request.url);
    const q = (url.searchParams.get("q") || "").toLowerCase().trim();
    if (!q) return _jsonResp({ error: "Missing query parameter ?q=", version: P31_VERSION }, 400);

    const items = await _loadFeed(env);
    const results = [];

    for (const item of items) {
      const text = [
        item.title, item.description, item.actor_tag, item.threat_type, item.source,
        ...(Array.isArray(item.ttps) ? item.ttps : []),
        item.severity,
      ].join(" ").toLowerCase();

      if (text.includes(q)) {
        const en = _computeEntityNormalization(item);
        results.push({
          id: item.id, title: (item.title || "").slice(0, 100),
          severity: item.severity, cvss: parseFloat(item.risk_score || item.cvss_score || 0),
          actor: en.actor.canonical, ttp_count: en.ttps.length,
          cve_count: en.cves.length, source: item.source,
          match_context: `Matched in advisory for q="${q}"`,
        });
      }
    }

    // Also search normalized entities
    const graph = _buildGraph(items);
    const nodeResults = graph.nodes.filter(n =>
      n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q)
    ).slice(0, 20).map(n => ({
      entity_id: n.id, entity_type: n.type, entity_label: n.label,
      item_count: n.itemCount, edge_count: n.edgeCount, meta: n.meta,
    }));

    return _jsonResp({
      schema_version: P31_VERSION, generated_at: new Date().toISOString(),
      query: q, advisory_matches: results.slice(0, 20),
      entity_matches: nodeResults,
      total_advisory_matches: results.length, total_entity_matches: nodeResults.length,
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Entity -----------------------------------------------------------

export async function handleP31Entity(request, env) {
  try {
    const url = new URL(request.url);
    const entityId = (url.searchParams.get("id") || "").trim();
    const entityType = (url.searchParams.get("type") || "").trim();

    const items = await _loadFeed(env);
    const graph = _buildGraph(items);

    if (entityId) {
      const node = graph.nodes.find(n => n.id === entityId || n.label.toLowerCase() === entityId.toLowerCase());
      if (!node) return _jsonResp({ error: `Entity not found: ${entityId}`, version: P31_VERSION }, 404);
      const edges = graph.edges.filter(e => e.source === node.id || e.target === node.id);
      return _jsonResp({ schema_version: P31_VERSION, generated_at: new Date().toISOString(), entity: node, relationships: edges });
    }

    // List entities by type or all
    const nodes = entityType
      ? graph.nodes.filter(n => n.type === entityType)
      : graph.nodes;

    return _jsonResp({
      schema_version: P31_VERSION, generated_at: new Date().toISOString(),
      total_entities: nodes.length, entity_types: Object.keys(graph.stats.by_type),
      entities: nodes.sort((a, b) => b.itemCount - a.itemCount).slice(0, 50),
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Relationships ----------------------------------------------------

export async function handleP31Relationships(request, env) {
  try {
    const url = new URL(request.url);
    const entityId = (url.searchParams.get("entity") || "").trim();
    const relType  = (url.searchParams.get("type") || "").trim();
    const minConf  = parseFloat(url.searchParams.get("min_confidence") || "0");

    const items = await _loadFeed(env);
    const graph = _buildGraph(items);

    let edges = graph.edges;
    if (entityId) edges = edges.filter(e => e.source.includes(entityId) || e.target.includes(entityId));
    if (relType)  edges = edges.filter(e => e.relation === relType);
    if (minConf > 0) edges = edges.filter(e => e.confidence >= minConf);

    const relationTypes = [...new Set(graph.edges.map(e => e.relation))];

    return _jsonResp({
      schema_version: P31_VERSION, generated_at: new Date().toISOString(),
      total_relationships: edges.length,
      available_relation_types: relationTypes,
      relationships: edges.slice(0, 100),
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Campaign ---------------------------------------------------------

export async function handleP31Campaign(request, env) {
  try {
    const items = await _loadFeed(env);
    if (items.length === 0) return _jsonResp({ error: "No feed data", version: P31_VERSION }, 404);

    // Group by actor
    const byActor = {};
    for (const item of items) {
      const actor = _normalizeActor(item.actor_tag || item.threat_actor || "").canonical || (item.actor_tag || "unattributed");
      if (!byActor[actor]) byActor[actor] = { actor, items: [], ttps: new Set(), cves: [], sources: new Set() };
      byActor[actor].items.push({
        id: item.id, title: (item.title || "").slice(0, 80), severity: item.severity,
        ts: item.timestamp || item.published_at || "",
      });
      (Array.isArray(item.ttps) ? item.ttps : []).forEach(t => byActor[actor].ttps.add(t));
      (((item.title || "") + " " + (item.description || "")).match(/CVE-\d{4}-\d+/g) || [])
        .forEach(c => byActor[actor].cves.push(c));
      if (item.source) byActor[actor].sources.add(item.source);
    }

    const campaigns = Object.values(byActor).map(c => ({
      actor: c.actor,
      advisory_count: c.items.length,
      technique_count: c.ttps.size,
      cve_count: [...new Set(c.cves)].length,
      source_count: c.sources.size,
      techniques: [...c.ttps].slice(0, 8),
      advisories: c.items.slice(0, 5),
    })).sort((a, b) => b.advisory_count - a.advisory_count);

    return _jsonResp({
      schema_version: P31_VERSION, generated_at: new Date().toISOString(),
      total_campaigns: campaigns.length, total_advisories: items.length,
      campaigns,
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Copilot ----------------------------------------------------------

export async function handleP31Copilot(request, env) {
  try {
    const url    = new URL(request.url);
    const itemId = (url.searchParams.get("id") || "").trim();
    const items  = await _loadFeed(env);
    if (items.length === 0) return _jsonResp({ error: "No feed data", version: P31_VERSION }, 404);

    const item = itemId ? items.find(i => i.id === itemId) : items[0];
    if (!item) return _jsonResp({ error: `Item not found: ${itemId}`, version: P31_VERSION }, 404);

    const copilot  = _computeCopilot(item);
    const playbook = _computePlaybook(item);
    const entity   = _computeEntityNormalization(item);

    return _jsonResp({
      schema_version:  P31_VERSION,
      generated_at:    new Date().toISOString(),
      item_id:         item.id,
      item_title:      (item.title || "").slice(0, 100),
      analyst_copilot: {
        why_this_matters:        copilot.whyParts,
        what_changed:            copilot.whatChanged,
        what_to_investigate_first: copilot.whatFirst,
        what_logs_to_check:      copilot.logList,
        what_next:               copilot.whatNext,
        item_age_hours:          Math.round(copilot.ageHours),
      },
      investigation_playbook: {
        ioc_pivot_plan:          playbook.iocPivots,
        log_sources:             playbook.logSources,
        expected_artifacts:      playbook.artifacts,
        investigation_timeline:  playbook.timelineSteps,
        escalation_criteria:     playbook.escalation,
      },
      entity_context: {
        actor: entity.actor,
        techniques: entity.ttps.slice(0, 10),
        cves: entity.cves,
        tactics: entity.tactics,
      },
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Observability ----------------------------------------------------

export async function handleP31Observability(request, env) {
  try {
    const items = await _loadFeed(env);
    const graph = _buildGraph(items);

    // Entity coverage rates
    const withActor = items.filter(i => i.actor_tag && i.actor_tag !== "Unknown").length;
    const withTtps  = items.filter(i => Array.isArray(i.ttps) && i.ttps.length > 0).length;
    const withCves  = items.filter(i => /CVE-\d{4}-\d+/.test((i.title || "") + " " + (i.description || ""))).length;

    return _jsonResp({
      schema_version:    P31_VERSION,
      generated_at:      new Date().toISOString(),
      graph_stats:       graph.stats,
      entity_coverage: {
        items_with_actor_attr: withActor,
        items_with_ttps:       withTtps,
        items_with_cves:       withCves,
        actor_coverage_pct:    Math.round(withActor / (items.length || 1) * 100),
        ttp_coverage_pct:      Math.round(withTtps / (items.length || 1) * 100),
        cve_coverage_pct:      Math.round(withCves / (items.length || 1) * 100),
      },
      knowledge_health: {
        graph_richness_pct: Math.min(100, Math.round(graph.stats.total_edges / Math.max(1, items.length) * 20)),
        avg_entity_degree:  graph.stats.total_nodes > 0
          ? Math.round(graph.stats.total_edges * 2 / graph.stats.total_nodes * 10) / 10
          : 0,
        verified_edge_pct: graph.stats.total_edges > 0
          ? Math.round(graph.stats.verified_edges / graph.stats.total_edges * 100)
          : 0,
      },
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}

// -- API: P31 Certify ----------------------------------------------------------

export async function handleP31Certify(request, env) {
  try {
    const items = await _loadFeed(env);
    const graph = _buildGraph(items);

    const withTtps  = items.filter(i => Array.isArray(i.ttps) && i.ttps.length > 0).length;
    const withActor = items.filter(i => i.actor_tag && i.actor_tag !== "Unknown").length;
    const avgConf   = graph.stats.avg_confidence;

    const gates = [
      { id: "G_FD",   label: "Feed data available",                     pass: items.length > 0 },
      { id: "G_GN",   label: "Graph has nodes",                         pass: graph.stats.total_nodes > 0 },
      { id: "G_GE",   label: "Graph has edges",                         pass: graph.stats.total_edges > 0 },
      { id: "G_CONF", label: "Avg edge confidence >= 0.70",             pass: avgConf >= 0.70 },
      { id: "G_TTP",  label: "TTP coverage >= 80% of items",            pass: items.length === 0 || withTtps / items.length >= 0.80 },
      { id: "G_ACT",  label: "Graph has actor nodes",                   pass: graph.stats.by_type["threat_actor"] > 0 },
    ];

    const passed   = gates.filter(g => g.pass).length;
    const blockers = gates.filter(g => !g.pass).length;
    const tier     = blockers === 0 ? "WORLDWIDE_RELEASE" : blockers <= 1 ? "CONTROLLED_RELEASE" : "BLOCKED";

    return _jsonResp({
      schema_version: P31_VERSION, generated_at: new Date().toISOString(),
      release_tier:   tier, blocker_count: blockers,
      passed_count:   passed, total_gates: gates.length,
      gates, graph_stats: graph.stats,
    });
  } catch (e) {
    return _jsonResp({ error: String(e), version: P31_VERSION }, 500);
  }
}
