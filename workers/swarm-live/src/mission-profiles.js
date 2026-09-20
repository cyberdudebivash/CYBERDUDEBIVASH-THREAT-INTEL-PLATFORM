// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX — MISSION PROFILES
// V4.47.0
//
// Profiles select which existing real agents are expected to execute. They do
// not invent capabilities, findings, or backend routes.
// =============================================================================

export const MISSION_PROFILES = Object.freeze({
  AUTO: Object.freeze({
    label: 'Auto / Full Fabric',
    agents: Object.freeze([
      'ioc-hunter','cve-intelligence','threat-hunter','attack-mapper',
      'siem-defender','ir-playbook','exposure-analyst','risk-synthesizer',
    ]),
  }),
  FULL_CTI_FABRIC: Object.freeze({
    label: 'Full CTI Fabric',
    agents: Object.freeze([
      'ioc-hunter','cve-intelligence','threat-hunter','attack-mapper',
      'siem-defender','ir-playbook','exposure-analyst','risk-synthesizer',
    ]),
  }),
  IOC_TRIAGE: Object.freeze({
    label: 'IOC Triage',
    agents: Object.freeze([
      'ioc-hunter','threat-hunter','attack-mapper','siem-defender','risk-synthesizer',
    ]),
  }),
  CVE_RESPONSE: Object.freeze({
    label: 'CVE Response',
    agents: Object.freeze([
      'ioc-hunter','cve-intelligence','siem-defender','ir-playbook','exposure-analyst','risk-synthesizer',
    ]),
  }),
  THREAT_ACTOR_INVESTIGATION: Object.freeze({
    label: 'Threat Actor Investigation',
    agents: Object.freeze([
      'ioc-hunter','threat-hunter','attack-mapper','siem-defender','risk-synthesizer',
    ]),
  }),
  SOC_DETECTION_ENGINEERING: Object.freeze({
    label: 'SOC Detection Engineering',
    agents: Object.freeze([
      'ioc-hunter','attack-mapper','siem-defender','risk-synthesizer',
    ]),
  }),
  INCIDENT_RESPONSE: Object.freeze({
    label: 'Incident Response',
    agents: Object.freeze([
      'ioc-hunter','threat-hunter','attack-mapper','ir-playbook','exposure-analyst','risk-synthesizer',
    ]),
  }),
  EXPOSURE_ASSESSMENT: Object.freeze({
    label: 'Exposure Assessment',
    agents: Object.freeze([
      'ioc-hunter','cve-intelligence','exposure-analyst','risk-synthesizer',
    ]),
  }),
  EXECUTIVE_RISK: Object.freeze({
    label: 'Executive Risk',
    agents: Object.freeze([
      'ioc-hunter','cve-intelligence','threat-hunter','exposure-analyst','risk-synthesizer',
    ]),
  }),
});

export function normalizeMissionProfile(value) {
  const normalized = String(value || 'AUTO').trim().toUpperCase().replace(/[\s-]+/g, '_');
  return Object.prototype.hasOwnProperty.call(MISSION_PROFILES, normalized) ? normalized : null;
}

export function resolveMissionProfile(value) {
  const id = normalizeMissionProfile(value);
  if (!id) return null;
  return Object.freeze({ id, ...MISSION_PROFILES[id] });
}

export function profileIncludesAgent(profile, agentId) {
  const resolved = typeof profile === 'string' ? resolveMissionProfile(profile) : profile;
  return Boolean(resolved?.agents?.includes(agentId));
}

export function listMissionProfiles() {
  return Object.entries(MISSION_PROFILES).map(([id, value]) => ({
    id,
    label: value.label,
    agent_count: value.agents.length,
    agents: [...value.agents],
  }));
}
