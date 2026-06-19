export type ThreatLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface MitreTactic {
  id: string;
  name: string;
  tactic: string;
}

export interface ThreatActor {
  id: string;
  slug: string;
  display_name: string;
  aliases: readonly string[];
  mitre_id: string | null;
  country: string;
  sponsor: string;
  motivation: readonly string[];
  sectors_targeted: readonly string[];
  primary_ttps: readonly string[];
  malware: readonly string[];
  active_since: string;
  last_active: string;
  threat_level: ThreatLevel;
  description: string;
  profile_url: string;
  is_ransomware: boolean;
}

export interface CveRecord {
  id: string;
  slug: string;
  severity: Severity;
  cvss_score: number | null;
  epss_score: number | null;
  kev_present: boolean;
  published_at: string;
  source_url: string;
  risk_score: number;
  advisory_count: number;
  mitre_tactics: MitreTactic[];
}

export type IocType = "ip" | "domain" | "hash_sha256" | "url";
export type ConfidenceLevel = "HIGH" | "MEDIUM" | "LOW";
export type TlpLevel = "GREEN" | "AMBER" | "WHITE";

export interface IocRecord {
  id: string;
  slug: string;
  type: IocType;
  value: string;
  threat_type: string;
  threat_actor: string | null;
  malware_family: string | null;
  confidence: ConfidenceLevel;
  severity: Severity;
  first_seen: string;
  last_seen: string;
  tags: readonly string[];
  source: string;
  mitre_tactics: MitreTactic[];
  tlp: TlpLevel;
  description: string;
}
