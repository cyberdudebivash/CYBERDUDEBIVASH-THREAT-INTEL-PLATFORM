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
