/**
 * WEB3 MODULE — TYPE DEFINITIONS
 * Place at: /web3/types/index.ts
 */

// ─── RISK SCORING ─────────────────────────────────────────────────────────────
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RiskScore {
  score: number;           // 0–100
  level: RiskLevel;
  factors: RiskFactor[];
  calculatedAt: string;   // ISO timestamp
}

export interface RiskFactor {
  id: string;
  label: string;
  weight: number;         // contribution to overall score
  description: string;
}

// ─── WALLET INTELLIGENCE ──────────────────────────────────────────────────────
export type WalletTag =
  | 'scam'
  | 'mixer'
  | 'exchange'
  | 'whale'
  | 'phishing'
  | 'rug-pull'
  | 'sanctioned'
  | 'defi'
  | 'nft'
  | 'mev-bot'
  | 'unknown';

export interface WalletAnalysis {
  address: string;
  network: string;
  risk: RiskScore;
  tags: WalletTag[];
  balance: {
    eth: string;
    usd: string;
  };
  transactionCount: number;
  firstSeen: string;
  lastSeen: string;
  summary: string;
  relatedAddresses: string[];
  analysedAt: string;
  source: 'etherscan' | 'alchemy' | 'mock';
}

// ─── CONTRACT SCANNER ─────────────────────────────────────────────────────────
export type VulnSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ContractVulnerability {
  id: string;
  name: string;
  severity: VulnSeverity;
  description: string;
  recommendation: string;
  lineRef?: string;
  cwe?: string;           // CWE reference
}

export type VulnCategory =
  | 'reentrancy'
  | 'access-control'
  | 'honeypot'
  | 'overflow'
  | 'delegatecall'
  | 'frontrunning'
  | 'tx-origin'
  | 'unchecked-return'
  | 'timestamp-dependence';

export interface ContractScanResult {
  address?: string;
  network?: string;
  contractName?: string;
  vulnerabilities: ContractVulnerability[];
  riskScore: number;
  riskLevel: RiskLevel;
  isHoneypot: boolean;
  isVerified: boolean;
  detectedPatterns: VulnCategory[];
  summary: string;
  scannedAt: string;
}

// ─── THREAT FEED ──────────────────────────────────────────────────────────────
export type ThreatCategory =
  | 'rug-pull'
  | 'exploit'
  | 'phishing'
  | 'malicious-wallet'
  | 'flash-loan-attack'
  | 'bridge-hack'
  | 'oracle-manipulation'
  | 'governance-attack'
  | 'private-key-compromise';

export interface Web3ThreatEntry {
  id: string;
  title: string;
  category: ThreatCategory;
  severity: VulnSeverity;
  description: string;
  affectedProtocol?: string;
  affectedAddresses: string[];
  lossUSD?: number;
  network: string;
  exploitTxHash?: string;
  sourceUrl?: string;
  publishedAt: string;
  iocs: string[];         // Indicators of Compromise
  tags: string[];
}

// ─── TRANSACTION MONITOR ─────────────────────────────────────────────────────
export type TxAlertType =
  | 'large-transfer'
  | 'mixer-interaction'
  | 'known-scammer'
  | 'rapid-drain'
  | 'unusual-pattern';

export interface SuspiciousTransaction {
  hash: string;
  from: string;
  to: string;
  valueETH: string;
  valueUSD: string;
  network: string;
  blockNumber: number;
  timestamp: string;
  alertType: TxAlertType;
  alertMessage: string;
  riskScore: number;
}

// ─── DASHBOARD SUMMARY ────────────────────────────────────────────────────────
export interface Web3DashboardStats {
  highRiskWallets: number;
  latestThreats: number;
  suspiciousTransactions: number;
  highRiskContracts: number;
  totalLossUSD: number;
  lastUpdated: string;
}

// ─── API RESPONSE WRAPPER ────────────────────────────────────────────────────
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}
