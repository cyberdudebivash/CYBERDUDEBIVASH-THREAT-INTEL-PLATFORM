/**
 * RISK SCORING ENGINE
 * ====================
 * Place at: /web3-api/services/riskEngine.js
 *
 * Computes wallet and contract risk scores from multiple signal sources.
 * Fully isolated from core Sentinel APEX scoring logic.
 */

'use strict';

// ─── KNOWN MALICIOUS INDICATORS ───────────────────────────────────────────────
// In production: load from threat DB / OFAC sanctions list / Chainalysis API
const KNOWN_SCAM_FRAGMENTS = ['dead', 'feed', 'babe'];   // address fragments (demo)

const MIXER_PATTERNS = [
  '0x722122df12d4e14e13ac3b6895a86e84145b6967', // Tornado Cash router (example)
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
];

const HIGH_RISK_KEYWORDS = ['honeypot', 'drain', 'rugpull', 'exploit'];

// ─── WALLET RISK SCORING ──────────────────────────────────────────────────────
/**
 * Score a wallet address 0–100.
 *
 * @param {{
 *   address: string;
 *   balanceWei: string;
 *   txCount: number;
 *   firstTx?: string;
 *   lastTx?: string;
 *   network: string;
 * }} walletData
 * @returns {{
 *   score: number;
 *   level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';
 *   factors: Array<{ id: string; label: string; weight: number; description: string }>;
 *   tags: string[];
 * }}
 */
function scoreWallet(walletData) {
  const factors = [];
  const tags    = [];
  let   score   = 0;

  const { address, balanceWei, txCount, firstTx, lastTx } = walletData;
  const addrLower = address.toLowerCase();

  // ── Factor 1: Known mixer interaction ──────────────────────────────────────
  if (MIXER_PATTERNS.some(m => addrLower === m.toLowerCase())) {
    score += 40;
    factors.push({
      id:          'mixer',
      label:       'Known Mixer Address',
      weight:      40,
      description: 'This address matches a known cryptocurrency mixer/tumbler.',
    });
    tags.push('mixer');
  }

  // ── Factor 2: Address pattern analysis ────────────────────────────────────
  if (KNOWN_SCAM_FRAGMENTS.some(f => addrLower.includes(f))) {
    score += 15;
    factors.push({
      id:          'pattern',
      label:       'Suspicious Address Pattern',
      weight:      15,
      description: 'Address contains patterns associated with known scam wallets.',
    });
    tags.push('scam');
  }

  // ── Factor 3: Balance analysis ────────────────────────────────────────────
  const balanceEth = parseFloat(balanceWei) / 1e18;
  if (balanceEth > 1000) {
    score += 10;
    factors.push({
      id:          'whale',
      label:       'Whale Wallet',
      weight:      10,
      description: `Balance of ${balanceEth.toFixed(2)} ETH is unusually high.`,
    });
    tags.push('whale');
  }

  // ── Factor 4: Transaction velocity ────────────────────────────────────────
  if (txCount > 0 && firstTx && lastTx) {
    const ageMs     = Date.now() - new Date(firstTx).getTime();
    const ageDays   = ageMs / 86_400_000;
    const txPerDay  = txCount / Math.max(ageDays, 1);

    if (txPerDay > 100) {
      score += 20;
      factors.push({
        id:          'velocity',
        label:       'Abnormal Transaction Velocity',
        weight:      20,
        description: `${txPerDay.toFixed(0)} transactions/day detected — possible bot or drainer.`,
      });
      tags.push('mev-bot');
    }
  }

  // ── Factor 5: Very new wallet ─────────────────────────────────────────────
  if (firstTx) {
    const ageDays = (Date.now() - new Date(firstTx).getTime()) / 86_400_000;
    if (ageDays < 7) {
      score += 15;
      factors.push({
        id:          'new_wallet',
        label:       'Very New Wallet',
        weight:      15,
        description: `Wallet created only ${Math.floor(ageDays)} day(s) ago. Higher risk profile.`,
      });
    }
  }

  // ── Factor 6: Zero transaction history ────────────────────────────────────
  if (txCount === 0) {
    score += 5;
    factors.push({
      id:          'no_history',
      label:       'No Transaction History',
      weight:      5,
      description: 'Wallet has no on-chain history. Cannot assess behaviour.',
    });
    tags.push('unknown');
  }

  // ── Ensure score is in bounds ──────────────────────────────────────────────
  score = Math.min(100, Math.max(0, score));

  // ── If no specific tags, mark as unknown ──────────────────────────────────
  if (tags.length === 0) tags.push('unknown');

  return {
    score,
    level:   scoreToLevel(score),
    factors,
    tags,
  };
}

// ─── CONTRACT RISK SCORING ────────────────────────────────────────────────────
/**
 * Detect vulnerabilities in Solidity source code via static pattern matching.
 *
 * @param {string} code - Solidity source
 * @returns {{
 *   vulnerabilities: Array;
 *   riskScore: number;
 *   isHoneypot: boolean;
 *   detectedPatterns: string[];
 * }}
 */
function scanSolidityCode(code) {
  const vulnerabilities = [];
  const detectedPatterns = [];
  let   riskScore = 0;

  // ── Reentrancy check ───────────────────────────────────────────────────────
  if (
    code.includes('.call{value:') &&
    /\.call\{value:[^}]+\}/.test(code) &&
    !/ReentrancyGuard/.test(code) &&
    !/nonReentrant/.test(code)
  ) {
    riskScore += 35;
    detectedPatterns.push('reentrancy');
    vulnerabilities.push({
      id:             'REENTRANCY-001',
      name:           'Reentrancy Vulnerability',
      severity:       'CRITICAL',
      description:    'External call is made before state variables are updated. An attacker can re-enter the function before the state is updated, draining funds.',
      recommendation: 'Apply the Checks-Effects-Interactions pattern: update state variables before making external calls. Use OpenZeppelin\'s ReentrancyGuard.',
      lineRef:        'Look for: .call{value: ...}() before state updates',
      cwe:            'CWE-841',
    });
  }

  // ── tx.origin auth ────────────────────────────────────────────────────────
  if (/tx\.origin/.test(code)) {
    riskScore += 20;
    detectedPatterns.push('tx-origin');
    vulnerabilities.push({
      id:             'TXORIGIN-001',
      name:           'tx.origin Authentication',
      severity:       'HIGH',
      description:    'Using tx.origin for authentication is vulnerable to phishing attacks. A malicious contract can trick the legitimate user into calling it.',
      recommendation: 'Replace tx.origin with msg.sender for all authentication checks.',
      lineRef:        'tx.origin',
      cwe:            'CWE-287',
    });
  }

  // ── Unchecked return values ───────────────────────────────────────────────
  if (/\.call\(/.test(code) && !/require\(.*\.call/.test(code) && !/if.*\.call/.test(code)) {
    riskScore += 15;
    detectedPatterns.push('unchecked-return');
    vulnerabilities.push({
      id:             'UNCHECKED-001',
      name:           'Unchecked Return Value',
      severity:       'MEDIUM',
      description:    'Return value of a low-level call is not checked. Failed calls are silently ignored.',
      recommendation: 'Always check the return value of .call() and revert on failure.',
      lineRef:        '.call(',
      cwe:            'CWE-252',
    });
  }

  // ── Delegatecall risk ─────────────────────────────────────────────────────
  if (/delegatecall/.test(code)) {
    riskScore += 25;
    detectedPatterns.push('delegatecall');
    vulnerabilities.push({
      id:             'DELEGATECALL-001',
      name:           'Unsafe delegatecall',
      severity:       'HIGH',
      description:    'delegatecall executes code in the context of the calling contract. If the target is not trusted or upgradeable in an unsafe way, this can lead to storage corruption.',
      recommendation: 'Ensure delegatecall targets are trusted, immutable addresses. Use OpenZeppelin\'s upgradeable patterns.',
      lineRef:        'delegatecall',
      cwe:            'CWE-829',
    });
  }

  // ── Timestamp dependence ──────────────────────────────────────────────────
  if (/block\.timestamp/.test(code) && /require|if/.test(code)) {
    riskScore += 10;
    detectedPatterns.push('timestamp-dependence');
    vulnerabilities.push({
      id:             'TIMESTAMP-001',
      name:           'Block Timestamp Dependence',
      severity:       'LOW',
      description:    'Contract logic depends on block.timestamp. Miners can manipulate this value within ~15 seconds, potentially exploiting time-sensitive logic.',
      recommendation: 'Avoid critical logic based on block.timestamp. Use block numbers for ordering instead.',
      lineRef:        'block.timestamp',
      cwe:            'CWE-330',
    });
  }

  // ── Selfdestruct ──────────────────────────────────────────────────────────
  if (/selfdestruct|suicide/.test(code)) {
    riskScore += 20;
    detectedPatterns.push('access-control');
    vulnerabilities.push({
      id:             'SELFDESTRUCT-001',
      name:           'Selfdestruct Present',
      severity:       'HIGH',
      description:    'Contract contains a selfdestruct instruction. If callable by an unauthorized party, this can destroy the contract and steal remaining funds.',
      recommendation: 'Add strict access control to any selfdestruct path. Consider removing it entirely.',
      lineRef:        'selfdestruct / suicide',
      cwe:            'CWE-471',
    });
  }

  // ── Honeypot detection ────────────────────────────────────────────────────
  const isHoneypot = detectHoneypotPatterns(code);
  if (isHoneypot) {
    riskScore += 40;
    detectedPatterns.push('honeypot');
    vulnerabilities.push({
      id:             'HONEYPOT-001',
      name:           'Potential Honeypot',
      severity:       'CRITICAL',
      description:    'Contract exhibits honeypot patterns: users can deposit but are prevented from withdrawing funds.',
      recommendation: 'DO NOT interact with this contract. It is likely a scam designed to trap funds.',
      lineRef:        'Conditional transfer logic',
      cwe:            'CWE-284',
    });
  }

  return {
    vulnerabilities,
    riskScore: Math.min(100, riskScore),
    isHoneypot,
    detectedPatterns,
  };
}

/**
 * Heuristic honeypot detection.
 * @param {string} code
 * @returns {boolean}
 */
function detectHoneypotPatterns(code) {
  let score = 0;

  // Transfer restricted by owner
  if (/require\(msg\.sender == owner/.test(code) && /transfer|withdraw/.test(code)) score++;

  // Hidden fee traps
  if (/fee.*=.*10[0-9]{2}/.test(code) || /tax.*=.*[89][0-9]/.test(code)) score++;

  // Blacklist/whitelist gating transfers
  if (/blacklist|whitelist/.test(code) && /require.*\[msg\.sender\]/.test(code)) score++;

  // High keyword density
  const text = code.toLowerCase();
  const hits  = HIGH_RISK_KEYWORDS.filter(kw => text.includes(kw)).length;
  if (hits >= 2) score++;

  return score >= 2;
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function scoreToLevel(score) {
  if (score >= 81) return 'CRITICAL';
  if (score >= 61) return 'HIGH';
  if (score >= 31) return 'MEDIUM';
  return 'LOW';
}

module.exports = {
  scoreWallet,
  scanSolidityCode,
  scoreToLevel,
};
