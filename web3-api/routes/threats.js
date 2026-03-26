/**
 * THREAT FEED ROUTE
 * Place at: /web3-api/routes/threats.js
 */

'use strict';

const express   = require('express');
const rateLimit = require('express-rate-limit');
const router    = express.Router();

const { validatePagination, validateSeverity, validateCategory } = require('../utils/validators');

const feedLimiter = rateLimit({
  windowMs: 60_000,
  max:      60,
  message: { success: false, error: 'Rate limit exceeded.', timestamp: new Date().toISOString() },
});

// ─── MOCK THREAT DATA ─────────────────────────────────────────────────────────
// In production: replace with DB query to your threat intelligence store
function generateMockThreats(total = 50) {
  const categories = [
    'rug-pull', 'exploit', 'phishing', 'malicious-wallet',
    'flash-loan-attack', 'bridge-hack', 'oracle-manipulation',
  ];
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const networks   = ['ethereum', 'polygon', 'bsc', 'arbitrum'];
  const protocols  = ['UniswapV3', 'Curve', 'Aave', 'Compound', 'PancakeSwap', 'dYdX', 'Balancer'];

  return Array.from({ length: total }, (_, i) => {
    const cat = categories[i % categories.length];
    const sev = severities[i % severities.length];
    const net = networks[i % networks.length];
    const pro = protocols[i % protocols.length];
    const lossUSD = sev === 'CRITICAL' ? (i + 1) * 12_500_000 :
                    sev === 'HIGH'     ? (i + 1) * 2_000_000  : undefined;

    const daysAgo = i * 0.5;
    const date    = new Date(Date.now() - daysAgo * 86_400_000).toISOString();

    return {
      id:               `THREAT-${String(i + 1).padStart(4, '0')}`,
      title:            THREAT_TITLES[cat] || `${cat} incident on ${pro}`,
      category:         cat,
      severity:         sev,
      description:      THREAT_DESCRIPTIONS[cat] || 'Suspicious on-chain activity detected.',
      affectedProtocol: pro,
      affectedAddresses:[`0x${String(i).repeat(20).slice(0, 40)}`],
      lossUSD,
      network:          net,
      exploitTxHash:    sev === 'CRITICAL' ? `0x${'a'.repeat(64)}` : undefined,
      sourceUrl:        `https://rekt.news/example-${i}`,
      publishedAt:      date,
      iocs:             [
        `0x${String(i + 10).repeat(10).slice(0, 40)}`,
        `malicious-domain-${i}.eth`,
      ],
      tags:             [cat, net, sev.toLowerCase()],
    };
  });
}

const THREAT_TITLES = {
  'rug-pull':               'Rug Pull: Protocol Founders Drain Liquidity',
  'exploit':                'Smart Contract Exploit: Re-entrancy Attack',
  'phishing':               'Phishing Campaign: Fake Protocol Website',
  'malicious-wallet':       'Sanctioned Wallet Activity Detected',
  'flash-loan-attack':      'Flash Loan Manipulation: Price Oracle Exploited',
  'bridge-hack':            'Cross-Chain Bridge Compromised',
  'oracle-manipulation':    'Chainlink Oracle Manipulation Attempt',
  'governance-attack':      'Governance Proposal Attack',
  'private-key-compromise': 'Private Key Compromise: Admin Wallet Drained',
};

const THREAT_DESCRIPTIONS = {
  'rug-pull':               'Protocol developers withdrew all liquidity, abandoning the project and causing total loss for investors.',
  'exploit':                'Attacker exploited a reentrancy vulnerability in the withdraw function, draining the protocol treasury.',
  'phishing':               'A sophisticated phishing site mimicking the official protocol interface was used to steal user approval signatures.',
  'malicious-wallet':       'OFAC-sanctioned wallet detected interacting with DeFi protocols in violation of international sanctions.',
  'flash-loan-attack':      'Attacker used a flash loan to manipulate price oracle readings, enabling profitable arbitrage at user expense.',
  'bridge-hack':            'Cryptographic signature verification flaw in the bridge contract allowed unauthorized withdrawal of bridged assets.',
  'oracle-manipulation':    'Multiple oracle price feeds were manipulated within a single block using coordinated transactions.',
  'governance-attack':      'Attacker accumulated governance tokens to pass a malicious proposal granting control of the treasury.',
  'private-key-compromise': 'Admin private key was compromised via supply-chain attack on developer tooling.',
};

const MOCK_THREATS = generateMockThreats(60);

router.get('/', feedLimiter, (req, res, next) => {
  try {
    const { page, limit } = validatePagination(req.query);
    const severity = validateSeverity(req.query.severity);
    const category = validateCategory(req.query.category);

    let filtered = [...MOCK_THREATS];

    if (severity) filtered = filtered.filter(t => t.severity === severity);
    if (category) filtered = filtered.filter(t => t.category === category);

    const total  = filtered.length;
    const start  = (page - 1) * limit;
    const paged  = filtered.slice(start, start + limit);

    res.json({
      success: true,
      data: { threats: paged, total, page, limit },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
