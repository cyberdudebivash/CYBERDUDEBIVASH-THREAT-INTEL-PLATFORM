/**
 * TRANSACTION MONITOR ROUTE
 * Place at: /web3-api/routes/transactions.js
 */

'use strict';

const express   = require('express');
const rateLimit = require('express-rate-limit');
const router    = express.Router();

const { validatePagination, validateNetwork } = require('../utils/validators');

const txLimiter = rateLimit({
  windowMs: 60_000,
  max:      30,
  message: { success: false, error: 'Rate limit exceeded.', timestamp: new Date().toISOString() },
});

const ALERT_TYPES = ['large-transfer', 'mixer-interaction', 'known-scammer', 'rapid-drain', 'unusual-pattern'];
const NETWORKS    = ['ethereum', 'polygon', 'bsc', 'arbitrum'];

function generateMockTransactions(count = 80) {
  return Array.from({ length: count }, (_, i) => {
    const alertType = ALERT_TYPES[i % ALERT_TYPES.length];
    const network   = NETWORKS[i % NETWORKS.length];
    const riskScore = Math.min(100, 40 + (i % 60));
    const valueETH  = ((i + 1) * 7.3).toFixed(3);
    const valueUSD  = `$${((i + 1) * 7.3 * 2400).toLocaleString()}`;
    const minsAgo   = i * 3;

    return {
      hash:         `0x${String(i + 1).padStart(64, '0')}`,
      from:         `0x${String(i * 13 + 1).padStart(40, 'a').slice(0, 40)}`,
      to:           `0x${String(i * 17 + 9).padStart(40, 'b').slice(0, 40)}`,
      valueETH,
      valueUSD,
      network,
      blockNumber:  19_500_000 + i,
      timestamp:    new Date(Date.now() - minsAgo * 60_000).toISOString(),
      alertType,
      alertMessage: ALERT_MESSAGES[alertType],
      riskScore,
    };
  });
}

const ALERT_MESSAGES = {
  'large-transfer':    'Transfer exceeds $500K threshold — potential whale movement or protocol drain.',
  'mixer-interaction': 'Interaction detected with known Tornado Cash or mixer contract.',
  'known-scammer':     'Address matches known scammer in threat intelligence database.',
  'rapid-drain':       'Multiple rapid consecutive withdrawals detected — possible drainer bot.',
  'unusual-pattern':   'Transaction pattern deviates significantly from historical baseline.',
};

const MOCK_TRANSACTIONS = generateMockTransactions(80);

router.get('/suspicious', txLimiter, (req, res, next) => {
  try {
    const { page, limit } = validatePagination(req.query);
    const netV = validateNetwork(req.query.network);
    if (!netV.valid) {
      return res.status(400).json({ success: false, error: netV.error, timestamp: new Date().toISOString() });
    }

    let filtered = [...MOCK_TRANSACTIONS];

    if (req.query.network) {
      filtered = filtered.filter(tx => tx.network === req.query.network);
    }

    // Sort by riskScore desc
    filtered.sort((a, b) => b.riskScore - a.riskScore);

    const total = filtered.length;
    const start = (page - 1) * limit;
    const paged = filtered.slice(start, start + limit);

    res.json({
      success: true,
      data: { transactions: paged, total, page, limit },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
