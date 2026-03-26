/**
 * WALLET ANALYZER ROUTE
 * Place at: /web3-api/routes/wallet.js
 */

'use strict';

const express   = require('express');
const rateLimit = require('express-rate-limit');
const router    = express.Router();

const { validateAddress, validateNetwork } = require('../utils/validators');
const { getWalletData }   = require('../services/blockchainService');
const { scoreWallet }     = require('../services/riskEngine');

// Stricter rate limit for wallet analysis (expensive API calls)
const walletLimiter = rateLimit({
  windowMs: 60_000,         // 1 minute
  max:      10,
  message: {
    success:   false,
    error:     'Wallet analyzer rate limit exceeded. Max 10 requests/minute.',
    timestamp: new Date().toISOString(),
  },
});

router.post('/analyze', walletLimiter, async (req, res, next) => {
  try {
    const { address, network = 'ethereum' } = req.body;

    // Input validation
    const addrValidation = validateAddress(address);
    if (!addrValidation.valid) {
      return res.status(400).json({
        success:   false,
        error:     addrValidation.error,
        timestamp: new Date().toISOString(),
      });
    }

    const netValidation = validateNetwork(network);
    if (!netValidation.valid) {
      return res.status(400).json({
        success:   false,
        error:     netValidation.error,
        timestamp: new Date().toISOString(),
      });
    }

    const normalizedAddr = address.trim().toLowerCase();

    // Fetch on-chain data
    const walletData = await getWalletData(normalizedAddr, network);

    // Score risk
    const riskResult = scoreWallet({ address: normalizedAddr, network, ...walletData });

    // Format balance
    const balanceEth = walletData.balanceEth ||
      (parseFloat(walletData.balanceWei || '0') / 1e18).toFixed(4);
    const balanceUSD = `$${(parseFloat(balanceEth) * 2_400).toFixed(2)}`; // Approx ETH price

    const result = {
      address:          normalizedAddr,
      network,
      risk: {
        score:         riskResult.score,
        level:         riskResult.level,
        factors:       riskResult.factors,
        calculatedAt:  new Date().toISOString(),
      },
      tags:             riskResult.tags,
      balance: {
        eth:  balanceEth,
        usd:  balanceUSD,
      },
      transactionCount: walletData.txCount || 0,
      firstSeen:        walletData.firstTx || new Date().toISOString(),
      lastSeen:         walletData.lastTx  || new Date().toISOString(),
      summary:          generateWalletSummary(normalizedAddr, riskResult),
      relatedAddresses: [],   // Extend: Chainalysis graph API
      analysedAt:       new Date().toISOString(),
      source:           walletData.source || 'etherscan',
    };

    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    next(err);
  }
});

function generateWalletSummary(address, riskResult) {
  const level = riskResult.level;
  const score = riskResult.score;
  const tagStr = riskResult.tags.join(', ');

  if (level === 'CRITICAL') {
    return `CRITICAL RISK (${score}/100): Address ${address.slice(0, 8)}... exhibits highly malicious behaviour. ` +
           `Tagged as: ${tagStr}. Immediate action recommended — do not interact.`;
  }
  if (level === 'HIGH') {
    return `HIGH RISK (${score}/100): Address shows significant red flags including ${tagStr}. ` +
           `Exercise extreme caution before any interaction.`;
  }
  if (level === 'MEDIUM') {
    return `MEDIUM RISK (${score}/100): Some suspicious signals detected (${tagStr}). ` +
           `Perform additional due diligence before transacting.`;
  }
  return `LOW RISK (${score}/100): No major red flags detected. Standard precautions apply.`;
}

module.exports = router;
