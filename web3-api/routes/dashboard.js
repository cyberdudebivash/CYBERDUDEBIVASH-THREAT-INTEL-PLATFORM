/**
 * DASHBOARD ROUTE
 * Place at: /web3-api/routes/dashboard.js
 */

'use strict';

const express = require('express');
const router  = express.Router();

// Mock stats — replace with real DB queries in production
router.get('/stats', async (req, res, next) => {
  try {
    res.json({
      success: true,
      data: {
        highRiskWallets:        142,
        latestThreats:           38,
        suspiciousTransactions: 267,
        highRiskContracts:       19,
        totalLossUSD:      847_000_000,
        lastUpdated:        new Date().toISOString(),
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
