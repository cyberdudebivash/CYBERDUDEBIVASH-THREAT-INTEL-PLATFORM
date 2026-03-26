/**
 * CONTRACT SCANNER ROUTE
 * Place at: /web3-api/routes/contract.js
 */

'use strict';

const express   = require('express');
const rateLimit = require('express-rate-limit');
const router    = express.Router();

const {
  validateAddress,
  validateNetwork,
  validateSolidityCode,
} = require('../utils/validators');
const { getContractData } = require('../services/blockchainService');
const { scanSolidityCode, scoreToLevel } = require('../services/riskEngine');

// Slower rate limit — scanning is intensive
const contractLimiter = rateLimit({
  windowMs: 60_000,
  max:      5,
  message: {
    success:   false,
    error:     'Contract scanner rate limit: max 5 scans/minute.',
    timestamp: new Date().toISOString(),
  },
});

router.post('/scan', contractLimiter, async (req, res, next) => {
  try {
    const { address, code, network = 'ethereum' } = req.body;

    if (!address && !code) {
      return res.status(400).json({
        success:   false,
        error:     'Either contract address or source code is required.',
        timestamp: new Date().toISOString(),
      });
    }

    // Validate inputs
    if (address) {
      const v = validateAddress(address);
      if (!v.valid) return res.status(400).json({ success: false, error: v.error, timestamp: new Date().toISOString() });
    }

    if (code) {
      const v = validateSolidityCode(code);
      if (!v.valid) return res.status(400).json({ success: false, error: v.error, timestamp: new Date().toISOString() });
    }

    const netV = validateNetwork(network);
    if (!netV.valid) return res.status(400).json({ success: false, error: netV.error, timestamp: new Date().toISOString() });

    // Fetch contract data if address provided
    let contractMeta = { contractName: 'Unknown', isVerified: false, sourceCode: code || '' };

    if (address) {
      const fetched = await getContractData(address.trim().toLowerCase(), network);
      contractMeta  = { ...contractMeta, ...fetched };
    }

    const sourceToScan = code || contractMeta.sourceCode || '';

    // Run vulnerability scanner
    const scanResult = sourceToScan
      ? scanSolidityCode(sourceToScan)
      : { vulnerabilities: [], riskScore: 0, isHoneypot: false, detectedPatterns: [] };

    const result = {
      address:          address ? address.trim().toLowerCase() : undefined,
      network,
      contractName:     contractMeta.contractName,
      vulnerabilities:  scanResult.vulnerabilities,
      riskScore:        scanResult.riskScore,
      riskLevel:        scoreToLevel(scanResult.riskScore),
      isHoneypot:       scanResult.isHoneypot,
      isVerified:       contractMeta.isVerified,
      detectedPatterns: scanResult.detectedPatterns,
      summary:          generateContractSummary(scanResult),
      scannedAt:        new Date().toISOString(),
    };

    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    next(err);
  }
});

function generateContractSummary({ vulnerabilities, riskScore, isHoneypot, detectedPatterns }) {
  const critCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;

  if (isHoneypot) {
    return `⚠️ HONEYPOT DETECTED: This contract is designed to prevent withdrawals. ` +
           `Risk score: ${riskScore}/100. Do NOT interact.`;
  }
  if (critCount > 0) {
    return `${critCount} CRITICAL vulnerability${critCount > 1 ? 'ies' : ''} detected (${detectedPatterns.join(', ')}). ` +
           `Risk score: ${riskScore}/100. Immediate remediation required.`;
  }
  if (highCount > 0) {
    return `${highCount} HIGH severity issue${highCount > 1 ? 's' : ''} found. ` +
           `Risk score: ${riskScore}/100. Security audit strongly recommended before deployment.`;
  }
  if (vulnerabilities.length > 0) {
    return `${vulnerabilities.length} issue${vulnerabilities.length > 1 ? 's' : ''} detected. ` +
           `Risk score: ${riskScore}/100. Review and remediate before production use.`;
  }
  return `No major vulnerabilities detected. Risk score: ${riskScore}/100. ` +
         `Consider a professional audit before mainnet deployment.`;
}

module.exports = router;
