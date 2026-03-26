/**
 * STIX EXPORT ROUTE
 * Place at: /web3-api/routes/stix.js
 *
 * Add to server.js:
 *   const stixRoutes = require('./routes/stix');
 *   app.use('/web3-api/stix', stixRoutes);
 *
 * Endpoints:
 *   GET  /web3-api/stix/export       → Download STIX bundle
 *   GET  /web3-api/stix/manifest     → List all exported bundles
 *   GET  /web3-api/stix/status       → Export status and config
 */

'use strict';

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const router   = express.Router();
const rateLimit = require('express-rate-limit');

const { exportThreatsAsSTIX, PRODUCER_IDENTITY } = require('../services/stixBridge');

const STIX_ENABLED    = process.env.WEB3_STIX_EXPORT === 'true';
const STIX_OUTPUT_DIR = process.env.WEB3_STIX_OUTPUT_DIR
  || path.join(process.cwd(), 'web3', 'stix');

const stixLimiter = rateLimit({
  windowMs: 60_000,
  max:      5,
  message: { success: false, error: 'STIX export rate limit: 5/minute.', timestamp: new Date().toISOString() },
});

// GET /web3-api/stix/status
router.get('/status', (req, res) => {
  res.json({
    success: true,
    data: {
      enabled:      STIX_ENABLED,
      outputDir:    STIX_OUTPUT_DIR,
      producer:     PRODUCER_IDENTITY.name,
      specVersion:  '2.1',
      description:  'Isolated Web3 threat STIX bridge. Never modifies core STIX pipeline.',
    },
    timestamp: new Date().toISOString(),
  });
});

// GET /web3-api/stix/manifest
router.get('/manifest', (req, res) => {
  if (!STIX_ENABLED) {
    return res.status(503).json({
      success: false,
      error:   'STIX export disabled. Set WEB3_STIX_EXPORT=true.',
      timestamp: new Date().toISOString(),
    });
  }

  const manifestPath = path.join(STIX_OUTPUT_DIR, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    return res.json({
      success: true,
      data:    { bundles: [], message: 'No bundles exported yet.' },
      timestamp: new Date().toISOString(),
    });
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  res.json({ success: true, data: manifest, timestamp: new Date().toISOString() });
});

// GET /web3-api/stix/export
router.get('/export', stixLimiter, async (req, res, next) => {
  if (!STIX_ENABLED) {
    return res.status(503).json({
      success: false,
      error:   'STIX export disabled. Set WEB3_STIX_EXPORT=true.',
      timestamp: new Date().toISOString(),
    });
  }

  try {
    // In production: load threats from your DB
    // For now: generate from mock data
    const mockThreats = generateExportableThreats();
    const { bundle, filePath } = exportThreatsAsSTIX(mockThreats, { writeToDisk: true });

    // Offer as JSON download
    const asDownload = req.query.download === 'true';
    if (asDownload) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition',
        `attachment; filename="web3-stix-${new Date().toISOString().slice(0, 10)}.json"`);
      return res.send(JSON.stringify(bundle, null, 2));
    }

    res.json({
      success:     true,
      data: {
        bundleId:    bundle.id,
        objectCount: bundle.objects.length,
        specVersion: bundle.spec_version,
        created:     bundle.created,
        outputFile:  filePath ? path.basename(filePath) : null,
        preview:     bundle.objects.slice(0, 3),  // First 3 objects as preview
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

// ─── MOCK THREAT DATA FOR EXPORT ─────────────────────────────────────────────
function generateExportableThreats() {
  return [
    {
      id:               'THREAT-0001',
      title:            'Flash Loan Attack on DEX Protocol',
      category:         'flash-loan-attack',
      severity:         'CRITICAL',
      description:      'Attacker used flash loan to manipulate price oracle, draining $2.4M from liquidity pool.',
      affectedProtocol: 'UniswapV3',
      affectedAddresses: ['0x1234567890abcdef1234567890abcdef12345678'],
      lossUSD:          2_400_000,
      network:          'ethereum',
      exploitTxHash:    '0x' + 'a'.repeat(64),
      sourceUrl:        'https://rekt.news/example',
      publishedAt:      new Date().toISOString(),
      iocs: [
        '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        'fake-protocol.app',
      ],
      tags: ['flash-loan', 'defi', 'critical'],
    },
    {
      id:               'THREAT-0002',
      title:            'Rug Pull: DeFi Protocol Exit Scam',
      category:         'rug-pull',
      severity:         'HIGH',
      description:      'Protocol developers withdrew all liquidity from pools without warning.',
      affectedProtocol: 'FakeYield Finance',
      affectedAddresses: ['0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'],
      lossUSD:          850_000,
      network:          'bsc',
      publishedAt:      new Date(Date.now() - 86_400_000).toISOString(),
      iocs: ['0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'],
      tags: ['rug-pull', 'bsc'],
    },
  ];
}

module.exports = router;
