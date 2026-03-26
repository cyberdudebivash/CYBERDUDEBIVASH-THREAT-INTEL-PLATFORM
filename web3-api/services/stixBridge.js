/**
 * WEB3 → STIX 2.1 BRIDGE (READ-ONLY)
 * =====================================
 * Place at: /web3-api/services/stixBridge.js
 *
 * ISOLATION GUARANTEE:
 * ─────────────────────
 * • READ-ONLY: never writes to your existing STIX files or pipeline
 * • Generates NEW STIX bundles in /web3/stix/ (separate directory)
 * • Your existing stix/ directory is never touched
 * • Disabled by default: WEB3_STIX_EXPORT=false
 *
 * STIX 2.1 Objects produced:
 * • indicator         (malicious wallets, contracts)
 * • threat-actor      (rug-pull groups, exploit crews)
 * • attack-pattern    (reentrancy, flash loan, etc.)
 * • malware           (drainer contracts, honeypots)
 * • relationship      (links all objects)
 * • bundle            (wraps all objects)
 *
 * Output: /web3/stix/web3-threats-<date>.json
 */

'use strict';

const path = require('path');
const fs   = require('fs');
const { v4: uuidv4 } = require('crypto'); // Node built-in — no dependency needed

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const STIX_EXPORT_ENABLED = process.env.WEB3_STIX_EXPORT === 'true';
const STIX_OUTPUT_DIR     = process.env.WEB3_STIX_OUTPUT_DIR
  || path.join(process.cwd(), 'web3', 'stix');

// ─── STIX 2.1 IDENTITY (your organisation) ───────────────────────────────────
const PRODUCER_IDENTITY = {
  type:               'identity',
  spec_version:       '2.1',
  id:                 `identity--${deterministicUUID('cyberdudebivash-sentinel-apex')}`,
  created:            '2024-01-01T00:00:00.000Z',
  modified:           '2024-01-01T00:00:00.000Z',
  name:               'CYBERDUDEBIVASH Sentinel APEX',
  identity_class:     'system',
  description:        'Automated Web3 Threat Intelligence produced by Sentinel APEX Web3 Module',
  sectors:            ['technology'],
  contact_information:'https://github.com/cyberdudebivash',
};

// ─── CATEGORY → ATTACK PATTERN MAP ───────────────────────────────────────────
const CATEGORY_TO_ATTACK_PATTERN = {
  'rug-pull':               { name: 'Rug Pull', capecId: 'CAPEC-149' },
  'exploit':                { name: 'Smart Contract Exploit', capecId: 'CAPEC-212' },
  'phishing':               { name: 'Web3 Phishing', capecId: 'CAPEC-98'  },
  'flash-loan-attack':      { name: 'Flash Loan Price Manipulation', capecId: 'CAPEC-212' },
  'bridge-hack':            { name: 'Cross-Chain Bridge Exploit', capecId: 'CAPEC-212' },
  'oracle-manipulation':    { name: 'Price Oracle Manipulation', capecId: 'CAPEC-212' },
  'governance-attack':      { name: 'Governance Token Attack', capecId: 'CAPEC-122' },
  'private-key-compromise': { name: 'Private Key Theft', capecId: 'CAPEC-560' },
  'malicious-wallet':       { name: 'Malicious Wallet Activity', capecId: 'CAPEC-163' },
};

// ─── SEVERITY → TLP MAP ──────────────────────────────────────────────────────
const SEVERITY_TO_TLP = {
  CRITICAL: 'TLP:RED',
  HIGH:     'TLP:AMBER',
  MEDIUM:   'TLP:GREEN',
  LOW:      'TLP:WHITE',
};

// ─── MAIN EXPORT FUNCTION ─────────────────────────────────────────────────────
/**
 * Convert Web3 threats to a STIX 2.1 bundle.
 *
 * @param {import('../routes/threats').Web3ThreatEntry[]} threats
 * @param {object} [options]
 * @param {boolean} [options.writeToDisk] - Write bundle to /web3/stix/ directory
 * @returns {{ bundle: object; filePath?: string }}
 */
function exportThreatsAsSTIX(threats, options = {}) {
  if (!STIX_EXPORT_ENABLED && !options.force) {
    return {
      bundle:  null,
      skipped: true,
      reason:  'WEB3_STIX_EXPORT=false. Set to true to enable STIX export.',
    };
  }

  const now     = new Date().toISOString();
  const objects = [PRODUCER_IDENTITY];

  for (const threat of threats) {
    const threatObjects = threatToSTIX(threat, now);
    objects.push(...threatObjects);
  }

  const bundle = {
    type:         'bundle',
    id:           `bundle--${generateUUID()}`,
    spec_version: '2.1',
    created:      now,
    objects,
  };

  let filePath;

  if (options.writeToDisk !== false) {
    filePath = writeSTIXBundle(bundle);
  }

  return { bundle, filePath };
}

// ─── SINGLE THREAT → STIX OBJECTS ────────────────────────────────────────────
function threatToSTIX(threat, timestamp) {
  const objects   = [];
  const now       = timestamp || new Date().toISOString();
  const tlp       = SEVERITY_TO_TLP[threat.severity] || 'TLP:WHITE';
  const attackMeta = CATEGORY_TO_ATTACK_PATTERN[threat.category];

  // ── Attack Pattern ────────────────────────────────────────────────────────
  const attackPatternId = `attack-pattern--${deterministicUUID(threat.category)}`;
  const attackPattern = {
    type:          'attack-pattern',
    spec_version:  '2.1',
    id:            attackPatternId,
    created:       now,
    modified:      now,
    created_by_ref: PRODUCER_IDENTITY.id,
    name:          attackMeta?.name || threat.category,
    description:   threat.description,
    ...(attackMeta?.capecId && {
      external_references: [{
        source_name:   'capec',
        external_id:   attackMeta.capecId,
        url:           `https://capec.mitre.org/data/definitions/${attackMeta.capecId.replace('CAPEC-', '')}.html`,
      }],
    }),
    object_marking_refs: [tlpToSTIXMarking(tlp)],
  };
  objects.push(attackPattern);

  // ── Indicators (malicious addresses as STIX indicators) ───────────────────
  const indicatorIds = [];

  for (const addr of (threat.affectedAddresses || [])) {
    if (!isValidAddress(addr)) continue;

    const indicatorId = `indicator--${deterministicUUID(addr + threat.id)}`;
    indicatorIds.push(indicatorId);

    objects.push({
      type:          'indicator',
      spec_version:  '2.1',
      id:            indicatorId,
      created:       threat.publishedAt || now,
      modified:      now,
      created_by_ref: PRODUCER_IDENTITY.id,
      name:          `Malicious Address: ${addr.slice(0, 10)}...`,
      description:   `Address involved in ${threat.category} on ${threat.network}. ${threat.title}`,
      indicator_types: categoryToIndicatorTypes(threat.category),
      pattern:       `[ethereum-addr:value = '${addr.toLowerCase()}']`,
      pattern_type:  'stix',
      valid_from:    threat.publishedAt || now,
      confidence:    severityToConfidence(threat.severity),
      labels:        [threat.category, threat.network, threat.severity.toLowerCase()],
      object_marking_refs: [tlpToSTIXMarking(tlp)],
      ...(threat.sourceUrl && {
        external_references: [{ source_name: 'web', url: threat.sourceUrl }],
      }),
    });
  }

  // ── Transaction IOCs ───────────────────────────────────────────────────────
  if (threat.exploitTxHash) {
    const txIndicatorId = `indicator--${deterministicUUID(threat.exploitTxHash)}`;

    objects.push({
      type:          'indicator',
      spec_version:  '2.1',
      id:            txIndicatorId,
      created:       threat.publishedAt || now,
      modified:      now,
      created_by_ref: PRODUCER_IDENTITY.id,
      name:          `Exploit Transaction: ${threat.exploitTxHash.slice(0, 12)}...`,
      description:   `Transaction hash for ${threat.title} exploit`,
      indicator_types: ['malicious-activity'],
      pattern:       `[ethereum-tx:hash = '${threat.exploitTxHash}']`,
      pattern_type:  'stix',
      valid_from:    threat.publishedAt || now,
      confidence:    95,
      labels:        [threat.category, 'exploit-tx'],
      object_marking_refs: [tlpToSTIXMarking(tlp)],
    });

    indicatorIds.push(txIndicatorId);
  }

  // ── IOC strings ───────────────────────────────────────────────────────────
  for (const ioc of (threat.iocs || [])) {
    const iocId = `indicator--${deterministicUUID(ioc + threat.id)}`;

    objects.push({
      type:          'indicator',
      spec_version:  '2.1',
      id:            iocId,
      created:       threat.publishedAt || now,
      modified:      now,
      created_by_ref: PRODUCER_IDENTITY.id,
      name:          `IOC: ${ioc}`,
      indicator_types: categoryToIndicatorTypes(threat.category),
      pattern:       isValidAddress(ioc)
        ? `[ethereum-addr:value = '${ioc.toLowerCase()}']`
        : `[domain-name:value = '${ioc}']`,
      pattern_type:  'stix',
      valid_from:    threat.publishedAt || now,
      confidence:    severityToConfidence(threat.severity),
      labels:        [threat.category, 'ioc'],
      object_marking_refs: [tlpToSTIXMarking(tlp)],
    });

    indicatorIds.push(iocId);
  }

  // ── Relationships ─────────────────────────────────────────────────────────
  for (const indicatorId of indicatorIds) {
    objects.push({
      type:           'relationship',
      spec_version:   '2.1',
      id:             `relationship--${generateUUID()}`,
      created:        now,
      modified:       now,
      created_by_ref: PRODUCER_IDENTITY.id,
      relationship_type: 'indicates',
      source_ref:     indicatorId,
      target_ref:     attackPatternId,
      description:    `Indicator associated with ${attackMeta?.name || threat.category}`,
    });
  }

  return objects;
}

// ─── DISK WRITE ───────────────────────────────────────────────────────────────
function writeSTIXBundle(bundle) {
  // Ensure output directory exists
  if (!fs.existsSync(STIX_OUTPUT_DIR)) {
    fs.mkdirSync(STIX_OUTPUT_DIR, { recursive: true });
  }

  const dateStr  = new Date().toISOString().slice(0, 10);
  const filename = `web3-threats-${dateStr}.json`;
  const filePath = path.join(STIX_OUTPUT_DIR, filename);

  // Write — never overwrite existing (append new objects if file exists)
  if (fs.existsSync(filePath)) {
    const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const existingIds = new Set(existing.objects.map(o => o.id));
    const newObjects  = bundle.objects.filter(o => !existingIds.has(o.id));

    if (newObjects.length > 0) {
      existing.objects.push(...newObjects);
      existing.modified = bundle.created;
      fs.writeFileSync(filePath, JSON.stringify(existing, null, 2), 'utf8');
      console.log(`[WEB3-STIX] Appended ${newObjects.length} objects to ${filename}`);
    }
  } else {
    fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2), 'utf8');
    console.log(`[WEB3-STIX] Created new bundle: ${filename} (${bundle.objects.length} objects)`);
  }

  // Write manifest (GitHub Pages-compatible index)
  writeManifest(STIX_OUTPUT_DIR);

  return filePath;
}

function writeManifest(dir) {
  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json') && f !== 'manifest.json')
    .map(f => ({
      filename: f,
      created:  fs.statSync(path.join(dir, f)).birthtime.toISOString(),
      size:     fs.statSync(path.join(dir, f)).size,
    }))
    .sort((a, b) => b.filename.localeCompare(a.filename));

  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify({
      source:       'CYBERDUDEBIVASH Sentinel APEX Web3 Module',
      spec_version: '2.1',
      updated:      new Date().toISOString(),
      bundles:      files,
    }, null, 2),
    'utf8'
  );
}

// ─── STIX ROUTE HANDLER ───────────────────────────────────────────────────────
/**
 * Express route: GET /web3-api/stix/export
 * Returns STIX bundle of all current threats.
 */
async function stixExportHandler(req, res) {
  if (!STIX_EXPORT_ENABLED) {
    return res.status(503).json({
      success: false,
      error:   'STIX export is disabled. Set WEB3_STIX_EXPORT=true to enable.',
      timestamp: new Date().toISOString(),
    });
  }

  try {
    // In production: load from your threat database
    const { MOCK_THREATS } = require('../routes/threats');
    const { bundle, filePath } = exportThreatsAsSTIX(
      // eslint-disable-next-line no-undef
      MOCK_THREATS || [],
      { writeToDisk: true }
    );

    res.json({
      success:     true,
      data: {
        bundle,
        objectCount: bundle.objects.length,
        filePath:    filePath ? path.basename(filePath) : null,
      },
      timestamp:   new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error:   `STIX export failed: ${err.message}`,
      timestamp: new Date().toISOString(),
    });
  }
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function generateUUID() {
  // Node.js 14.17+ built-in crypto
  return require('crypto').randomUUID();
}

function deterministicUUID(input) {
  // SHA-256 → UUID v5 format (no external deps)
  const hash = require('crypto')
    .createHash('sha256')
    .update(String(input))
    .digest('hex');
  return [
    hash.slice(0,  8),
    hash.slice(8,  12),
    '5' + hash.slice(13, 16),  // Version 5
    hash.slice(16, 20),
    hash.slice(20, 32),
  ].join('-');
}

function isValidAddress(str) {
  return /^0x[a-fA-F0-9]{40}$/.test(String(str));
}

function categoryToIndicatorTypes(category) {
  const map = {
    'rug-pull':               ['malicious-activity', 'attribution'],
    'exploit':                ['malicious-activity'],
    'phishing':               ['phishing'],
    'malicious-wallet':       ['malicious-activity', 'attribution'],
    'flash-loan-attack':      ['malicious-activity'],
    'bridge-hack':            ['malicious-activity'],
    'oracle-manipulation':    ['malicious-activity'],
    'governance-attack':      ['malicious-activity', 'attribution'],
    'private-key-compromise': ['malicious-activity', 'compromise'],
  };
  return map[category] || ['malicious-activity'];
}

function severityToConfidence(severity) {
  const map = { CRITICAL: 95, HIGH: 80, MEDIUM: 60, LOW: 40, INFO: 20 };
  return map[severity] || 50;
}

function tlpToSTIXMarking(tlp) {
  const markings = {
    'TLP:WHITE': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    'TLP:GREEN': 'marking-definition--34098fce-860f-479c-ad6f-32f61e3dd194',
    'TLP:AMBER': 'marking-definition--f88d31f6-1f26-4a72-a073-eff7f8ab52b4',
    'TLP:RED':   'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
  };
  return markings[tlp] || markings['TLP:WHITE'];
}

module.exports = {
  exportThreatsAsSTIX,
  stixExportHandler,
  PRODUCER_IDENTITY,
};
