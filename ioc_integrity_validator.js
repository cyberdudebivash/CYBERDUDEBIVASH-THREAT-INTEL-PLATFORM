/**
 * IOC Integrity Validator — SENTINEL APEX Feed Quality Engine
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Detect and remove code-file artifacts, internal filenames, and
 * non-IOC strings that are contaminating the iocs / iocs_by_type fields.
 *
 * EVIDENCE TRIGGERING THIS MODULE:
 *   - 33/44 feed items contain 'store.ts' as a domain IOC
 *   - ioc_count inflated to 23-26 on LOW-severity CVE items
 *   - ioc_confidence reaching 89-100 when real IOC count is near zero
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. BLOCKLIST — file extensions and patterns that are NEVER valid IOCs
// ---------------------------------------------------------------------------
const INVALID_IOC_EXTENSIONS = new Set([
  '.ts','.tsx','.js','.jsx','.mjs','.cjs',
  '.py','.rb','.go','.rs','.java','.kt',
  '.css','.scss','.sass','.less',
  '.html','.htm','.xml','.xsl',
  '.json','.yaml','.yml','.toml','.env',
  '.md','.txt','.rst','.log',
  '.sh','.bat','.ps1','.psm1','.cmd',
  '.patch','.diff','.sql',
  '.pdf','.docx','.xlsx','.pptx',
  '.zip','.gz','.tar','.pkg','.deb','.rpm',
  '.png','.jpg','.jpeg','.gif','.svg','.ico',
  '.woff','.woff2','.ttf','.eot',
]);

// Well-known internal filenames that should never appear as IOCs
const INVALID_IOC_FILENAMES = new Set([
  'store.ts','index.ts','index.js','main.py','app.py','utils.py',
  'package.json','tsconfig.json','webpack.config.js',
  'readme.md','changelog.md','license.md',
  'requirements.txt','setup.py','cargo.toml',
  'service-worker.js','sw.js',
]);

// RFC-compliant private/reserved IP ranges — not valid threat IOCs
const PRIVATE_IP_RANGES = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^169\.254\.\d{1,3}\.\d{1,3}$/,
  /^0\.0\.0\.0$/,
  /^255\.255\.255\.255$/,
  /^::1$/,
  /^fc[0-9a-f]{2}:/i,
];

// Source domain allowlist — URLs from these domains are metadata, not IOCs
const SOURCE_DOMAINS_NOT_IOCS = [
  'vulners.com','nvd.nist.gov','github.com','gitlab.com',
  'intel.cyberdudebivash.com','cyberdudebivash.com',
  'cve.mitre.org','exploit-db.com','packetstormsecurity.com',
];

// Regex: valid IPv4
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
// Regex: valid domain (at minimum two labels, no path)
const DOMAIN_RE = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/i;
// Regex: MD5 / SHA1 / SHA256 hashes
const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
// CVE pattern
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

// ---------------------------------------------------------------------------
// 2. IOC VALIDATION FUNCTIONS
// ---------------------------------------------------------------------------

function hasInvalidExtension(value) {
  const lower = value.toLowerCase();
  for (const ext of INVALID_IOC_EXTENSIONS) {
    if (lower.endsWith(ext)) return { invalid: true, reason: `code/data file extension: ${ext}` };
  }
  return { invalid: false };
}

function isInvalidFilename(value) {
  const base = value.split('/').pop().toLowerCase();
  if (INVALID_IOC_FILENAMES.has(base)) return { invalid: true, reason: `known internal filename: ${base}` };
  return { invalid: false };
}

function isPrivateIP(value) {
  for (const re of PRIVATE_IP_RANGES) {
    if (re.test(value)) return { invalid: true, reason: 'private/reserved IP address' };
  }
  return { invalid: false };
}

function isSourceDomainNotIOC(value) {
  const lower = value.toLowerCase();
  for (const d of SOURCE_DOMAINS_NOT_IOCS) {
    if (lower.includes(d)) return { invalid: true, reason: `source/metadata domain: ${d}` };
  }
  return { invalid: false };
}

function classifyIOCType(value) {
  if (!value || typeof value !== 'string') return null;
  const v = value.trim();
  if (HASH_RE.test(v)) return 'hash';
  if (CVE_RE.test(v)) return 'cve';
  if (IPV4_RE.test(v)) {
    const parts = v.split('.').map(Number);
    if (parts.every(p => p <= 255)) return 'ipv4';
  }
  if (v.startsWith('http://') || v.startsWith('https://') || v.startsWith('ftp://')) return 'url';
  if (DOMAIN_RE.test(v) && v.includes('.')) return 'domain';
  return 'unknown';
}

/**
 * validateIOC — core function
 * Returns { valid: bool, type: string|null, reason: string|null }
 */
function validateIOC(value, declaredType) {
  if (!value || typeof value !== 'string') {
    return { valid: false, type: null, reason: 'null or non-string value' };
  }
  const v = value.trim();
  if (v.length < 4) return { valid: false, type: null, reason: 'value too short' };

  // Extension check first — catches code files regardless of declared type
  const extCheck = hasInvalidExtension(v);
  if (extCheck.invalid) return { valid: false, type: null, reason: extCheck.reason };

  const fnCheck = isInvalidFilename(v);
  if (fnCheck.invalid) return { valid: false, type: null, reason: fnCheck.reason };

  if (declaredType === 'domain' || declaredType === 'ip') {
    const ipCheck = isPrivateIP(v);
    if (ipCheck.invalid) return { valid: false, type: null, reason: ipCheck.reason };

    const srcCheck = isSourceDomainNotIOC(v);
    if (srcCheck.invalid) return { valid: false, type: null, reason: srcCheck.reason };
  }

  const type = classifyIOCType(v);
  if (type === 'unknown') {
    return { valid: false, type: null, reason: 'unrecognised IOC pattern' };
  }

  return { valid: true, type, reason: null };
}

// ---------------------------------------------------------------------------
// 3. FEED ITEM CLEANER
// ---------------------------------------------------------------------------

/**
 * cleanIOCsForItem
 * Takes a feed item, validates all IOC values, returns cleaned item + audit.
 */
function cleanIOCsForItem(item) {
  const audit = {
    item_id: item.id || item.stix_id || 'UNKNOWN',
    original_ioc_count: item.ioc_count || 0,
    removed_iocs: [],
    retained_iocs: [],
    contaminants: [],
    contamination_types: {},
  };

  const cleanedIocs = [];
  const cleanedByType = {};

  // Process flat iocs list
  const rawIocs = Array.isArray(item.iocs) ? item.iocs : [];
  for (const ioc of rawIocs) {
    const result = validateIOC(ioc, null);
    if (result.valid) {
      cleanedIocs.push(ioc);
      audit.retained_iocs.push(ioc);
    } else {
      audit.removed_iocs.push({ value: ioc, reason: result.reason });
      audit.contaminants.push(ioc);
      audit.contamination_types[result.reason] = (audit.contamination_types[result.reason] || 0) + 1;
    }
  }

  // Process iocs_by_type
  const rawByType = item.iocs_by_type || {};
  for (const [type, values] of Object.entries(rawByType)) {
    const cleanedVals = [];
    for (const val of (Array.isArray(values) ? values : [])) {
      const result = validateIOC(val, type);
      if (result.valid) {
        cleanedVals.push(val);
      } else {
        if (!audit.contaminants.includes(val)) {
          audit.removed_iocs.push({ value: val, reason: result.reason, declared_type: type });
          audit.contaminants.push(val);
        }
      }
    }
    if (cleanedVals.length > 0) cleanedByType[type] = cleanedVals;
  }

  const cleanedItem = Object.assign({}, item, {
    iocs: cleanedIocs,
    iocs_by_type: cleanedByType,
    ioc_count: cleanedIocs.length,
    ioc_integrity_validated: true,
    ioc_integrity_validated_at: new Date().toISOString(),
    ioc_integrity_version: '1.0.0',
  });

  audit.cleaned_ioc_count = cleanedIocs.length;
  audit.contamination_found = audit.removed_iocs.length > 0;
  audit.contamination_ratio = rawIocs.length > 0
    ? (audit.removed_iocs.length / rawIocs.length).toFixed(3)
    : '0.000';

  return { cleanedItem, audit };
}

// ---------------------------------------------------------------------------
// 4. FEED-LEVEL RUNNER
// ---------------------------------------------------------------------------

/**
 * runIOCIntegrityValidation
 * Process entire feed array. Returns { cleanedFeed, report }.
 */
function runIOCIntegrityValidation(feed) {
  if (!Array.isArray(feed)) throw new Error('feed must be an array');

  const allAudits = [];
  const cleanedFeed = [];
  let totalContaminants = 0;
  let itemsWithContamination = 0;

  for (const item of feed) {
    const { cleanedItem, audit } = cleanIOCsForItem(item);
    cleanedFeed.push(cleanedItem);
    allAudits.push(audit);
    if (audit.contamination_found) {
      itemsWithContamination++;
      totalContaminants += audit.removed_iocs.length;
    }
  }

  const report = {
    validation_id: `IOC-VAL-${Date.now()}`,
    generated_at: new Date().toISOString(),
    validator_version: '1.0.0',
    feed_item_count: feed.length,
    items_with_contamination: itemsWithContamination,
    total_contaminants_removed: totalContaminants,
    contamination_rate: feed.length > 0
      ? ((itemsWithContamination / feed.length) * 100).toFixed(1) + '%'
      : '0.0%',
    severity: itemsWithContamination > feed.length * 0.5 ? 'CRITICAL' :
              itemsWithContamination > feed.length * 0.2 ? 'HIGH' :
              itemsWithContamination > 0 ? 'MEDIUM' : 'CLEAN',
    item_audits: allAudits,
    recommendations: _buildRecommendations(allAudits),
  };

  return { cleanedFeed, report };
}

function _buildRecommendations(audits) {
  const recs = [];
  const contamTypes = {};
  for (const a of audits) {
    for (const [t, c] of Object.entries(a.contamination_types || {})) {
      contamTypes[t] = (contamTypes[t] || 0) + c;
    }
  }
  if (contamTypes['code/data file extension: .ts'] > 5) {
    recs.push('CRITICAL: TypeScript file "store.ts" appears as domain IOC in majority of items — IOC extraction pipeline is pulling from codebase file paths. Fix root cause in extraction layer.');
  }
  if (Object.keys(contamTypes).length > 0) {
    recs.push('Implement IOC extraction allowlist: only accept validated IPv4, IPv6, FQDN, URL, and hash patterns at ingestion time.');
    recs.push('Add IOC schema validation to STIX bundle generation pipeline before publishing feed.json.');
  }
  return recs;
}

// ---------------------------------------------------------------------------
// 5. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    validateIOC,
    cleanIOCsForItem,
    runIOCIntegrityValidation,
    classifyIOCType,
    INVALID_IOC_EXTENSIONS,
    INVALID_IOC_FILENAMES,
  };
}
