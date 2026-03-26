/**
 * INPUT VALIDATION UTILITIES
 * Place at: /web3-api/utils/validators.js
 *
 * All user inputs are validated here before any processing.
 * Never trust client-supplied data.
 */

'use strict';

// ─── ADDRESS VALIDATION ────────────────────────────────────────────────────────
const ETH_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const TX_HASH_RE     = /^0x[a-fA-F0-9]{64}$/;

/**
 * @param {string} address
 * @returns {{ valid: boolean; error?: string }}
 */
function validateAddress(address) {
  if (!address || typeof address !== 'string') {
    return { valid: false, error: 'Address is required and must be a string' };
  }
  const trimmed = address.trim();
  if (!ETH_ADDRESS_RE.test(trimmed)) {
    return { valid: false, error: 'Invalid Ethereum address format. Must be 0x followed by 40 hex characters.' };
  }
  return { valid: true };
}

/**
 * @param {string} hash
 * @returns {{ valid: boolean; error?: string }}
 */
function validateTxHash(hash) {
  if (!hash || typeof hash !== 'string') {
    return { valid: false, error: 'Transaction hash is required' };
  }
  if (!TX_HASH_RE.test(hash.trim())) {
    return { valid: false, error: 'Invalid transaction hash format' };
  }
  return { valid: true };
}

// ─── NETWORK VALIDATION ────────────────────────────────────────────────────────
const SUPPORTED_NETWORKS = new Set(['ethereum', 'polygon', 'bsc']);

/**
 * @param {string} network
 * @returns {{ valid: boolean; error?: string }}
 */
function validateNetwork(network) {
  if (!network) return { valid: true }; // Optional field
  if (!SUPPORTED_NETWORKS.has(network)) {
    return {
      valid: false,
      error: `Unsupported network: '${network}'. Supported: ${[...SUPPORTED_NETWORKS].join(', ')}`,
    };
  }
  return { valid: true };
}

// ─── SOLIDITY CODE VALIDATION ─────────────────────────────────────────────────
const MAX_CODE_LENGTH = 50_000; // 50KB max

/**
 * @param {string} code
 * @returns {{ valid: boolean; error?: string }}
 */
function validateSolidityCode(code) {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Contract source code is required' };
  }
  if (code.length > MAX_CODE_LENGTH) {
    return { valid: false, error: `Contract code too large. Max ${MAX_CODE_LENGTH} characters.` };
  }
  // Basic Solidity sanity check
  if (!code.includes('pragma solidity') && !code.includes('contract ') && !code.includes('interface ')) {
    return { valid: false, error: 'Does not appear to be valid Solidity code' };
  }
  return { valid: true };
}

// ─── PAGINATION VALIDATION ─────────────────────────────────────────────────────
/**
 * @param {{ page?: any; limit?: any }} params
 * @returns {{ page: number; limit: number; error?: string }}
 */
function validatePagination(params) {
  let page  = parseInt(params.page, 10);
  let limit = parseInt(params.limit, 10);

  if (isNaN(page)  || page  < 1)   page  = 1;
  if (isNaN(limit) || limit < 1)   limit = 20;
  if (limit > 100) limit = 100;    // Hard cap — prevent abuse

  return { page, limit };
}

// ─── GENERIC STRING SANITIZER ─────────────────────────────────────────────────
/**
 * Strips potential injection characters from a string field.
 * @param {string} value
 * @param {number} [maxLen=64]
 * @returns {string}
 */
function sanitizeString(value, maxLen = 64) {
  if (!value || typeof value !== 'string') return '';
  return value
    .trim()
    .slice(0, maxLen)
    .replace(/[<>"'`\\]/g, '');
}

// ─── SEVERITY / CATEGORY WHITELIST VALIDATION ─────────────────────────────────
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const VALID_CATEGORIES = new Set([
  'rug-pull', 'exploit', 'phishing', 'malicious-wallet',
  'flash-loan-attack', 'bridge-hack', 'oracle-manipulation',
  'governance-attack', 'private-key-compromise',
]);

/**
 * @param {string} value
 * @returns {string|undefined}
 */
function validateSeverity(value) {
  if (!value) return undefined;
  const upper = String(value).toUpperCase();
  return VALID_SEVERITIES.has(upper) ? upper : undefined;
}

/**
 * @param {string} value
 * @returns {string|undefined}
 */
function validateCategory(value) {
  if (!value) return undefined;
  const lower = String(value).toLowerCase();
  return VALID_CATEGORIES.has(lower) ? lower : undefined;
}

module.exports = {
  validateAddress,
  validateTxHash,
  validateNetwork,
  validateSolidityCode,
  validatePagination,
  validateSeverity,
  validateCategory,
  sanitizeString,
};
