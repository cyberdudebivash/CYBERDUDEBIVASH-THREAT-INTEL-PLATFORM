/**
 * WEB3 MODULE FEATURE FLAG CONFIGURATION
 * ========================================
 * ZERO REGRESSION GUARANTEE: This flag gates the ENTIRE Web3 subsystem.
 * Setting WEB3_ENABLED = false instantly disables all Web3 features
 * without touching any existing Sentinel APEX systems.
 *
 * Place this file at: /config/web3.config.js
 */

const WEB3_CONFIG = {
  // ─── MASTER KILL SWITCH ────────────────────────────────────────────────────
  WEB3_ENABLED: process.env.NEXT_PUBLIC_WEB3_ENABLED === 'true' || false,

  // ─── API ENDPOINTS (Isolated from core system) ─────────────────────────────
  API_BASE_URL: process.env.NEXT_PUBLIC_WEB3_API_URL || '/web3-api',

  // ─── RATE LIMITING ─────────────────────────────────────────────────────────
  RATE_LIMITS: {
    walletAnalyzer: 10,      // requests per minute
    contractScanner: 5,
    threatFeed: 60,
    transactions: 30,
  },

  // ─── CACHE SETTINGS ────────────────────────────────────────────────────────
  CACHE_TTL: {
    walletData: 5 * 60 * 1000,        // 5 minutes
    contractData: 15 * 60 * 1000,     // 15 minutes
    threatFeed: 2 * 60 * 1000,        // 2 minutes
    transactions: 1 * 60 * 1000,      // 1 minute
  },

  // ─── TIMEOUT SETTINGS (Failure containment) ────────────────────────────────
  TIMEOUTS: {
    walletAnalyzer: 15000,    // 15s
    contractScanner: 30000,   // 30s
    threatFeed: 10000,        // 10s
    transactions: 10000,      // 10s
  },

  // ─── SUPPORTED NETWORKS ────────────────────────────────────────────────────
  NETWORKS: {
    ethereum: { id: 1, name: 'Ethereum', symbol: 'ETH' },
    polygon:  { id: 137, name: 'Polygon', symbol: 'MATIC' },
    bsc:      { id: 56, name: 'BSC', symbol: 'BNB' },
  },

  // ─── RISK THRESHOLDS ───────────────────────────────────────────────────────
  RISK_THRESHOLDS: {
    LOW:      { min: 0,  max: 30,  color: '#00ff88', label: 'LOW' },
    MEDIUM:   { min: 31, max: 60,  color: '#ffaa00', label: 'MEDIUM' },
    HIGH:     { min: 61, max: 80,  color: '#ff6600', label: 'HIGH' },
    CRITICAL: { min: 81, max: 100, color: '#ff0044', label: 'CRITICAL' },
  },
};

module.exports = WEB3_CONFIG;
