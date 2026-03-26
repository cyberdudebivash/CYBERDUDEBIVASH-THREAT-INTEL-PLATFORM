/**
 * WEB3 API SERVER — MAIN ENTRY POINT
 * =====================================
 * Place at: /web3-api/server.js
 *
 * ISOLATION GUARANTEE:
 * - Runs on a SEPARATE PORT (default: 3001)
 * - Zero shared state with core Sentinel APEX backend
 * - Independent process — crash here = zero impact on main system
 *
 * Start: node web3-api/server.js
 * Or:    WEB3_PORT=3001 node web3-api/server.js
 */

'use strict';

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const morgan     = require('morgan');

// ─── ROUTE MODULES ────────────────────────────────────────────────────────────
const dashboardRoutes    = require('./routes/dashboard');
const walletRoutes       = require('./routes/wallet');
const contractRoutes     = require('./routes/contract');
const threatRoutes       = require('./routes/threats');
const transactionRoutes  = require('./routes/transactions');

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
const { validateOrigin } = require('./middleware/cors');
const { errorHandler }   = require('./middleware/errorHandler');
const { featureFlag }    = require('./middleware/featureFlag');

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const PORT         = process.env.WEB3_PORT         || 3001;
const WEB3_ENABLED = process.env.WEB3_ENABLED      === 'true';
const CORS_ORIGIN  = process.env.WEB3_CORS_ORIGIN  || 'http://localhost:3000';
const NODE_ENV     = process.env.NODE_ENV           || 'development';

// ─── APP INIT ─────────────────────────────────────────────────────────────────
const app = express();

// ─── SECURITY HEADERS ────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
    },
  },
}));

// ─── CORS — ISOLATED POLICY ───────────────────────────────────────────────────
app.use(cors({
  origin:      validateOrigin(CORS_ORIGIN),
  methods:     ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-Module', 'X-API-Key'],
  credentials: false,
}));

// ─── BODY PARSING ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '256kb' }));    // Strict limit — no large payloads
app.use(express.urlencoded({ extended: false }));

// ─── LOGGING ─────────────────────────────────────────────────────────────────
if (NODE_ENV !== 'test') {
  app.use(morgan('[:date[iso]] :method :url :status :response-time ms'));
}

// ─── GLOBAL RATE LIMITING ────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,   // 15 minutes
  max:             200,
  standardHeaders: true,
  legacyHeaders:   false,
  message: {
    success:   false,
    error:     'Too many requests. Please try again later.',
    timestamp: new Date().toISOString(),
  },
  keyGenerator: (req) => req.ip,
});
app.use(globalLimiter);

// ─── FEATURE FLAG GATE ────────────────────────────────────────────────────────
// Any request to /web3-api/* hits this first.
// If WEB3_ENABLED=false, returns 503 immediately.
app.use(featureFlag(WEB3_ENABLED));

// ─── HEALTH CHECK (always available, even when WEB3_ENABLED=false) ────────────
app.get('/web3-api/health', (req, res) => {
  res.json({
    status:      'ok',
    module:      'web3',
    enabled:     WEB3_ENABLED,
    timestamp:   new Date().toISOString(),
    uptime:      process.uptime(),
    version:     process.env.npm_package_version || '1.0.0',
  });
});

// ─── API ROUTES ───────────────────────────────────────────────────────────────
// All prefixed with /web3-api to avoid collision with core system
app.use('/web3-api/dashboard',    dashboardRoutes);
app.use('/web3-api/wallet',       walletRoutes);
app.use('/web3-api/contract',     contractRoutes);
app.use('/web3-api/threats',      threatRoutes);
app.use('/web3-api/transactions', transactionRoutes);

// ─── 404 HANDLER ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success:   false,
    error:     `Web3 API route not found: ${req.method} ${req.path}`,
    timestamp: new Date().toISOString(),
  });
});

// ─── GLOBAL ERROR HANDLER ─────────────────────────────────────────────────────
app.use(errorHandler);

// ─── UNCAUGHT EXCEPTION SAFETY ───────────────────────────────────────────────
// Critical: Web3 process errors must never propagate to main system
process.on('uncaughtException', (err) => {
  console.error('[WEB3-API] Uncaught exception (contained):', err.message);
  // In production, alert + graceful restart. Don't exit in dev.
  if (NODE_ENV === 'production') process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('[WEB3-API] Unhandled rejection (contained):', reason);
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[WEB3-API] 🛡  Server running on port ${PORT}`);
    console.log(`[WEB3-API] 🔧  Feature flag: ${WEB3_ENABLED ? 'ENABLED ✓' : 'DISABLED ✗'}`);
    console.log(`[WEB3-API] 🌐  CORS origin:  ${CORS_ORIGIN}`);
    console.log(`[WEB3-API] ⚙️   Environment: ${NODE_ENV}`);
  });
}

module.exports = app; // Export for testing
