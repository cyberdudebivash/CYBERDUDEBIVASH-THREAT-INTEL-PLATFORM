/**
 * FEATURE FLAG MIDDLEWARE
 * Place at: /web3-api/middleware/featureFlag.js
 *
 * Gates all Web3 API routes behind WEB3_ENABLED flag.
 * Health endpoint is always excluded.
 */

'use strict';

/**
 * @param {boolean} enabled
 * @returns {import('express').RequestHandler}
 */
function featureFlag(enabled) {
  return function web3FeatureGate(req, res, next) {
    // Health check always passes
    if (req.path === '/web3-api/health') return next();

    if (!enabled) {
      return res.status(503).json({
        success:   false,
        error:     'Web3 module is currently disabled. Set WEB3_ENABLED=true to activate.',
        module:    'web3',
        timestamp: new Date().toISOString(),
      });
    }

    next();
  };
}

module.exports = { featureFlag };
