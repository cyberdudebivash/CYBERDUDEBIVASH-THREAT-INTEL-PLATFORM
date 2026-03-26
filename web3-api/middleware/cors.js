/**
 * CORS MIDDLEWARE
 * Place at: /web3-api/middleware/cors.js
 */

'use strict';

/**
 * Returns a CORS origin validator function.
 * Supports comma-separated list of allowed origins.
 *
 * @param {string} allowedOrigins - comma-separated origins, or '*'
 * @returns {Function}
 */
function validateOrigin(allowedOrigins) {
  if (allowedOrigins === '*') return '*';

  const origins = allowedOrigins
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  return function (origin, callback) {
    // Allow non-browser requests (server-to-server, curl) in dev
    if (!origin) return callback(null, true);

    if (origins.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error(`CORS: Origin '${origin}' not allowed`));
  };
}

module.exports = { validateOrigin };
