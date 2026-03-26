/**
 * ERROR HANDLER MIDDLEWARE
 * Place at: /web3-api/middleware/errorHandler.js
 *
 * Catches all unhandled errors in the Web3 API layer.
 * Ensures no stack traces leak in production.
 */

'use strict';

const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * @param {Error} err
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const status = err.status || err.statusCode || 500;

  console.error(`[WEB3-API ERROR] ${req.method} ${req.path} → ${err.message}`);

  res.status(status).json({
    success:   false,
    error:     NODE_ENV === 'production'
      ? 'An internal error occurred in the Web3 module'
      : err.message,
    ...(NODE_ENV !== 'production' && { stack: err.stack }),
    timestamp: new Date().toISOString(),
  });
}

module.exports = { errorHandler };
