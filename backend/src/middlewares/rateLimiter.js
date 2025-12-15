'use strict';
const rateLimit = require('express-rate-limit');
const logger = require('../config/logger');

const rateLimitHandler = (req, res) => {
  logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
  res.status(429).json({ success: false, error: 'Trop de requêtes. Réessayez plus tard.' });
};

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Trop de requêtes' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  skip: (req) => req.path === '/health'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, error: 'Trop de tentatives de connexion' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  skipSuccessfulRequests: true
});

const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, error: 'Trop de comptes créés' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});

module.exports = { globalLimiter, authLimiter, createAccountLimiter, apiLimiter };
