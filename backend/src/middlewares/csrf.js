/**
 * =============================================================================
 * MIDDLEWARES/CSRF.JS - Protection CSRF (version stable)
 * =============================================================================
 *
 * Ici, je protège l'API contre le CSRF avec un modèle simple et robuste :
 * - Je stocke un secret CSRF côté cookie httpOnly (non accessible en JS).
 * - Je renvoie au client un token dérivé (HMAC) via /api/csrf-token.
 * - Le client doit renvoyer ce token dérivé dans le header X-CSRF-Token.
 * - Je compare le token reçu avec l'HMAC attendu.
 *
 * Objectif: éviter qu'un site externe puisse forcer une action (POST/PUT/PATCH/DELETE)
 * sans que le navigateur de l'utilisateur envoie un token valide.
 * =============================================================================
 */

'use strict';

const crypto = require('crypto');
const logger = require('../config/logger');

const generateCsrfToken = () => crypto.randomBytes(32).toString('hex');

const hashToken = (token, secret) =>
  crypto.createHmac('sha256', secret).update(token).digest('hex');

const csrfProtection = (options = {}) => {
  const {
    secret = process.env.CSRF_SECRET || process.env.JWT_SECRET,
    cookieName = '_csrf',
    headerName = 'x-csrf-token',
    bodyField = '_csrf',
    methods = ['POST', 'PUT', 'DELETE', 'PATCH'],
    ignorePaths = [
      '/api/auth/login',
      '/api/auth/register',
      '/api/auth/refresh',
      '/api/csrf-token',
      '/health',
    ],
    cookieOptions = {},
  } = options;

  if (!secret) {
    throw new Error('CSRF_SECRET ou JWT_SECRET doit être défini');
  }

  // Je ne couple pas "secure" à NODE_ENV : je pilote ça proprement via env.
  const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
  const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'lax';
  const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

  return (req, res, next) => {
    // 1) Je crée le secret CSRF (cookie) si je ne l'ai pas encore
    let csrfSecret = req.cookies?.[cookieName];

    if (!csrfSecret) {
      csrfSecret = generateCsrfToken();

      res.cookie(cookieName, csrfSecret, {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: COOKIE_SAMESITE,
        domain: COOKIE_DOMAIN,
        maxAge: 24 * 60 * 60 * 1000, // 24h
        path: '/',
        ...cookieOptions,
      });
    }

    // 2) Je calcule le token que je permets au client de renvoyer
    const expected = hashToken(csrfSecret, secret);

    res.locals.csrfToken = expected;
    req.csrfToken = () => expected;

    // 3) Je vérifie le token sur les méthodes mutantes (sauf chemins ignorés)
    if (methods.includes(req.method)) {
      if (ignorePaths.some((p) => req.path.startsWith(p))) {
        return next();
      }

      const submitted =
        req.headers?.[headerName] ||
        req.headers?.[headerName.toLowerCase()] ||
        req.body?.[bodyField] ||
        req.query?.[bodyField];

      if (!submitted) {
        logger.warn('CSRF token manquant', { path: req.path, method: req.method, ip: req.ip });
        return res.status(403).json({ success: false, error: 'Token CSRF manquant' });
      }

      if (submitted !== expected) {
        logger.warn('CSRF token invalide', { path: req.path, method: req.method, ip: req.ip });
        return res.status(403).json({ success: false, error: 'Token CSRF invalide' });
      }
    }

    return next();
  };
};

const getCsrfToken = (req, res) => {
  // Je renvoie un format simple et stable pour le frontend.
  res.json({
    success: true,
    csrfToken: req.csrfToken(),
  });
};

module.exports = {
  csrfProtection,
  getCsrfToken,
  generateCsrfToken,
  hashToken,
};
