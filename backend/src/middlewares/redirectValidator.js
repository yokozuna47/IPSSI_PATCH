/**
 * =============================================================================
 * MIDDLEWARES/REDIRECT-VALIDATOR.JS - Protection Open Redirect
 * =============================================================================
 * 
 * Protection contre :
 * - Open Redirect attacks
 * - URL manipulation
 * - Protocol switching attacks (http → javascript:)
 * 
 * =============================================================================
 */

'use strict';

const url = require('url');
const logger = require('../config/logger');
const { AppError } = require('./errorHandler');

/**
 * Domaines autorisés pour les redirections
 */
const ALLOWED_REDIRECT_DOMAINS = [
  'localhost',
  '127.0.0.1',
  process.env.FRONTEND_DOMAIN || 'localhost',
  process.env.BACKEND_DOMAIN || 'localhost',
];

/**
 * Protocoles autorisés
 */
const ALLOWED_PROTOCOLS = ['http:', 'https:'];

/**
 * Patterns dangereux dans les URLs
 */
const DANGEROUS_URL_PATTERNS = [
  /javascript:/i,
  /vbscript:/i,
  /data:/i,
  /file:/i,
  /about:/i,
  /blob:/i,
  /\s*javascript/i, // Avec espaces avant
  /%0[aAdD]/,       // Newlines encodées (CRLF injection)
  /%09/,            // Tab encodé
  /@/,              // user@host trick
  /\/\//,           // Protocol-relative URLs (peut être détourné)
];

/**
 * Décode récursivement une URL
 */
const recursiveDecodeURI = (str, maxDepth = 5) => {
  if (maxDepth <= 0) return str;
  
  try {
    const decoded = decodeURIComponent(str);
    if (decoded === str) return str;
    return recursiveDecodeURI(decoded, maxDepth - 1);
  } catch (e) {
    return str;
  }
};

/**
 * Valide une URL de redirection
 * 
 * @param {string} redirectUrl - URL à valider
 * @param {Object} options - Options de validation
 * @returns {Object} - { valid: boolean, sanitized: string, reason: string }
 */
const validateRedirectUrl = (redirectUrl, options = {}) => {
  const {
    allowRelative = true,
    allowedDomains = ALLOWED_REDIRECT_DOMAINS,
    allowedProtocols = ALLOWED_PROTOCOLS,
  } = options;

  if (!redirectUrl || typeof redirectUrl !== 'string') {
    return { valid: false, reason: 'URL vide ou invalide' };
  }

  // Décode récursivement
  const decodedUrl = recursiveDecodeURI(redirectUrl.trim());

  // Vérifie les patterns dangereux
  for (const pattern of DANGEROUS_URL_PATTERNS) {
    if (pattern.test(redirectUrl) || pattern.test(decodedUrl)) {
      return {
        valid: false,
        reason: 'Pattern dangereux détecté',
        pattern: pattern.toString()
      };
    }
  }

  // Gère les URLs relatives
  if (decodedUrl.startsWith('/') && !decodedUrl.startsWith('//')) {
    if (!allowRelative) {
      return { valid: false, reason: 'URLs relatives non autorisées' };
    }
    
    // URL relative valide
    return {
      valid: true,
      sanitized: decodedUrl,
      type: 'relative'
    };
  }

  // Parse l'URL
  let parsedUrl;
  try {
    parsedUrl = new URL(decodedUrl);
  } catch (e) {
    // Si ce n'est pas une URL valide et qu'on autorise les relatives
    if (allowRelative && /^[a-zA-Z0-9\-._~:\/?#\[\]@!$&'()*+,;=]+$/.test(decodedUrl)) {
      // Traite comme chemin relatif
      return {
        valid: true,
        sanitized: '/' + decodedUrl.replace(/^\/+/, ''),
        type: 'relative'
      };
    }
    return { valid: false, reason: 'URL malformée' };
  }

  // Vérifie le protocole
  if (!allowedProtocols.includes(parsedUrl.protocol)) {
    return {
      valid: false,
      reason: `Protocole non autorisé: ${parsedUrl.protocol}`
    };
  }

  // Vérifie le domaine
  const hostname = parsedUrl.hostname.toLowerCase();
  const isAllowedDomain = allowedDomains.some(domain => {
    const domainLower = domain.toLowerCase();
    return hostname === domainLower || hostname.endsWith('.' + domainLower);
  });

  if (!isAllowedDomain) {
    return {
      valid: false,
      reason: `Domaine non autorisé: ${hostname}`
    };
  }

  // URL valide
  return {
    valid: true,
    sanitized: parsedUrl.href,
    type: 'absolute',
    hostname
  };
};

/**
 * Middleware de protection Open Redirect
 */
const redirectProtection = (options = {}) => {
  const {
    paramNames = ['redirect', 'redirect_uri', 'next', 'url', 'return', 'returnTo', 'return_to', 'goto', 'target'],
    allowRelative = true,
    logOnly = false
  } = options;

  return (req, res, next) => {
    // Collecte les valeurs à vérifier
    const valuesToCheck = [];

    // Vérifie query params
    for (const paramName of paramNames) {
      if (req.query[paramName]) {
        valuesToCheck.push({
          source: 'query',
          param: paramName,
          value: req.query[paramName]
        });
      }
    }

    // Vérifie body
    if (req.body) {
      for (const paramName of paramNames) {
        if (req.body[paramName]) {
          valuesToCheck.push({
            source: 'body',
            param: paramName,
            value: req.body[paramName]
          });
        }
      }
    }

    // Valide chaque URL
    for (const item of valuesToCheck) {
      const result = validateRedirectUrl(item.value, { allowRelative });

      if (!result.valid) {
        logger.warn('Open Redirect attempt blocked', {
          source: item.source,
          param: item.param,
          value: item.value.substring(0, 200),
          reason: result.reason,
          ip: req.ip,
          path: req.path,
          userAgent: req.get('User-Agent')
        });

        if (!logOnly) {
          return res.status(400).json({
            success: false,
            error: 'URL de redirection invalide'
          });
        }
      } else {
        // Remplace par l'URL sanitizée
        if (item.source === 'query') {
          req.query[item.param] = result.sanitized;
        } else if (item.source === 'body') {
          req.body[item.param] = result.sanitized;
        }
      }
    }

    next();
  };
};

/**
 * Helper pour effectuer une redirection sécurisée
 */
const safeRedirect = (res, redirectUrl, options = {}) => {
  const { fallback = '/', statusCode = 302 } = options;

  const result = validateRedirectUrl(redirectUrl, options);

  if (result.valid) {
    logger.info('Safe redirect', { url: result.sanitized });
    return res.redirect(statusCode, result.sanitized);
  } else {
    logger.warn('Redirect blocked, using fallback', {
      attemptedUrl: redirectUrl?.substring(0, 200),
      reason: result.reason,
      fallback
    });
    return res.redirect(statusCode, fallback);
  }
};

module.exports = {
  validateRedirectUrl,
  redirectProtection,
  safeRedirect,
  ALLOWED_REDIRECT_DOMAINS,
  ALLOWED_PROTOCOLS,
  DANGEROUS_URL_PATTERNS
};
