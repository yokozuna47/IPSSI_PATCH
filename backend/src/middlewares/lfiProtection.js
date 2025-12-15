/**
 * =============================================================================
 * MIDDLEWARES/LFI-PROTECTION.JS - Protection LFI / Path Traversal
 * =============================================================================
 * 
 * Protection contre :
 * - Local File Inclusion (LFI)
 * - Path Traversal (../)
 * - Data URI attacks
 * - Null byte injection
 * - URL encoding bypass
 * 
 * =============================================================================
 */

'use strict';

const path = require('path');
const logger = require('../config/logger');
const { AppError } = require('./errorHandler');

/**
 * Patterns dangereux à détecter
 */
const DANGEROUS_PATTERNS = [
  // Path Traversal
  /\.\.\//g,                      // ../
  /\.\.\\/g,                      // ..\
  /%2e%2e%2f/gi,                  // URL encoded ../
  /%2e%2e\//gi,                   // Mixed encoding
  /\.\.%2f/gi,                    // Mixed encoding
  /%2e%2e%5c/gi,                  // URL encoded ..\
  /%252e%252e%252f/gi,            // Double URL encoded
  /\.%2e\//gi,                    // Partial encoding
  /%2e\.\//gi,                    // Partial encoding
  
  // Null byte
  /%00/g,                         // Null byte URL encoded
  /\x00/g,                        // Null byte raw
  
  // Fichiers sensibles
  /\/etc\/passwd/gi,
  /\/etc\/shadow/gi,
  /\/etc\/hosts/gi,
  /\/proc\/self/gi,
  /\/var\/log/gi,
  /\/windows\/system32/gi,
  /boot\.ini/gi,
  /win\.ini/gi,
  
  // Wrappers PHP/protocoles dangereux
  /php:\/\//gi,
  /data:/gi,
  /file:\/\//gi,
  /zip:\/\//gi,
  /phar:\/\//gi,
  /expect:\/\//gi,
  /glob:\/\//gi,
  /input:\/\//gi,
  /filter:\/\//gi,
  
  // Sensibles
  /\.htaccess/gi,
  /\.htpasswd/gi,
  /\.git/gi,
  /\.svn/gi,
  /\.env/gi,
  /config\.php/gi,
  /wp-config/gi,
];

/**
 * Dossiers autorisés (whitelist)
 */
const ALLOWED_DIRECTORIES = [
  '/uploads',
  '/public',
  '/static',
  '/assets',
  '/images',
];

/**
 * Décode récursivement les URL encodées
 * Pour détecter les tentatives de bypass par double/triple encoding
 */
const recursiveDecodeURI = (str, maxDepth = 5) => {
  if (maxDepth <= 0) return str;
  
  try {
    const decoded = decodeURIComponent(str);
    if (decoded === str) return str; // Plus rien à décoder
    return recursiveDecodeURI(decoded, maxDepth - 1);
  } catch (e) {
    return str;
  }
};

/**
 * Normalise et sécurise un chemin
 */
const sanitizePath = (inputPath) => {
  if (!inputPath || typeof inputPath !== 'string') {
    return '';
  }

  // Décode récursivement
  let decodedPath = recursiveDecodeURI(inputPath);

  // Supprime les null bytes
  decodedPath = decodedPath.replace(/\x00/g, '');
  decodedPath = decodedPath.replace(/%00/g, '');

  // Normalise les slashes
  decodedPath = decodedPath.replace(/\\/g, '/');

  // Supprime les doubles slashes
  decodedPath = decodedPath.replace(/\/+/g, '/');

  // Résout le chemin et vérifie qu'il ne remonte pas
  const normalized = path.normalize(decodedPath);

  return normalized;
};

/**
 * Vérifie si un chemin est sûr
 */
const isPathSafe = (inputPath, allowedBase = null) => {
  const sanitized = sanitizePath(inputPath);

  // Vérifie les patterns dangereux
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(inputPath) || pattern.test(sanitized)) {
      return {
        safe: false,
        reason: 'Pattern dangereux détecté',
        pattern: pattern.toString()
      };
    }
  }

  // Si une base est spécifiée, vérifie que le chemin reste dans la base
  if (allowedBase) {
    const resolvedBase = path.resolve(allowedBase);
    const resolvedPath = path.resolve(allowedBase, sanitized);

    if (!resolvedPath.startsWith(resolvedBase)) {
      return {
        safe: false,
        reason: 'Chemin sort du dossier autorisé'
      };
    }
  }

  return { safe: true, sanitized };
};

/**
 * Middleware de protection LFI
 */
const lfiProtection = (options = {}) => {
  const {
    checkBody = true,
    checkQuery = true,
    checkParams = true,
    allowedBase = process.env.UPLOAD_DIR || './uploads',
    logOnly = false
  } = options;

  return (req, res, next) => {
    const valuesToCheck = [];

    // Collecte les valeurs à vérifier
    if (checkQuery && req.query) {
      Object.entries(req.query).forEach(([key, value]) => {
        if (typeof value === 'string') {
          valuesToCheck.push({ source: 'query', key, value });
        }
      });
    }

    if (checkParams && req.params) {
      Object.entries(req.params).forEach(([key, value]) => {
        if (typeof value === 'string') {
          valuesToCheck.push({ source: 'params', key, value });
        }
      });
    }

    if (checkBody && req.body) {
      const checkObject = (obj, prefix = '') => {
        Object.entries(obj).forEach(([key, value]) => {
          const fullKey = prefix ? `${prefix}.${key}` : key;
          if (typeof value === 'string') {
            valuesToCheck.push({ source: 'body', key: fullKey, value });
          } else if (typeof value === 'object' && value !== null) {
            checkObject(value, fullKey);
          }
        });
      };
      checkObject(req.body);
    }

    // Vérifie chaque valeur
    for (const item of valuesToCheck) {
      const result = isPathSafe(item.value, allowedBase);

      if (!result.safe) {
        logger.warn('LFI/Path Traversal attempt blocked', {
          source: item.source,
          key: item.key,
          value: item.value.substring(0, 100),
          reason: result.reason,
          pattern: result.pattern,
          ip: req.ip,
          path: req.path,
          method: req.method,
          userAgent: req.get('User-Agent')
        });

        if (!logOnly) {
          return res.status(400).json({
            success: false,
            error: 'Requête invalide'
          });
        }
      }
    }

    next();
  };
};

/**
 * Middleware spécifique pour les routes de fichiers/médias
 */
const mediaPathProtection = (allowedDir) => {
  return (req, res, next) => {
    const requestedFile = req.params.filename || req.params.file || req.params.path;

    if (!requestedFile) {
      return next();
    }

    // Vérifie le chemin
    const result = isPathSafe(requestedFile, allowedDir);

    if (!result.safe) {
      logger.warn('Media path traversal blocked', {
        requestedFile,
        reason: result.reason,
        ip: req.ip
      });

      return res.status(403).json({
        success: false,
        error: 'Accès refusé'
      });
    }

    // Attache le chemin sanitizé
    req.sanitizedPath = result.sanitized;
    next();
  };
};

/**
 * Protection contre les Data URI
 */
const blockDataURI = (req, res, next) => {
  const checkValue = (value) => {
    if (typeof value !== 'string') return false;
    const decoded = recursiveDecodeURI(value);
    return /^data:/i.test(decoded);
  };

  // Vérifie query, body et params
  const allValues = [
    ...Object.values(req.query || {}),
    ...Object.values(req.params || {}),
    ...JSON.stringify(req.body || {}).match(/"[^"]*"/g) || []
  ];

  for (const value of allValues) {
    if (checkValue(value)) {
      logger.warn('Data URI blocked', {
        ip: req.ip,
        path: req.path
      });

      return res.status(400).json({
        success: false,
        error: 'Format non autorisé'
      });
    }
  }

  next();
};

module.exports = {
  lfiProtection,
  mediaPathProtection,
  blockDataURI,
  isPathSafe,
  sanitizePath,
  DANGEROUS_PATTERNS,
  ALLOWED_DIRECTORIES
};
