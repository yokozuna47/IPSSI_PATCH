/**
 * =============================================================================
 * MIDDLEWARES/HEADERS-SECURITY.JS - Validation User-Agent & Referer
 * =============================================================================
 * 
 * Protection contre :
 * - User-Agent spoofing
 * - Referer manipulation
 * - Bots malveillants
 * - Requêtes automatisées non autorisées
 * 
 * =============================================================================
 */

'use strict';

const logger = require('../config/logger');

/**
 * Liste des User-Agents bloqués (bots malveillants, scanners, etc.)
 */
const BLOCKED_USER_AGENTS = [
  /sqlmap/i,          // SQL injection tool
  /nikto/i,           // Web scanner
  /nessus/i,          // Vulnerability scanner
  /nmap/i,            // Network scanner
  /masscan/i,         // Port scanner
  /zgrab/i,           // Scanner
  /gobuster/i,        // Directory brute-force
  /dirbuster/i,       // Directory brute-force
  /wfuzz/i,           // Fuzzer
  /hydra/i,           // Brute-force tool
  /medusa/i,          // Brute-force tool
  /burp/i,            // Burp Suite
  /owasp/i,           // ZAP
  /acunetix/i,        // Web scanner
  /havij/i,           // SQL injection
  /w3af/i,            // Web scanner
  /metasploit/i,      // Exploit framework
  /curl\/.*libcurl/i, // curl avec libcurl (scripts automatisés)
  /python-requests/i, // Python requests (souvent utilisé pour scraping)
  /scrapy/i,          // Web scraper
  /wget/i,            // Téléchargeur
  /libwww-perl/i,     // Perl scripts
  /java\//i,          // Java bots
  /^$/,               // User-Agent vide
];

/**
 * User-Agents légitimes autorisés (patterns)
 */
const ALLOWED_USER_AGENTS = [
  /mozilla/i,
  /chrome/i,
  /safari/i,
  /firefox/i,
  /edge/i,
  /opera/i,
  /android/i,
  /iphone/i,
  /ipad/i,
  /mobile/i,
];

/**
 * Domaines de referer autorisés
 */
const ALLOWED_REFERERS = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  process.env.BACKEND_URL || 'http://localhost:8000',
  'http://localhost',
  'https://localhost',
];

/**
 * Middleware de validation du User-Agent
 */
const validateUserAgent = (options = {}) => {
  const { 
    strict = false,      // Mode strict : bloque si User-Agent absent
    logOnly = false      // Log uniquement, ne bloque pas
  } = options;

  return (req, res, next) => {
    const userAgent = req.get('User-Agent') || '';

    // Vérifie si le User-Agent est bloqué
    for (const pattern of BLOCKED_USER_AGENTS) {
      if (pattern.test(userAgent)) {
        logger.warn('User-Agent bloqué', {
          userAgent,
          ip: req.ip,
          path: req.path,
          method: req.method
        });

        if (!logOnly) {
          return res.status(403).json({
            success: false,
            error: 'Accès refusé'
          });
        }
      }
    }

    // Mode strict : vérifie que le User-Agent est légitime
    if (strict && userAgent) {
      const isLegitimate = ALLOWED_USER_AGENTS.some(pattern => 
        pattern.test(userAgent)
      );

      if (!isLegitimate) {
        logger.warn('User-Agent suspect', {
          userAgent,
          ip: req.ip,
          path: req.path
        });

        if (!logOnly) {
          return res.status(403).json({
            success: false,
            error: 'Accès refusé'
          });
        }
      }
    }

    // User-Agent absent
    if (!userAgent) {
      logger.warn('User-Agent absent', {
        ip: req.ip,
        path: req.path
      });

      if (strict && !logOnly) {
        return res.status(400).json({
          success: false,
          error: 'User-Agent requis'
        });
      }
    }

    // Stocke le User-Agent pour logging
    req.userAgentInfo = {
      raw: userAgent,
      isBot: !ALLOWED_USER_AGENTS.some(p => p.test(userAgent))
    };

    next();
  };
};

/**
 * Middleware de validation du Referer
 * 
 * Vérifie que les requêtes POST/PUT/DELETE proviennent
 * d'une origine autorisée.
 */
const validateReferer = (options = {}) => {
  const {
    allowEmpty = true,    // Autorise les requêtes sans Referer
    logOnly = false,
    methods = ['POST', 'PUT', 'DELETE', 'PATCH']
  } = options;

  return (req, res, next) => {
    // Ne vérifie que certaines méthodes
    if (!methods.includes(req.method)) {
      return next();
    }

    const referer = req.get('Referer') || req.get('Referrer') || '';
    const origin = req.get('Origin') || '';

    // Autorise les requêtes sans Referer si configuré
    if (!referer && !origin) {
      if (allowEmpty) {
        return next();
      }
      
      logger.warn('Referer/Origin absent pour méthode sensible', {
        method: req.method,
        path: req.path,
        ip: req.ip
      });

      if (!logOnly) {
        return res.status(403).json({
          success: false,
          error: 'Origine non vérifiable'
        });
      }
      return next();
    }

    // Vérifie que le Referer/Origin est autorisé
    const sourceUrl = referer || origin;
    const isAllowed = ALLOWED_REFERERS.some(allowed => 
      sourceUrl.startsWith(allowed)
    );

    if (!isAllowed) {
      logger.warn('Referer/Origin non autorisé', {
        referer,
        origin,
        ip: req.ip,
        path: req.path,
        method: req.method
      });

      if (!logOnly) {
        return res.status(403).json({
          success: false,
          error: 'Origine non autorisée'
        });
      }
    }

    next();
  };
};

/**
 * Middleware combiné pour la sécurité des headers
 */
const headersSecurity = (options = {}) => {
  return (req, res, next) => {
    // Ajoute des headers de sécurité supplémentaires
    res.setHeader('X-Request-ID', req.id || Math.random().toString(36).substr(2, 9));
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    // Valide User-Agent
    validateUserAgent(options)(req, res, (err) => {
      if (err) return next(err);
      
      // Valide Referer
      validateReferer(options)(req, res, next);
    });
  };
};

module.exports = {
  validateUserAgent,
  validateReferer,
  headersSecurity,
  BLOCKED_USER_AGENTS,
  ALLOWED_REFERERS
};
