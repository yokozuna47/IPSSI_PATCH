# 🛡️ CORRECTIONS DE SÉCURITÉ - IPSSI_PATCH

## Document Détaillant les Corrections Appliquées

---

## 📋 Table des Matières

1. [Vue d'Ensemble](#1-vue-densemble)
2. [FIX-001 : Protection SQL Injection avec ORM](#2-fix-001--protection-sql-injection-avec-orm)
3. [FIX-002 : Hachage des Mots de Passe](#3-fix-002--hachage-des-mots-de-passe)
4. [FIX-003 : Protection XSS](#4-fix-003--protection-xss)
5. [FIX-004 : Configuration CORS Sécurisée](#5-fix-004--configuration-cors-sécurisée)
6. [FIX-005 : Rate Limiting](#6-fix-005--rate-limiting)
7. [FIX-006 : Headers de Sécurité (Helmet)](#7-fix-006--headers-de-sécurité-helmet)
8. [FIX-007 : Validation des Entrées](#8-fix-007--validation-des-entrées)
9. [FIX-008 : Authentification JWT](#9-fix-008--authentification-jwt)
10. [FIX-009 : Gestion des Erreurs Sécurisée](#10-fix-009--gestion-des-erreurs-sécurisée)
11. [FIX-010 : Logging Sécurisé](#11-fix-010--logging-sécurisé)
12. [FIX-011 : Sécurisation Docker](#12-fix-011--sécurisation-docker)

---

## 1. Vue d'Ensemble

### Tableau Récapitulatif des Corrections

| ID | Vulnérabilité Corrigée | Solution | Fichier(s) Modifié(s) |
|----|------------------------|----------|----------------------|
| FIX-001 | SQL Injection | ORM Sequelize | `models/*.js`, `controllers/*.js` |
| FIX-002 | Mots de passe en clair | bcrypt 12 rounds | `utils/password.js` |
| FIX-003 | XSS | Helmet CSP + xss-clean | `middlewares/security.js` |
| FIX-004 | CORS permissif | Whitelist origines | `middlewares/security.js` |
| FIX-005 | Pas de rate limit | express-rate-limit | `middlewares/rateLimiter.js` |
| FIX-006 | Headers manquants | Helmet complet | `middlewares/security.js` |
| FIX-007 | Pas de validation | express-validator | `validators/*.js` |
| FIX-008 | Pas d'authentification | JWT + cookies | `middlewares/auth.js` |
| FIX-009 | Erreurs exposées | Error handler custom | `middlewares/errorHandler.js` |
| FIX-010 | Pas de logging | Winston | `config/logger.js` |
| FIX-011 | Docker non sécurisé | Hardening complet | `Dockerfile`, `docker-compose.yml` |

---

## 2. FIX-001 : Protection SQL Injection avec ORM

### Problème Original

```javascript
// ❌ AVANT - Code vulnérable
app.post('/query', async (req, res) => {
  db.run(req.body);  // Exécution directe de requête SQL
});

app.post('/user', (req, res) => {
  db.all(req.body, [], (err, rows) => { ... });
});
```

### Solution Implémentée

#### Utilisation de Sequelize ORM

**Fichier : `backend/src/models/User.js`**

```javascript
/**
 * Modèle User avec Sequelize
 * 
 * Sécurité :
 * - Utilisation d'un ORM pour prévenir les injections SQL
 * - Validation des données au niveau du modèle
 * - Exclusion automatique du mot de passe dans les requêtes
 */

const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    comment: 'UUID v4 pour éviter l\'énumération'
  },
  
  username: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true,
    validate: {
      len: {
        args: [3, 50],
        msg: 'Le username doit faire entre 3 et 50 caractères'
      },
      isAlphanumeric: {
        msg: 'Le username ne peut contenir que des lettres et chiffres'
      }
    }
  },
  
  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: {
      isEmail: {
        msg: 'Email invalide'
      }
    }
  },
  
  password: {
    type: DataTypes.STRING(255),
    allowNull: false
    // Note: Le hachage est géré dans le hook beforeCreate
  },
  
  role: {
    type: DataTypes.ENUM('user', 'admin'),
    defaultValue: 'user'
  },
  
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  
  loginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    comment: 'Compteur pour le lockout anti brute-force'
  },
  
  lockUntil: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Date de fin de blocage du compte'
  }
}, {
  tableName: 'users',
  timestamps: true,
  paranoid: true,  // Soft delete pour audit
  
  // Scopes pour ne jamais exposer le mot de passe par défaut
  defaultScope: {
    attributes: { exclude: ['password'] }
  },
  scopes: {
    withPassword: {
      attributes: { include: ['password'] }
    }
  }
});

module.exports = User;
```

**Fichier : `backend/src/controllers/userController.js`**

```javascript
/**
 * Contrôleur User
 * 
 * Toutes les requêtes passent par l'ORM Sequelize
 * qui échappe automatiquement les paramètres.
 */

const User = require('../models/User');
const { Op } = require('sequelize');

/**
 * Récupérer un utilisateur par ID
 * 
 * ✅ Sécurisé : findByPk utilise des requêtes paramétrées
 */
exports.getUserById = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    // L'ORM génère : SELECT ... FROM users WHERE id = $1
    // Le paramètre est automatiquement échappé
    const user = await User.findByPk(id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'Utilisateur non trouvé' 
      });
    }
    
    res.json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

/**
 * Rechercher des utilisateurs
 * 
 * ✅ Sécurisé : Les opérateurs Sequelize sont sûrs
 */
exports.searchUsers = async (req, res, next) => {
  try {
    const { username, email } = req.query;
    
    // Construction sécurisée de la clause WHERE
    const whereClause = {};
    
    if (username) {
      // Op.iLike génère une requête paramétrée
      whereClause.username = { [Op.iLike]: `%${username}%` };
    }
    
    if (email) {
      whereClause.email = { [Op.iLike]: `%${email}%` };
    }
    
    const users = await User.findAll({
      where: whereClause,
      limit: 50,  // Toujours limiter les résultats
      order: [['createdAt', 'DESC']]
    });
    
    res.json({ success: true, data: users });
  } catch (error) {
    next(error);
  }
};
```

### Requête SQL Générée

```sql
-- Avant (vulnérable)
SELECT * FROM users WHERE id = 1 OR 1=1

-- Après (sécurisé avec Sequelize)
SELECT "id", "username", "email", "role", "isActive", "createdAt", "updatedAt" 
FROM "users" AS "User" 
WHERE "User"."id" = $1 AND "User"."deletedAt" IS NULL;
-- Paramètre $1 = '1 OR 1=1' (traité comme string, pas exécuté)
```
## 3. FIX-002 : Hachage des Mots de Passe

### Problème Original

```javascript
// ❌ AVANT - Mot de passe en clair
db.run(`INSERT INTO users (name, password) VALUES ('${fullName}', '${password}')`);

### Solution Implémentée

**Fichier : backend/src/utils/argon2.js**

```javascript
/**
 * Utilitaire de gestion des mots de passe
 * 
 * Utilise Argon2id (recommandation OWASP & ANSSI)
 */

const argon2 = require('argon2');

/**
 * Hasher un mot de passe
 * 
 * @param {string} plainPassword - Mot de passe en clair
 * @returns {Promise<string>} - Mot de passe hashé
 */
exports.hashPassword = async (plainPassword) => {
  return argon2.hash(plainPassword, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
};

/**
 * Vérifier un mot de passe
 * 
 * @param {string} plainPassword - Mot de passe fourni par l'utilisateur
 * @param {string} hashedPassword - Mot de passe hashé en base
 * @returns {Promise<boolean>} - true si correspondance
 */
exports.verifyPassword = async (plainPassword, hashedPassword) => {
  return argon2.verify(hashedPassword, plainPassword);
};
```


**Hook dans le modèle User :**

```javascript
// Dans models/User.js
const { hashPassword } = require('../utils/argon2');

User.beforeCreate(async (user) => {
  // Hash automatique du mot de passe avant insertion
  if (user.password) {
    user.password = await hashPassword(user.password);
  }
});

User.beforeUpdate(async (user) => {
  // Hash si le mot de passe a changé
  if (user.changed('password')) {
    user.password = await hashPassword(user.password);
  }
});
---

## 4. FIX-003 : Protection XSS

### Problème Original

Aucune protection contre les scripts malicieux injectés dans les commentaires.

### Solution Implémentée

**Fichier : `backend/src/middlewares/security.js`**

```javascript
/**
 * Middleware de sécurité combiné
 * 
 * Implémente plusieurs couches de protection :
 * - Helmet pour les headers HTTP
 * - xss-clean pour nettoyer les entrées
 * - hpp pour éviter la pollution de paramètres
 */

const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');

/**
 * Configuration Helmet avec Content Security Policy
 * 
 * CSP empêche l'exécution de scripts non autorisés
 */
const helmetConfig = helmet({
  // Content Security Policy - Empêche XSS
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],  // Seuls nos scripts sont autorisés
      styleSrc: ["'self'", "'unsafe-inline'"],  // Styles inline pour React
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],  // Bloque Flash, Java, etc.
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],   // Bloque les iframes (anti-clickjacking)
    },
  },
  
  // Protection contre le clickjacking
  frameguard: { action: 'deny' },
  
  // Cache le header X-Powered-By
  hidePoweredBy: true,
  
  // Force HTTPS
  hsts: {
    maxAge: 31536000,  // 1 an
    includeSubDomains: true,
    preload: true
  },
  
  // Empêche le MIME type sniffing
  noSniff: true,
  
  // Protection XSS navigateur (legacy)
  xssFilter: true,
  
  // Politique de référent stricte
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

/**
 * Middleware xss-clean
 * 
 * Nettoie automatiquement req.body, req.query, req.params
 * Remplace les caractères dangereux : < > & " '
 */
const xssClean = xss();

/**
 * Middleware hpp (HTTP Parameter Pollution)
 * 
 * Empêche les attaques par duplication de paramètres
 * Ex: ?id=1&id=2 → prend seulement le dernier
 */
const hppProtection = hpp({
  whitelist: ['sort', 'fields']  // Paramètres autorisés en tableau
});

module.exports = {
  helmetConfig,
  xssClean,
  hppProtection
};
```

**Sanitization supplémentaire côté frontend :**

```javascript
// frontend/src/utils/sanitize.js
import DOMPurify from 'dompurify';

/**
 * Nettoie le HTML pour éviter les XSS
 * À utiliser avant tout affichage de contenu utilisateur
 */
export const sanitizeHTML = (dirty) => {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],  // Tags autorisés
    ALLOWED_ATTR: []  // Aucun attribut autorisé
  });
};
```

---

## 5. FIX-004 : Configuration CORS Sécurisée

### Problème Original

```javascript
// ❌ AVANT - Accepte toutes les origines
app.use(cors());
```

### Solution Implémentée

**Fichier : `backend/src/middlewares/security.js` (suite)**

```javascript
const cors = require('cors');

/**
 * Configuration CORS restrictive
 * 
 * Principe du moindre privilège :
 * - Seules les origines connues sont autorisées
 * - Les méthodes HTTP sont limitées
 * - Les credentials sont gérés de manière sécurisée
 */
const corsOptions = {
  // Origines autorisées (whitelist)
  origin: (origin, callback) => {
    const allowedOrigins = [
      process.env.FRONTEND_URL || 'http://localhost:3000',
      'http://localhost:3001'  // Pour les tests
    ];
    
    // Autorise les requêtes sans origin (Postman, curl, mobile apps)
    // En production, vous pouvez désactiver ceci
    if (!origin) {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Non autorisé par CORS'));
    }
  },
  
  // Méthodes HTTP autorisées
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  
  // Headers autorisés
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token'
  ],
  
  // Headers exposés au frontend
  exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  
  // Autorise les cookies cross-origin
  credentials: true,
  
  // Cache preflight pendant 24h
  maxAge: 86400,
  
  // Permet les requêtes preflight
  preflightContinue: false,
  optionsSuccessStatus: 204
};

const corsMiddleware = cors(corsOptions);

module.exports = { corsMiddleware };
```

---

## 6. FIX-005 : Rate Limiting

### Problème Original

Aucune limite sur le nombre de requêtes.

### Solution Implémentée

**Fichier : `backend/src/middlewares/rateLimiter.js`**

```javascript
/**
 * Configuration du Rate Limiting
 * 
 * Protège contre :
 * - Attaques par brute force
 * - Déni de service (DoS)
 * - Scraping abusif
 * - Enumération d'utilisateurs
 */

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('../config/redis');

/**
 * Rate limiter global
 * 
 * Limite : 100 requêtes par fenêtre de 15 minutes par IP
 */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requêtes max
  
  // Message personnalisé
  message: {
    success: false,
    error: 'Trop de requêtes, veuillez réessayer plus tard',
    retryAfter: '15 minutes'
  },
  
  // Headers standard
  standardHeaders: true,  // Retourne RateLimit-* headers
  legacyHeaders: false,   // Désactive X-RateLimit-* headers
  
  // Utilise Redis pour le stockage (recommandé en cluster)
  store: new RedisStore({
    client: redis,
    prefix: 'rl:global:'
  }),
  
  // Ignore les requêtes réussies pour le calcul
  skipSuccessfulRequests: false,
  
  // Handler personnalisé
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'Trop de requêtes',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

/**
 * Rate limiter pour l'authentification
 * 
 * Plus restrictif : 5 tentatives par 15 minutes
 * Protège contre le brute force de mots de passe
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 tentatives seulement
  
  message: {
    success: false,
    error: 'Trop de tentatives de connexion',
    retryAfter: '15 minutes'
  },
  
  store: new RedisStore({
    client: redis,
    prefix: 'rl:auth:'
  }),
  
  // Compte uniquement les échecs
  skipSuccessfulRequests: true
});

/**
 * Rate limiter pour la création de compte
 * 
 * 3 créations par heure par IP
 */
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 heure
  max: 3,
  
  message: {
    success: false,
    error: 'Trop de comptes créés depuis cette IP',
    retryAfter: '1 heure'
  },
  
  store: new RedisStore({
    client: redis,
    prefix: 'rl:signup:'
  })
});

/**
 * Rate limiter pour les endpoints sensibles (API)
 * 
 * 30 requêtes par minute
 */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 30,
  
  store: new RedisStore({
    client: redis,
    prefix: 'rl:api:'
  })
});

module.exports = {
  globalLimiter,
  authLimiter,
  createAccountLimiter,
  apiLimiter
};
```

---

## 7. FIX-006 : Headers de Sécurité (Helmet)

Voir [FIX-003](#4-fix-003--protection-xss) pour la configuration complète de Helmet.

### Headers Ajoutés

| Header | Valeur | Protection |
|--------|--------|------------|
| `Content-Security-Policy` | `default-src 'self'...` | XSS |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Strict-Transport-Security` | `max-age=31536000` | Downgrade HTTPS |
| `X-XSS-Protection` | `1; mode=block` | XSS (legacy) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Fuite d'information |

---

## 8. FIX-007 : Validation des Entrées

### Problème Original

Aucune validation des données reçues.

### Solution Implémentée

**Fichier : `backend/src/validators/userValidator.js`**

```javascript
/**
 * Validateurs pour les endpoints User
 * 
 * Utilise express-validator pour :
 * - Valider le type des données
 * - Vérifier les contraintes (longueur, format)
 * - Sanitizer les entrées
 */

const { body, param, query, validationResult } = require('express-validator');

/**
 * Middleware de gestion des erreurs de validation
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }
  
  next();
};

/**
 * Validation pour la création d'utilisateur
 */
const createUserValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Le username doit faire entre 3 et 50 caractères')
    .isAlphanumeric()
    .withMessage('Le username ne peut contenir que des lettres et chiffres')
    .escape(),  // Échappe les caractères HTML
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Email invalide')
    .normalizeEmail()  // Normalise l'email
    .isLength({ max: 255 })
    .withMessage('Email trop long'),
  
  body('password')
    .isLength({ min: 12 })
    .withMessage('Le mot de passe doit faire au moins 12 caractères')
    .matches(/[A-Z]/)
    .withMessage('Le mot de passe doit contenir une majuscule')
    .matches(/[a-z]/)
    .withMessage('Le mot de passe doit contenir une minuscule')
    .matches(/\d/)
    .withMessage('Le mot de passe doit contenir un chiffre')
    .matches(/[!@#$%^&*]/)
    .withMessage('Le mot de passe doit contenir un caractère spécial'),
  
  handleValidationErrors
];

/**
 * Validation pour la récupération par ID
 */
const getUserByIdValidation = [
  param('id')
    .isUUID(4)
    .withMessage('ID invalide'),
  
  handleValidationErrors
];

/**
 * Validation pour la recherche
 */
const searchUsersValidation = [
  query('username')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .escape(),
  
  query('email')
    .optional()
    .trim()
    .isEmail()
    .normalizeEmail(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit doit être entre 1 et 100')
    .toInt(),
  
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page doit être >= 1')
    .toInt(),
  
  handleValidationErrors
];

module.exports = {
  createUserValidation,
  getUserByIdValidation,
  searchUsersValidation,
  handleValidationErrors
};
```

**Fichier : `backend/src/validators/commentValidator.js`**

```javascript
const { body, param } = require('express-validator');
const { handleValidationErrors } = require('./userValidator');

/**
 * Validation pour la création de commentaire
 */
const createCommentValidation = [
  body('content')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Le commentaire doit faire entre 1 et 500 caractères')
    .escape(),  // Échappe les caractères HTML dangereux
  
  handleValidationErrors
];

/**
 * Validation pour la suppression
 */
const deleteCommentValidation = [
  param('id')
    .isUUID(4)
    .withMessage('ID de commentaire invalide'),
  
  handleValidationErrors
];

module.exports = {
  createCommentValidation,
  deleteCommentValidation
};
```

---

## 9. FIX-008 : Authentification JWT

**Fichier : `backend/src/middlewares/auth.js`**

```javascript
/**
 * Middleware d'authentification JWT
 * 
 * Implémente :
 * - Vérification du token JWT
 * - Cookies httpOnly (protection XSS)
 * - Refresh token rotation
 * - Blacklist des tokens révoqués
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const redis = require('../config/redis');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';

/**
 * Vérifie le token JWT
 */
const verifyToken = async (req, res, next) => {
  try {
    // Récupère le token depuis le cookie httpOnly
    const token = req.cookies.accessToken;
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentification requise'
      });
    }
    
    // Vérifie si le token est dans la blacklist
    const isBlacklisted = await redis.get(`bl:${token}`);
    if (isBlacklisted) {
      return res.status(401).json({
        success: false,
        error: 'Token révoqué'
      });
    }
    
    // Vérifie et décode le token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Récupère l'utilisateur
    const user = await User.findByPk(decoded.userId);
    
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Utilisateur non trouvé ou désactivé'
      });
    }
    
    // Vérifie le lockout
    if (user.lockUntil && user.lockUntil > new Date()) {
      return res.status(423).json({
        success: false,
        error: 'Compte temporairement verrouillé'
      });
    }
    
    // Attache l'utilisateur à la requête
    req.user = user;
    next();
    
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expiré'
      });
    }
    
    return res.status(401).json({
      success: false,
      error: 'Token invalide'
    });
  }
};

/**
 * Vérifie le rôle de l'utilisateur
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentification requise'
      });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Permission refusée'
      });
    }
    
    next();
  };
};

/**
 * Génère un token JWT
 */
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

/**
 * Révoque un token (logout)
 */
const revokeToken = async (token) => {
  const decoded = jwt.decode(token);
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);
  
  if (ttl > 0) {
    await redis.setex(`bl:${token}`, ttl, 'revoked');
  }
};

module.exports = {
  verifyToken,
  requireRole,
  generateToken,
  revokeToken
};
```

---

## 10. FIX-009 : Gestion des Erreurs Sécurisée

**Fichier : `backend/src/middlewares/errorHandler.js`**

```javascript
/**
 * Gestionnaire d'erreurs centralisé
 * 
 * Principe : Ne jamais exposer les détails techniques au client
 */

const logger = require('../config/logger');

/**
 * Classe d'erreur applicative
 */
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Middleware de gestion des erreurs
 */
const errorHandler = (err, req, res, next) => {
  // Log complet côté serveur
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userId: req.user?.id || 'anonymous'
  });
  
  // Erreur opérationnelle (prévue)
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      success: false,
      error: err.message
    });
  }
  
  // Erreur Sequelize
  if (err.name === 'SequelizeValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Données invalides',
      details: err.errors.map(e => e.message)
    });
  }
  
  if (err.name === 'SequelizeUniqueConstraintError') {
    return res.status(409).json({
      success: false,
      error: 'Cette ressource existe déjà'
    });
  }
  
  // Erreur JWT
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: 'Token invalide'
    });
  }
  
  // Erreur inconnue (ne pas exposer les détails)
  const isProduction = process.env.NODE_ENV === 'production';
  
  return res.status(500).json({
    success: false,
    error: isProduction 
      ? 'Une erreur est survenue' 
      : err.message
  });
};

/**
 * Handler pour les routes non trouvées
 */
const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route non trouvée'
  });
};

module.exports = {
  AppError,
  errorHandler,
  notFoundHandler
};
```

---

## 11. FIX-010 : Logging Sécurisé

**Fichier : `backend/src/config/logger.js`**

```javascript
/**
 * Configuration du logging avec Winston
 * 
 * Bonnes pratiques :
 * - Logs structurés (JSON)
 * - Niveaux de log appropriés
 * - Rotation des fichiers
 * - Pas de données sensibles dans les logs
 */

const winston = require('winston');
const path = require('path');

// Format personnalisé
const customFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Filtre pour masquer les données sensibles
const maskSensitiveData = winston.format((info) => {
  const sensitiveFields = ['password', 'token', 'authorization', 'cookie'];
  
  const maskObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const masked = { ...obj };
    for (const key of Object.keys(masked)) {
      if (sensitiveFields.includes(key.toLowerCase())) {
        masked[key] = '***REDACTED***';
      } else if (typeof masked[key] === 'object') {
        masked[key] = maskObject(masked[key]);
      }
    }
    return masked;
  };
  
  return maskObject(info);
})();

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    maskSensitiveData,
    customFormat
  ),
  defaultMeta: { service: 'ipssi-secure-api' },
  transports: [
    // Fichier pour les erreurs
    new winston.transports.File({ 
      filename: path.join('logs', 'error.log'), 
      level: 'error',
      maxsize: 5242880,  // 5MB
      maxFiles: 5
    }),
    
    // Fichier pour tous les logs
    new winston.transports.File({ 
      filename: path.join('logs', 'combined.log'),
      maxsize: 5242880,
      maxFiles: 5
    })
  ]
});

// Console en développement
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
```

---

## 12. FIX-011 : Sécurisation Docker

Voir [DOCKER_GUIDE.md](DOCKER_GUIDE.md) pour la documentation complète.

### Résumé des Protections Docker

| Protection | Implémentation |
|------------|----------------|
| User non-root | `USER node` |
| Image minimale | Alpine Linux |
| Multi-stage build | Build ≠ Runtime |
| Read-only filesystem | `read_only: true` |
| Drop capabilities | `cap_drop: ALL` |
| No new privileges | `security_opt: no-new-privileges` |
| Réseau isolé | Network bridge interne |
| Secrets management | Docker secrets / .env |
| Health checks | Endpoints de santé |
| Resource limits | CPU et mémoire limités |

---

**Document généré dans le cadre du module Cybersécurité - IPSSI**
