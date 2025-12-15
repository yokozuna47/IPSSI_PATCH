'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const { globalLimiter } = require('./middlewares/rateLimiter');
const { headersSecurity } = require('./middlewares/headersSecurity');
const { lfiProtection, blockDataURI } = require('./middlewares/lfiProtection');
const { redirectProtection } = require('./middlewares/redirectValidator');
const { csrfProtection, getCsrfToken } = require('./middlewares/csrf');
const { errorHandler, notFoundHandler } = require('./middlewares/errorHandler');
const logger = require('./config/logger');

const routes = require('./routes');

const app = express();

// =============================================================================
// 1) TRUST PROXY / BASE
// =============================================================================
app.set('trust proxy', 1);
app.disable('x-powered-by');

const isProd = process.env.NODE_ENV === 'production';
if (isProd && !process.env.COOKIE_SECRET) {
  throw new Error('COOKIE_SECRET manquant en production');
}

// =============================================================================
// 2) HELMET (headers) — CSP gérée côté Nginx (évite double CSP)
// =============================================================================
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,         // évite de casser des ressources externes
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },

  frameguard: { action: 'deny' },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },

  // HSTS uniquement si HTTPS réellement activé
  hsts: false
}));

// =============================================================================
// 3) CORS — cohérent avec Nginx (http://localhost)
// =============================================================================
const allowedOrigins = new Set([
  process.env.FRONTEND_URL || 'http://localhost',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1',
  'http://127.0.0.1:3000',
]);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.has(origin)) return callback(null, true);

    logger.warn('CORS blocked', { origin });
    return callback(new Error('Non autorisé par la politique CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  credentials: true,
  maxAge: 86400
}));

// =============================================================================
// 4) RATE LIMITING
// =============================================================================
app.use(globalLimiter);

// =============================================================================
// 5) HEADERS SECURITY (log only pour éviter les faux positifs en démo)
// =============================================================================
app.use(headersSecurity({ strict: false, logOnly: true }));

// =============================================================================
// 6) BODY PARSERS (limites)
// =============================================================================
app.use(express.json({ limit: '10kb', strict: true }));
app.use(express.urlencoded({ extended: true, limit: '10kb', parameterLimit: 100 }));

// Cookies signés
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-cookie-secret'));

// =============================================================================
// 7) XSS CLEAN + HPP
// =============================================================================
app.use(xss());
app.use(hpp({ whitelist: ['sort', 'fields', 'page', 'limit', 'filter'] }));

// =============================================================================
// 8) OPEN REDIRECT + LFI / PATH TRAVERSAL + DATA URI
// =============================================================================
app.use(redirectProtection({ allowRelative: true, logOnly: false }));

app.use(lfiProtection({
  checkBody: true,
  checkQuery: true,
  checkParams: true,
  logOnly: false
}));
app.use(blockDataURI);

// =============================================================================
// 9) CSRF
// =============================================================================
app.use(csrfProtection({
  ignorePaths: ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/health', '/api/csrf-token']
}));

// =============================================================================
// 10) LOGGING
// =============================================================================
const morganFormat = isProd ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  stream: { write: (message) => logger.http(message.trim()) },
  skip: (req) => req.url === '/health'
}));

// =============================================================================
// 11) ROUTES
// =============================================================================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/api/csrf-token', getCsrfToken);

app.use('/api', routes);

// =============================================================================
// 12) ERROR HANDLERS
// =============================================================================
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
