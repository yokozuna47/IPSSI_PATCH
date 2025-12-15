'use strict';

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('./errorHandler');
const { compile } = require('morgan');

const isProd = process.env.NODE_ENV === 'production';

if (isProd && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET manquant en production');
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

// Cookies cohérents avec HTTP/HTTPS (pilotés par env, pas NODE_ENV)
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';          // true si HTTPS activé
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'lax';        // 'lax' en local, 'strict' possible si 100% même site
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;        // optionnel

const generateAccessToken = (userId) =>
  jwt.sign({ userId, type: 'access' }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

const generateRefreshToken = (userId) =>
  jwt.sign({ userId, type: 'refresh' }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });

const generateTokens = (res, userId) => {
  const accessToken = generateAccessToken(userId);
  const refreshToken = generateRefreshToken(userId);

  // access token cookie
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: 15 * 60 * 1000,
  });

  // refresh token cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/api/auth/refresh',
  });

  return { accessToken, refreshToken };
};

const verifyToken = async (req, res, next) => {
  try {
    let token = req.cookies?.accessToken;

    // fallback Bearer pour Postman (utile en audit)
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) throw new AppError('Authentification requise', 401);

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') throw new AppError('Session expirée', 401);
      throw new AppError('Token invalide', 401);
    }

    if (decoded.type !== 'access') throw new AppError('Type de token invalide', 401);

    // IMPORTANT: pas besoin du password ici
    const user = await User.findByPk(decoded.userId);
    if (!user) throw new AppError('Utilisateur non trouvé', 401);
    if (!user.isActive) throw new AppError('Compte désactivé', 401);
    if (user.isLocked && user.isLocked()) throw new AppError('Compte verrouillé', 423);

    req.user = user.toSafeObject();
    req.userId = user.id;

    return next();
  } catch (error) {
    return next(error);
  }
};

const clearAuthCookies = (res) => {
  // mêmes options que set-cookie (au moins path/domain/samesite/secure) pour être sûr que ça s’efface
  res.cookie('accessToken', '', {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    expires: new Date(0),
  });

  res.cookie('refreshToken', '', {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    expires: new Date(0),
    path: '/api/auth/refresh',
  });
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return next(new AppError('Authentification requise', 401));
  if (!roles.includes(req.user.role)) return next(new AppError('Permission refusée', 403));
  return next();
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateTokens,
  verifyToken,
  clearAuthCookies,
  requireRole,
};
