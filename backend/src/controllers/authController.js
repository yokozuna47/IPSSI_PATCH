'use strict';

const User = require('../models/User');
const {
  generateTokens,
  clearAuthCookies,
  generateAccessToken
} = require('../middlewares/auth');
const { AppError, catchAsync } = require('../middlewares/errorHandler');
const logger = require('../config/logger');
const jwt = require('jsonwebtoken');

/**
 * Inscription utilisateur
 */
exports.register = catchAsync(async (req, res) => {
  const { username, email, password } = req.body;

  const user = await User.create({ username, email, password });

  logger.info('Nouvel utilisateur', { userId: user.id, email });

  generateTokens(res, user.id);

  res.status(201).json({
    success: true,
    message: 'Compte créé',
    data: { user: user.toSafeObject() }
  });
});

/**
 * Connexion utilisateur
 */
exports.login = catchAsync(async (req, res) => {
  const { email, password } = req.body;

  const user = await User
    .scope('withPassword')
    .findOne({ where: { email: email.toLowerCase() } });

  if (!user) {
    throw new AppError('Email ou mot de passe incorrect', 401);
  }

  if (!user.isActive) {
    throw new AppError('Compte désactivé', 401);
  }

  if (user.isLocked()) {
    throw new AppError(
      `Compte verrouillé. Réessayez dans ${user.getLockTimeRemaining()} minutes.`,
      423
    );
  }

  const isValid = await user.verifyPassword(password);

  if (!isValid) {
    await user.incrementLoginAttempts();
    throw new AppError('Email ou mot de passe incorrect', 401);
  }

  await user.resetLoginAttempts();

  generateTokens(res, user.id);

  logger.info('Connexion réussie', { userId: user.id });

  res.json({
    success: true,
    message: 'Connexion réussie',
    data: { user: user.toSafeObject() }
  });
});

/**
 * Déconnexion
 */
exports.logout = catchAsync(async (req, res) => {
  clearAuthCookies(res);

  res.json({
    success: true,
    message: 'Déconnexion réussie'
  });
});

/**
 * Rafraîchissement du token d’accès
 */
exports.refreshToken = catchAsync(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new AppError('Token manquant', 401);
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
  } catch (err) {
    // 👉 CORRECTION IMPORTANTE : on évite les erreurs JWT non maîtrisées
    throw new AppError('Token invalide', 401);
  }

  if (decoded.type !== 'refresh') {
    throw new AppError('Token invalide', 401);
  }

  const user = await User.findByPk(decoded.userId);

  if (!user || !user.isActive) {
    throw new AppError('Utilisateur non trouvé', 401);
  }

  const newAccessToken = generateAccessToken(user.id);

  res.cookie('accessToken', newAccessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.json({
    success: true,
    message: 'Token rafraîchi'
  });
});

/**
 * Récupération du profil courant
 */
exports.getMe = catchAsync(async (req, res) => {
  const user = await User.findByPk(req.userId);

  if (!user) {
    throw new AppError('Utilisateur non trouvé', 404);
  }

  res.json({
    success: true,
    data: { user }
  });
});
