'use strict';
const logger = require('../config/logger');

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  
  logger.error({ message: err.message, stack: err.stack, path: req.path, method: req.method });
  
  if (err.name === 'SequelizeValidationError') {
    return res.status(400).json({ success: false, error: 'Données invalides' });
  }
  if (err.name === 'SequelizeUniqueConstraintError') {
    return res.status(409).json({ success: false, error: 'Cette ressource existe déjà' });
  }
  
  const isProduction = process.env.NODE_ENV === 'production';
  res.status(err.statusCode).json({
    success: false,
    error: isProduction && !err.isOperational ? 'Erreur serveur' : err.message
  });
};

const notFoundHandler = (req, res) => {
  res.status(404).json({ success: false, error: 'Route non trouvée' });
};

const catchAsync = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { AppError, errorHandler, notFoundHandler, catchAsync };
