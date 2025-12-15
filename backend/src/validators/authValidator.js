'use strict';
const { body, validationResult } = require('express-validator');

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};

const registerValidation = [
  body('username').trim().isLength({ min: 3, max: 50 }).isAlphanumeric().escape(),
  body('email').trim().isEmail().normalizeEmail().isLength({ max: 255 }),
  body('password')
    .isLength({ min: 12 }).withMessage('Min 12 caractères')
    .matches(/[A-Z]/).withMessage('Une majuscule requise')
    .matches(/[a-z]/).withMessage('Une minuscule requise')
    .matches(/\d/).withMessage('Un chiffre requis')
    .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Un caractère spécial requis'),
  handleValidation
];

const loginValidation = [
  body('email').trim().isEmail().normalizeEmail(),
  body('password').notEmpty(),
  handleValidation
];

module.exports = { registerValidation, loginValidation, handleValidation };
