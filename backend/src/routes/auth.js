'use strict';
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authLimiter, createAccountLimiter } = require('../middlewares/rateLimiter');
const { registerValidation, loginValidation } = require('../validators/authValidator');
const { verifyToken } = require('../middlewares/auth');

router.post('/register', createAccountLimiter, registerValidation, authController.register);
router.post('/login', authLimiter, loginValidation, authController.login);
router.post('/logout', verifyToken, authController.logout);
router.post('/refresh', authController.refreshToken);
router.get('/me', verifyToken, authController.getMe);

module.exports = router;
