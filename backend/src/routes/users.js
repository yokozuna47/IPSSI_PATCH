'use strict';

const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');
const { verifyToken, requireRole } = require('../middlewares/auth');
const { AppError } = require('../middlewares/errorHandler');

// Middleware: autorise uniquement le propriétaire du compte OU un admin
const requireSelfOrAdmin = (req, res, next) => {
  const isAdmin = req.user?.role === 'admin';
  const isSelf = String(req.userId) === String(req.params.id);

  if (isAdmin || isSelf) return next();
  return next(new AppError('Permission refusée', 403));
};

// ✅ LISTE USERS = ADMIN ONLY (sinon data leak)
router.get('/', verifyToken, requireRole('admin'), userController.getAllUsers);

// ✅ GET USER BY ID = SELF OR ADMIN
router.get('/:id', verifyToken, requireSelfOrAdmin, userController.getUserById);

// ✅ UPDATE USER = SELF OR ADMIN
router.put('/:id', verifyToken, requireSelfOrAdmin, userController.updateUser);

// ✅ DELETE USER = SELF OR ADMIN
router.delete('/:id', verifyToken, requireSelfOrAdmin, userController.deleteUser);

module.exports = router;
