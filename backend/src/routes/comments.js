'use strict';

const express = require('express');
const router = express.Router();

const commentController = require('../controllers/commentController');
const { verifyToken } = require('../middlewares/auth');
const { AppError } = require('../middlewares/errorHandler');
const { createCommentValidation } = require('../validators/commentValidator');

// Je définis un garde-fou owner/admin (anti-IDOR) pour les actions destructrices
const requireOwnerOrAdmin = async (req, res, next) => {
  try {
    const comment = await commentController._getCommentForAuth(req.params.id);
    if (!comment) return next(new AppError('Commentaire non trouvé', 404));

    const isAdmin = req.user?.role === 'admin';
    const isOwner = String(comment.userId) === String(req.userId);

    if (isAdmin || isOwner) {
      req.comment = comment; // je le réutilise dans le controller pour éviter un 2e fetch
      return next();
    }

    return next(new AppError('Permission refusée', 403));
  } catch (e) {
    return next(e);
  }
};

// Je veux "tout protégé", donc je mets verifyToken aussi sur la lecture.
router.get('/', verifyToken, commentController.getAllComments);
router.get('/:id', verifyToken, commentController.getCommentById);

// Création : auth requise
router.post('/', verifyToken, createCommentValidation, commentController.createComment);

// Suppression : owner OU admin
router.delete('/:id', verifyToken, requireOwnerOrAdmin, commentController.deleteComment);

module.exports = router;
