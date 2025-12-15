'use strict';

const Comment = require('../models/Comment');
const User = require('../models/User');
const { AppError, catchAsync } = require('../middlewares/errorHandler');

const AUTHOR_ATTRS = ['id', 'username'];
const COMMENT_ATTRS = ['id', 'content', 'userId', 'createdAt', 'updatedAt']; // j'exclus authorIp

// Je fournis une méthode interne pour les checks d'autorisation (owner/admin)
exports._getCommentForAuth = async (id) => {
  return Comment.findByPk(id, { attributes: ['id', 'userId'] });
};

exports.getAllComments = catchAsync(async (req, res) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const limitRaw = parseInt(req.query.limit, 10) || 20;
  const limit = Math.min(Math.max(limitRaw, 1), 100);
  const offset = (page - 1) * limit;

  const { count, rows: comments } = await Comment.findAndCountAll({
    attributes: COMMENT_ATTRS,
    include: [{ model: User, as: 'author', attributes: AUTHOR_ATTRS }],
    limit,
    offset,
    order: [['createdAt', 'DESC']],
  });

  res.json({
    success: true,
    data: {
      comments,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(count / limit),
        totalItems: count,
      },
    },
  });
});

exports.getCommentById = catchAsync(async (req, res) => {
  const comment = await Comment.findByPk(req.params.id, {
    attributes: COMMENT_ATTRS,
    include: [{ model: User, as: 'author', attributes: AUTHOR_ATTRS }],
  });

  if (!comment) throw new AppError('Commentaire non trouvé', 404);

  res.json({ success: true, data: { comment } });
});

exports.createComment = catchAsync(async (req, res) => {
  const content = String(req.body.content || '').trim();
  if (!content) throw new AppError('Contenu obligatoire', 400);
  if (content.length > 2000) throw new AppError('Contenu trop long', 400);

  const comment = await Comment.create({
    content,
    userId: req.userId,
    authorIp: req.ip, // je peux le stocker côté DB, mais je ne l'expose jamais
  });

  const created = await Comment.findByPk(comment.id, {
    attributes: COMMENT_ATTRS,
    include: [{ model: User, as: 'author', attributes: AUTHOR_ATTRS }],
  });

  res.status(201).json({ success: true, data: { comment: created } });
});

exports.deleteComment = catchAsync(async (req, res) => {
  // Si la route a déjà chargé req.comment (middleware owner/admin), je le réutilise
  const comment = req.comment || await Comment.findByPk(req.params.id, { attributes: ['id', 'userId'] });
  if (!comment) throw new AppError('Commentaire non trouvé', 404);

  const isAdmin = req.user?.role === 'admin';
  const isOwner = String(comment.userId) === String(req.userId);

  if (!isAdmin && !isOwner) throw new AppError('Permission refusée', 403);

  await Comment.destroy({ where: { id: comment.id } });
  res.status(204).send();
});
