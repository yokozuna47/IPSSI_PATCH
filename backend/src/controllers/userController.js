'use strict';

const User = require('../models/User');
const { Op } = require('sequelize');
const { AppError, catchAsync } = require('../middlewares/errorHandler');

// Champs autorisés à sortir (évite fuite de données)
const SAFE_USER_ATTRIBUTES = ['id', 'username', 'email', 'role', 'isActive', 'createdAt', 'updatedAt'];

exports.getAllUsers = catchAsync(async (req, res) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const limitRaw = parseInt(req.query.limit, 10) || 10;
  const limit = Math.min(Math.max(limitRaw, 1), 100);
  const offset = (page - 1) * limit;

  const search = (req.query.search || '').trim();
  const where = {};

  if (search) {
    where[Op.or] = [
      { username: { [Op.iLike]: `%${search}%` } },
      { email: { [Op.iLike]: `%${search}%` } },
    ];
  }

  const { count, rows: users } = await User.findAndCountAll({
    where,
    attributes: SAFE_USER_ATTRIBUTES,
    limit,
    offset,
    order: [['createdAt', 'DESC']],
  });

  res.json({
    success: true,
    data: {
      users,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(count / limit),
        totalItems: count,
      },
    },
  });
});

exports.getUserById = catchAsync(async (req, res) => {
  const user = await User.findByPk(req.params.id, { attributes: SAFE_USER_ATTRIBUTES });
  if (!user) throw new AppError('Utilisateur non trouvé', 404);

  res.json({ success: true, data: { user } });
});

exports.updateUser = catchAsync(async (req, res) => {
  const user = await User.findByPk(req.params.id, { attributes: SAFE_USER_ATTRIBUTES });
  if (!user) throw new AppError('Utilisateur non trouvé', 404);

  const { username, email } = req.body;

  // protections minimales (évite données bizarres)
  if (username !== undefined) {
    const u = String(username).trim();
    if (u.length < 3 || u.length > 30) throw new AppError('Username invalide (3-30)', 400);
    user.username = u;
  }

  if (email !== undefined) {
    const e = String(email).trim().toLowerCase();
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
    if (!emailOk) throw new AppError('Email invalide', 400);
    user.email = e;
  }

  await user.save();

  // Recharger proprement avec attributs safe
  const updatedUser = await User.findByPk(req.params.id, { attributes: SAFE_USER_ATTRIBUTES });

  res.json({ success: true, data: { user: updatedUser } });
});

exports.deleteUser = catchAsync(async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (!user) throw new AppError('Utilisateur non trouvé', 404);

  await user.destroy();
  res.status(204).send();
});
