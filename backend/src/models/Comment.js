'use strict';
const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/database');

class Comment extends Model {}

Comment.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  content: {
    type: DataTypes.TEXT,
    allowNull: false,
    validate: { len: [1, 1000] },
    set(value) {
      const sanitized = value.trim()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .substring(0, 1000);
      this.setDataValue('content', sanitized);
    }
  },
  userId: { type: DataTypes.UUID, allowNull: false },
  status: { type: DataTypes.ENUM('pending', 'approved', 'rejected'), defaultValue: 'approved' },
  authorIp: { type: DataTypes.STRING(45), allowNull: true }
}, {
  sequelize,
  modelName: 'Comment',
  tableName: 'comments',
  timestamps: true,
  paranoid: true,
  underscored: true
});

module.exports = Comment;
