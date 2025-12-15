'use strict';
const sequelize = require('../config/database');
const User = require('./User');
const Comment = require('./Comment');

User.hasMany(Comment, { foreignKey: 'userId', as: 'comments' });
Comment.belongsTo(User, { foreignKey: 'userId', as: 'author' });

module.exports = { sequelize, User, Comment };
