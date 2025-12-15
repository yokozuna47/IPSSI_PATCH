'use strict';
const { body, param } = require('express-validator');
const { handleValidation } = require('./authValidator');

const createCommentValidation = [
  body('content').trim().isLength({ min: 1, max: 1000 }).escape(),
  handleValidation
];

const getCommentByIdValidation = [
  param('id').isUUID(4),
  handleValidation
];

module.exports = { createCommentValidation, getCommentByIdValidation };
