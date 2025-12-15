'use strict';

const express = require('express');
const router = express.Router();

const { verifyToken } = require('../middlewares/auth');
const { upload, validateUploadedFile } = require('../middlewares/uploadSecurity');
const uploadController = require('../controllers/uploadController');

// Upload sécurisé : auth + multer + validation + déplacement final
router.post(
  '/',
  verifyToken,
  upload.single('file'),
  validateUploadedFile,
  uploadController.uploadFile
);

module.exports = router;
