'use strict';
const express = require('express');
const router = express.Router();

const authRoutes = require('./auth');
const userRoutes = require('./users');
const commentRoutes = require('./comments');
const uploadRoutes = require('./uploads');

router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/comments', commentRoutes);
router.use('/uploads', uploadRoutes);

// Route racine pour vérifier que l'API fonctionne

router.get('/', (req, res) => {
  res.json({ success: true, message: 'IPSSI Secure API v2.0' });
});

module.exports = router;
