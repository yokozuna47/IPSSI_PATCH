/**
 * =============================================================================
 * MODELS/IMAGE.JS - Modèle Image Sécurisé
 * =============================================================================
 * 
 * Protection contre :
 * - Image Upload Bypass (validation MIME + magic bytes)
 * - Path Traversal (sanitization du nom de fichier)
 * - LFI (chemins relatifs bloqués)
 * 
 * =============================================================================
 */

'use strict';

const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/database');
const path = require('path');
const sanitizeFilename = require('sanitize-filename');

class Image extends Model {
  /**
   * Retourne le chemin complet sécurisé
   */
  getSecurePath() {
    // Utilise uniquement le nom du fichier, jamais le chemin fourni
    const safeName = sanitizeFilename(this.filename);
    return path.join('/uploads/images', safeName);
  }

  /**
   * Vérifie si l'image appartient à l'utilisateur
   */
  isOwnedBy(userId) {
    return this.userId === userId;
  }
}

Image.init({
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },

  // Nom de fichier original (sanitizé)
  originalName: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      notEmpty: true
    },
    set(value) {
      // Sanitize le nom de fichier
      this.setDataValue('originalName', sanitizeFilename(value));
    }
  },

  // Nom de fichier stocké (UUID + extension)
  filename: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true
  },

  // Type MIME validé
  mimeType: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      isIn: {
        args: [['image/jpeg', 'image/png', 'image/gif', 'image/webp']],
        msg: 'Type de fichier non autorisé'
      }
    }
  },

  // Taille en bytes
  size: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      min: 1,
      max: 5 * 1024 * 1024 // 5 MB max
    }
  },

  // Hash SHA256 du fichier (intégrité)
  hash: {
    type: DataTypes.STRING(64),
    allowNull: true
  },

  // Dimensions
  width: {
    type: DataTypes.INTEGER,
    allowNull: true
  },

  height: {
    type: DataTypes.INTEGER,
    allowNull: true
  },

  // Propriétaire
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  },

  // Description (optionnelle, sanitizée)
  description: {
    type: DataTypes.TEXT,
    allowNull: true,
    set(value) {
      if (value) {
        // Échappe les caractères HTML
        const escaped = value
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;');
        this.setDataValue('description', escaped.substring(0, 1000));
      }
    }
  },

  // Statut
  status: {
    type: DataTypes.ENUM('pending', 'approved', 'rejected'),
    defaultValue: 'approved'
  },

  // IP de l'uploader
  uploaderIp: {
    type: DataTypes.STRING(45),
    allowNull: true
  }

}, {
  sequelize,
  modelName: 'Image',
  tableName: 'images',
  timestamps: true,
  paranoid: true,
  underscored: true,

  indexes: [
    { fields: ['user_id'] },
    { fields: ['status'] },
    { fields: ['hash'] }
  ]
});

module.exports = Image;
