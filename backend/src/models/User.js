/**
 * =============================================================================
 * MODELS/USER.JS - Modèle Utilisateur avec Argon2id
 * =============================================================================
 * 
 * Sécurité implémentée :
 * - Hachage Argon2id (OWASP 2023)
 * - UUID v4 (anti-énumération)
 * - Account lockout (anti brute-force)
 * - Validation stricte
 * - Soft delete (audit)
 * 
 * =============================================================================
 */

'use strict';

const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/database');
const { hashPassword, verifyPassword, needsRehash } = require('../utils/argon2');

class User extends Model {
  /**
   * Vérifie le mot de passe avec Argon2id
   */
  async verifyPassword(plainPassword) {
    return verifyPassword(plainPassword, this.password);
  }

  /**
   * Vérifie si le hash doit être mis à jour
   */
  passwordNeedsRehash() {
    return needsRehash(this.password);
  }

  /**
   * Vérifie si le compte est verrouillé
   */
  isLocked() {
    return this.lockUntil && this.lockUntil > new Date();
  }

  /**
   * Temps restant avant déverrouillage (en minutes)
   */
  getLockTimeRemaining() {
    if (!this.isLocked()) return 0;
    return Math.ceil((this.lockUntil - new Date()) / 60000);
  }

  /**
   * Incrémente les tentatives de connexion
   */
  async incrementLoginAttempts() {
    // Reset si le lockout a expiré
    if (this.lockUntil && this.lockUntil < new Date()) {
      await this.update({
        loginAttempts: 1,
        lockUntil: null
      });
      return;
    }

    const updates = { loginAttempts: this.loginAttempts + 1 };

    // Lockout progressif
    const attempts = this.loginAttempts + 1;
    if (attempts >= 10) {
      // 10+ tentatives : 1 heure
      updates.lockUntil = new Date(Date.now() + 60 * 60 * 1000);
    } else if (attempts >= 5) {
      // 5-9 tentatives : 15 minutes
      updates.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
    } else if (attempts >= 3) {
      // 3-4 tentatives : 5 minutes
      updates.lockUntil = new Date(Date.now() + 5 * 60 * 1000);
    }

    await this.update(updates);
  }

  /**
   * Reset après connexion réussie
   */
  async resetLoginAttempts() {
    await this.update({
      loginAttempts: 0,
      lockUntil: null,
      lastLoginAt: new Date()
    });
  }

  /**
   * Retourne l'objet sans données sensibles
   */
  toSafeObject() {
    const { password, loginAttempts, lockUntil, ...safe } = this.toJSON();
    return safe;
  }
}

User.init({
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },

  username: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true,
    validate: {
      len: [3, 50],
      isAlphanumeric: true,
      notEmpty: true
    }
  },

  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
      notEmpty: true
    },
    set(value) {
      this.setDataValue('email', value.toLowerCase().trim());
    }
  },

  password: {
    type: DataTypes.STRING(255),
    allowNull: false
  },

  role: {
    type: DataTypes.ENUM('user', 'admin'),
    defaultValue: 'user'
  },

  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },

  isEmailVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },

  loginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },

  lockUntil: {
    type: DataTypes.DATE,
    allowNull: true
  },

  lastLoginAt: {
    type: DataTypes.DATE,
    allowNull: true
  },

  lastLoginIp: {
    type: DataTypes.STRING(45),
    allowNull: true
  },

  lastUserAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  }

}, {
  sequelize,
  modelName: 'User',
  tableName: 'users',
  timestamps: true,
  paranoid: true,
  underscored: true,

  defaultScope: {
    attributes: { exclude: ['password', 'loginAttempts', 'lockUntil'] }
  },

  scopes: {
    withPassword: {
      attributes: { include: ['password', 'loginAttempts', 'lockUntil'] }
    },
    active: {
      where: { isActive: true }
    }
  }
});

// =============================================================================
// HOOKS - Hachage automatique avec Argon2id
// =============================================================================

User.beforeCreate(async (user) => {
  if (user.password) {
    user.password = await hashPassword(user.password);
  }
});

User.beforeUpdate(async (user) => {
  if (user.changed('password')) {
    user.password = await hashPassword(user.password);
  }
});

module.exports = User;
