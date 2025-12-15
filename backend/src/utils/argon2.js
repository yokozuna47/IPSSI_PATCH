/**
 * =============================================================================
 * UTILS/ARGON2.JS - Hachage des Mots de Passe avec Argon2id
 * =============================================================================
 * 
 * Argon2id est l'algorithme RECOMMANDÉ par OWASP en 2023/2024.
 * Il est résistant aux :
 * - Attaques par GPU (memory-hard)
 * - Attaques par timing (constant-time)
 * - Attaques par canaux auxiliaires
 * 
 * Configuration selon OWASP :
 * - Type: Argon2id (hybride Argon2i + Argon2d)
 * - Memory: 64 MB (65536 KB)
 * - Iterations: 3
 * - Parallelism: 4
 * 
 * =============================================================================
 */

'use strict';

const argon2 = require('argon2');

/**
 * Configuration Argon2id selon OWASP
 * 
 * Ces paramètres offrent un bon équilibre entre sécurité et performance.
 * En production, vous pouvez augmenter ces valeurs si votre serveur le permet.
 */
const ARGON2_OPTIONS = {
  type: argon2.argon2id,      // Argon2id = recommandé
  memoryCost: 65536,           // 64 MB de mémoire
  timeCost: 3,                 // 3 itérations
  parallelism: 4,              // 4 threads parallèles
  hashLength: 32,              // Longueur du hash (256 bits)
  saltLength: 16,              // Longueur du sel (128 bits)
};

/**
 * Hash un mot de passe avec Argon2id
 * 
 * @param {string} plainPassword - Mot de passe en clair
 * @returns {Promise<string>} - Hash Argon2id encodé
 * 
 * @example
 * const hash = await hashPassword('MonMotDePasse123!');
 * // Retourne: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
 */
const hashPassword = async (plainPassword) => {
  try {
    const hash = await argon2.hash(plainPassword, ARGON2_OPTIONS);
    return hash;
  } catch (error) {
    throw new Error(`Erreur lors du hachage: ${error.message}`);
  }
};

/**
 * Vérifie un mot de passe contre son hash Argon2id
 * 
 * Cette fonction est timing-safe (temps constant) pour éviter
 * les attaques par timing.
 * 
 * @param {string} plainPassword - Mot de passe fourni par l'utilisateur
 * @param {string} hashedPassword - Hash stocké en base de données
 * @returns {Promise<boolean>} - true si le mot de passe correspond
 * 
 * @example
 * const isValid = await verifyPassword('MonMotDePasse123!', storedHash);
 */
const verifyPassword = async (plainPassword, hashedPassword) => {
  try {
    const isMatch = await argon2.verify(hashedPassword, plainPassword);
    return isMatch;
  } catch (error) {
    // En cas d'erreur (hash invalide, etc.), retourne false
    // Ne pas exposer les détails de l'erreur
    return false;
  }
};

/**
 * Vérifie si un hash nécessite une mise à jour
 * 
 * Utile quand vous changez les paramètres Argon2.
 * Permet de re-hasher les mots de passe avec les nouveaux paramètres
 * lors de la prochaine connexion de l'utilisateur.
 * 
 * @param {string} hashedPassword - Hash actuel
 * @returns {boolean} - true si le hash doit être mis à jour
 */
const needsRehash = (hashedPassword) => {
  try {
    return argon2.needsRehash(hashedPassword, ARGON2_OPTIONS);
  } catch (error) {
    return true; // En cas de doute, re-hasher
  }
};

/**
 * Valide la force d'un mot de passe
 * 
 * Critères ANSSI / OWASP :
 * - Minimum 12 caractères
 * - Au moins 1 majuscule
 * - Au moins 1 minuscule  
 * - Au moins 1 chiffre
 * - Au moins 1 caractère spécial
 * - Pas de patterns communs
 * 
 * @param {string} password - Mot de passe à valider
 * @returns {Object} - { isValid: boolean, errors: string[], strength: string }
 */
const validatePasswordStrength = (password) => {
  const errors = [];
  let strength = 0;

  // Longueur minimum
  if (password.length < 12) {
    errors.push('Le mot de passe doit contenir au moins 12 caractères');
  } else if (password.length >= 16) {
    strength += 2;
  } else {
    strength += 1;
  }

  // Majuscule
  if (!/[A-Z]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins une majuscule');
  } else {
    strength += 1;
  }

  // Minuscule
  if (!/[a-z]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins une minuscule');
  } else {
    strength += 1;
  }

  // Chiffre
  if (!/\d/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins un chiffre');
  } else {
    strength += 1;
  }

  // Caractère spécial
  if (!/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins un caractère spécial');
  } else {
    strength += 1;
  }

  // Patterns communs à éviter
  const commonPatterns = [
    /^123/,
    /password/i,
    /azerty/i,
    /qwerty/i,
    /admin/i,
    /(.)\1{2,}/, // 3+ caractères identiques consécutifs
  ];

  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      errors.push('Le mot de passe contient un pattern trop commun');
      strength -= 1;
      break;
    }
  }

  // Évaluation de la force
  let strengthLabel;
  if (strength <= 2) {
    strengthLabel = 'faible';
  } else if (strength <= 4) {
    strengthLabel = 'moyen';
  } else {
    strengthLabel = 'fort';
  }

  return {
    isValid: errors.length === 0,
    errors,
    strength: strengthLabel,
    score: Math.max(0, strength)
  };
};

module.exports = {
  hashPassword,
  verifyPassword,
  needsRehash,
  validatePasswordStrength,
  ARGON2_OPTIONS
};
