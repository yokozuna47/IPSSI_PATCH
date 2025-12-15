/**
 * =============================================================================
 * MIDDLEWARES/UPLOAD-SECURITY.JS - Protection Upload de Fichiers
 * =============================================================================
 * 
 * Protection contre :
 * - Image Upload Bypass (double extension, MIME spoofing)
 * - Exécution de code (PHP, JSP, ASP)
 * - Magic bytes manipulation
 * - Path Traversal dans le nom de fichier
 * 
 * =============================================================================
 */

'use strict';

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;
const sanitizeFilename = require('sanitize-filename');
const FileType = require('file-type');
const logger = require('../config/logger');
const { AppError } = require('./errorHandler');

/**
 * Types MIME autorisés avec leurs magic bytes
 */
const ALLOWED_TYPES = {
  'image/jpeg': {
    extensions: ['.jpg', '.jpeg'],
    magicBytes: [
      [0xFF, 0xD8, 0xFF, 0xE0],
      [0xFF, 0xD8, 0xFF, 0xE1],
      [0xFF, 0xD8, 0xFF, 0xE8],
    ]
  },
  'image/png': {
    extensions: ['.png'],
    magicBytes: [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]]
  },
  'image/gif': {
    extensions: ['.gif'],
    magicBytes: [
      [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], // GIF87a
      [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
    ]
  },
  'image/webp': {
    extensions: ['.webp'],
    magicBytes: [[0x52, 0x49, 0x46, 0x46]] // RIFF
  }
};

/**
 * Extensions dangereuses à bloquer absolument
 */
const DANGEROUS_EXTENSIONS = [
  '.php', '.php3', '.php4', '.php5', '.phtml', '.phar',
  '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',
  '.asp', '.aspx', '.cer', '.asa', '.asax',
  '.exe', '.dll', '.bat', '.cmd', '.com', '.msi',
  '.sh', '.bash', '.zsh', '.ps1',
  '.py', '.pyc', '.pyo',
  '.pl', '.pm', '.cgi',
  '.jar', '.war', '.ear',
  '.htaccess', '.htpasswd',
  '.svg', // SVG peut contenir du JavaScript
  '.html', '.htm', '.xhtml',
  '.js', '.mjs', '.ts',
];

/**
 * Vérifie les magic bytes d'un fichier
 */
const verifyMagicBytes = (buffer, mimeType) => {
  const typeConfig = ALLOWED_TYPES[mimeType];
  if (!typeConfig) return false;

  return typeConfig.magicBytes.some(magicBytes => {
    for (let i = 0; i < magicBytes.length; i++) {
      if (buffer[i] !== magicBytes[i]) return false;
    }
    return true;
  });
};

/**
 * Configuration Multer sécurisée
 */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_DIR || '/app/uploads/temp';
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {
    // Génère un nom de fichier sécurisé (UUID + extension)
    const uniqueId = crypto.randomUUID();
    const originalExt = path.extname(file.originalname).toLowerCase();
    
    // Vérifie que l'extension est autorisée
    const isExtAllowed = Object.values(ALLOWED_TYPES)
      .some(config => config.extensions.includes(originalExt));
    
    if (!isExtAllowed) {
      return cb(new Error('Extension non autorisée'));
    }

    const safeFilename = `${uniqueId}${originalExt}`;
    cb(null, safeFilename);
  }
});

/**
 * Filtre de fichiers Multer
 */
const fileFilter = (req, file, cb) => {
  const originalName = file.originalname;
  const mimeType = file.mimetype;
  const extension = path.extname(originalName).toLowerCase();

  logger.debug('Upload attempt', {
    originalName,
    mimeType,
    extension,
    ip: req.ip
  });

  // 1. Vérifie les extensions dangereuses
  if (DANGEROUS_EXTENSIONS.includes(extension)) {
    logger.warn('Extension dangereuse bloquée', {
      originalName,
      extension,
      ip: req.ip
    });
    return cb(new AppError('Type de fichier non autorisé', 400), false);
  }

  // 2. Vérifie les doubles extensions (shell.php.jpg)
  const nameParts = originalName.split('.');
  if (nameParts.length > 2) {
    for (let i = 0; i < nameParts.length - 1; i++) {
      const ext = '.' + nameParts[i].toLowerCase();
      if (DANGEROUS_EXTENSIONS.includes(ext)) {
        logger.warn('Double extension dangereuse bloquée', {
          originalName,
          ip: req.ip
        });
        return cb(new AppError('Type de fichier non autorisé', 400), false);
      }
    }
  }

  // 3. Vérifie le type MIME
  if (!ALLOWED_TYPES[mimeType]) {
    logger.warn('MIME type non autorisé', {
      originalName,
      mimeType,
      ip: req.ip
    });
    return cb(new AppError('Type de fichier non autorisé', 400), false);
  }

  // 4. Vérifie la cohérence extension/MIME
  const allowedExts = ALLOWED_TYPES[mimeType].extensions;
  if (!allowedExts.includes(extension)) {
    logger.warn('Incohérence MIME/extension', {
      originalName,
      mimeType,
      extension,
      ip: req.ip
    });
    return cb(new AppError('Type de fichier non autorisé', 400), false);
  }

  cb(null, true);
};

/**
 * Instance Multer configurée
 */
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB max
    files: 5,                   // 5 fichiers max par requête
    fields: 10,                 // 10 champs max
    fieldSize: 1024 * 1024,     // 1 MB max par champ
  }
});

/**
 * Middleware de validation post-upload
 * 
 * Vérifie les magic bytes après l'upload
 */
const validateUploadedFile = async (req, res, next) => {
  if (!req.file && !req.files) {
    return next();
  }

  const files = req.files || [req.file];

  try {
    for (const file of files) {
      // Lit les premiers bytes du fichier
      const buffer = await fs.readFile(file.path);

      // Vérifie le vrai type du fichier via magic bytes
      const fileTypeResult = await FileType.fromBuffer(buffer);

      if (!fileTypeResult) {
        await fs.unlink(file.path);
        throw new AppError('Type de fichier non détectable', 400);
      }

      // Vérifie que le type détecté correspond au type déclaré
      if (fileTypeResult.mime !== file.mimetype) {
        logger.warn('MIME spoofing détecté', {
          declaredMime: file.mimetype,
          realMime: fileTypeResult.mime,
          filename: file.originalname,
          ip: req.ip
        });
        await fs.unlink(file.path);
        throw new AppError('Type de fichier invalide', 400);
      }

      // Vérifie les magic bytes manuellement
      if (!verifyMagicBytes(buffer, file.mimetype)) {
        logger.warn('Magic bytes invalides', {
          filename: file.originalname,
          ip: req.ip
        });
        await fs.unlink(file.path);
        throw new AppError('Fichier corrompu ou manipulé', 400);
      }

      // Recherche de code malveillant dans le fichier
      const content = buffer.toString('utf8', 0, Math.min(buffer.length, 10000));
      const dangerousPatterns = [
        /<\?php/i,
        /<\?=/i,
        /<%/,
        /<script/i,
        /javascript:/i,
        /eval\s*\(/i,
        /system\s*\(/i,
        /exec\s*\(/i,
        /passthru\s*\(/i,
        /shell_exec/i,
      ];

      for (const pattern of dangerousPatterns) {
        if (pattern.test(content)) {
          logger.warn('Code malveillant détecté dans fichier', {
            filename: file.originalname,
            pattern: pattern.toString(),
            ip: req.ip
          });
          await fs.unlink(file.path);
          throw new AppError('Fichier contenant du code malveillant', 400);
        }
      }

      // Calcule le hash SHA256 du fichier
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');
      file.hash = hash;

      logger.info('Fichier uploadé avec succès', {
        filename: file.filename,
        originalname: file.originalname,
        size: file.size,
        hash: hash.substring(0, 16) + '...',
        ip: req.ip
      });
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Déplace le fichier vers le dossier final
 */
const moveToFinal = async (tempPath, finalDir, filename) => {
  const safeName = sanitizeFilename(filename);
  const finalPath = path.join(finalDir, safeName);

  // Vérifie que le chemin final ne sort pas du dossier
  const resolvedFinal = path.resolve(finalPath);
  const resolvedDir = path.resolve(finalDir);

  if (!resolvedFinal.startsWith(resolvedDir)) {
    throw new AppError('Chemin non autorisé', 400);
  }

  await fs.mkdir(finalDir, { recursive: true });
  await fs.rename(tempPath, finalPath);

  return finalPath;
};

module.exports = {
  upload,
  validateUploadedFile,
  moveToFinal,
  ALLOWED_TYPES,
  DANGEROUS_EXTENSIONS
};
