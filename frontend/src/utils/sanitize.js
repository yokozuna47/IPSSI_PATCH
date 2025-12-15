/**
 * =============================================================================
 * UTILS/SANITIZE.JS - Sanitization Frontend
 * =============================================================================
 * 
 * Protection XSS côté client
 * 
 * =============================================================================
 */

/**
 * Sanitize une chaîne pour éviter les XSS
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim();
};

/**
 * Sanitize HTML (pour affichage de contenu riche)
 * Utilise DOMPurify si disponible
 */
export const sanitizeHTML = (html) => {
  if (typeof window !== 'undefined' && window.DOMPurify) {
    return window.DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
  }
  
  // Fallback : escape tout
  return sanitizeInput(html);
};

/**
 * Valide une URL
 */
export const isValidUrl = (url) => {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};

/**
 * Sanitize un nom de fichier
 */
export const sanitizeFilename = (filename) => {
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '.')
    .substring(0, 255);
};

export default {
  sanitizeInput,
  sanitizeHTML,
  isValidUrl,
  sanitizeFilename
};
