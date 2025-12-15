# ✅ OWASP Top 10 – Conformité
IPSSI_PATCH_v2.0

## A01: Broken Access Control
✔ JWT
✔ Vérification owner/admin (IDOR)
✔ Routes protégées

## A02: Cryptographic Failures
✔ Argon2id pour les mots de passe
✔ HTTPS via Nginx
✔ Cookies httpOnly / secure

## A03: Injection
✔ ORM Sequelize
✔ Requêtes paramétrées
✔ Validation serveur

## A04: Insecure Design
✔ Security by Design
✔ Defense in Depth

## A05: Security Misconfiguration
✔ Helmet
✔ CORS restrictif
✔ Headers de sécurité
✔ Docker hardening

## A06: Vulnerable Components
✔ Dépendances à jour
✔ npm audit
✔ Images Docker minimales

## A07: Identification & Authentication Failures
✔ JWT
✔ Lockout anti brute-force
✔ Rate limiting

## A08: Software & Data Integrity Failures
✔ Pas d’exécution dynamique
✔ Upload contrôlé

## A09: Logging & Monitoring
✔ Winston
✔ Logs structurés
✔ Pas de données sensibles

## A10: SSRF
✔ Pas d’accès URL dynamique
✔ Pas de proxy utilisateur
