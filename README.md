# 🔐 IPSSI_PATCH_SECURE v2.1

## Projet de Sécurisation d'Application Web - Security by Design

[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)](docs/SECURITY_FIXES.md)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20Protected-blue.svg)](docs/OWASP_CHECKLIST.md)
[![Docker](https://img.shields.io/badge/Docker-Containerized-blue.svg)](docs/DOCKER_GUIDE.md)
[![Argon2id](https://img.shields.io/badge/Password-Argon2id-purple.svg)](#)

---

## 📋 Table des Matières

1. [Présentation](#-présentation)
2. [Vulnérabilités Corrigées](#-vulnérabilités-corrigées)
3. [Architecture](#-architecture)
4. [Installation](#-installation)
5. [Technologies](#-technologies)
6. [Documentation](#-documentation)

---

## 🎯 Présentation

Ce projet transforme une application web vulnérable en **application sécurisée** en appliquant :
- **Security by Design** : Architecture pensée sécurité dès la conception
- **Defense in Depth** : Multiples couches de protection
- **OWASP Top 10** : Conformité aux standards de sécurité

---

## 🛡️ Vulnérabilités Corrigées (14/14)

| #  | Vulnérabilité | Protection Implémentée | Fichier(s) |
|----|---------------|------------------------|------------|
| 1  | **Admin Login (htpasswd)** | Basic Auth Nginx + JWT (admin) | `nginx/htpasswd`, `middlewares/auth.js` |
| 2  | **Headers non fiables (User-Agent / Referer)** | Validation et filtrage des headers | `middlewares/headersSecurity.js` |
| 3  | **Manipulation de cookies / session** | Cookies signés, httpOnly, secure, sameSite | `middlewares/auth.js` |
| 4  | **SQL Injection — User Table** | Sequelize ORM + requêtes paramétrées | `models/User.js` |
| 5  | **SQL Injection — Image Table** | Sequelize ORM + requêtes paramétrées | `models/Image.js` |
| 6  | **CSRF / champs client non fiables** | Validation serveur + CSRF token | `validators/*.js`, `middlewares/csrf.js` |
| 7  | **Brute force authentification** | Rate limiting + Account lockout (Argon2id) | `middlewares/rateLimiter.js` |
| 8  | **Accès fichiers cachés (.hidden)** | Blocage Nginx des fichiers sensibles | `nginx/nginx.conf` |
| 9  | **Open Redirect** | Whitelist d’URL + validation | `middlewares/redirectValidator.js` |
| 10 | **LFI / Data URI abuse** | Validation stricte des chemins et schémas | `middlewares/lfiProtection.js` |
| 11 | **Absence de validation des entrées** | express-validator strict | `validators/*.js` |
| 12 | **Image Upload Bypass** | Magic bytes, MIME, extensions, détection de contenu malveillant | `middlewares/uploadSecurity.js` |
| 13 | **Path Traversal** | Sanitization des chemins + confinement uploads | `middlewares/lfiProtection.js` |
| 14 | **HTML Injection / XSS** | Helmet CSP + DOMPurify + escaping | `middlewares/security.js` |


---

## 🚀 Installation

### Prérequis
- Docker >= 20.10
- Docker Compose >= 2.0
- Git

### Démarrage rapide

```bash
# 1. Cloner
git clone https://github.com/yokozuna47/IPSSI_PATCH.git
cd IPSSI_PATCH_V2

# 2. Configuration
cp .env.example .env
# Éditez .env avec vos valeurs sécurisées

# 3. Lancer
make install
make dev

# 4. Accéder
# Frontend : http://localhost
# API      : http://localhost/api
# Admin    : http://localhost/admin (user: admin, pass: voir .env)

## Commandes disponibles

make help       # Affiche l'aide
make dev        # Mode développement
make prod       # Mode production
make test       # Tests
make security   # Audit sécurité
make logs       # Voir les logs

## Technologies

***Backend***

| Tech               | Version | Usage                     |
| ------------------ | ------- | ------------------------- |
| Node.js            | 20 LTS  | Runtime                   |
| Express            | 4.18    | Framework                 |
| Sequelize          | 6.35    | ORM (anti-injection)      |
| PostgreSQL         | 16      | Base de données           |
| Redis              | 7       | Sessions / Rate limiting  |
| **Argon2id**       | 0.31    | **Hachage mots de passe** |
| Helmet             | 7.1     | Headers sécurité          |
| express-rate-limit | 7.1     | Anti brute-force          |


***Frontend***

| Tech      | Version | Usage        |
| --------- | ------- | ------------ |
| React     | 18      | Framework UI |
| DOMPurify | 3.0     | Anti-XSS     |
| Axios     | 1.6     | HTTP client  |

***Infrastructure***

| Tech   | Version | Usage               |
| ------ | ------- | ------------------- |
| Docker | 24      | Conteneurisation    |
| Nginx  | 1.25    | Reverse proxy       |
| Trivy  | Latest  | Scan vulnérabilités |

***Documentation***

| Document                                          | Description                         |
| ------------------------------------------------- | ----------------------------------- |
| [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)       | Audit de sécurité de la version d’origine (avant remédiation) | 
| [SECURITY_FIXES.md](docs/SECURITY_FIXES.md)       | Détail des 14 corrections           |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md)           | Architecture technique              |
| [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) | Documentation API REST              |
| [OWASP_CHECKLIST.md](docs/OWASP_CHECKLIST.md)     | Conformité OWASP                    |


📁 Structure du Projet

IPSSI_PATCH_V2/
├── README.md
├── docker-compose.yml
├── .env.example
├── Makefile
│
├── docs/
│   ├── SECURITY_AUDIT.md
│   ├── SECURITY_FIXES.md
│   └── OWASP_CHECKLIST.md
│
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── server.js
│       ├── app.js
│       ├── config/
│       ├── models/
│       │   ├── User.js
│       │   ├── Image.js
│       │   └── Comment.js
│       ├── middlewares/
│       │   ├── security.js
│       │   ├── auth.js
│       │   ├── rateLimiter.js
│       │   ├── headersSecurity.js
│       │   ├── uploadSecurity.js
│       │   ├── lfiProtection.js
│       │   ├── redirectValidator.js
│       │   ├── csrf.js
│       │   └── errorHandler.js
│       ├── controllers/
│       ├── routes/
│       ├── validators/
│       └── utils/
│           └── argon2.js
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.js
│       ├── pages/
│       │   ├── Login.jsx
│       │   ├── Register.jsx
│       │   └── Dashboard.jsx
│       ├── components/
│       └── utils/
│           └── sanitize.js
│
├── nginx/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── htpasswd
│
└── database/
    └── init.sql

