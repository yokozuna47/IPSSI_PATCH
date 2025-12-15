# 🔍 AUDIT DE SÉCURITÉ - IPSSI_PATCH

## Document d'Analyse des Vulnérabilités

**Date de l'audit** : 2025  
**Application auditée** : IPSSI_PATCH (version originale)  
**Auditeur** : Ba Issiakha  
**Méthodologie** : Analyse statique du code + OWASP Top 10

---

## 📋 Table des Matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Méthodologie](#2-méthodologie)
3. [Vulnérabilités Critiques](#3-vulnérabilités-critiques)
4. [Vulnérabilités Moyennes](#4-vulnérabilités-moyennes)
5. [Vulnérabilités Faibles](#5-vulnérabilités-faibles)
6. [Analyse des Dépendances](#6-analyse-des-dépendances)
7. [Recommandations Prioritaires](#7-recommandations-prioritaires)

---

## 1. Résumé Exécutif

### Vue d'ensemble

| Sévérité | Nombre | Pourcentage |
|----------|--------|-------------|
| 🔴 Critique | 5 | 50% |
| 🟠 Moyenne | 4 | 40% |
| 🟡 Faible | 1 | 10% |
| **Total** | **10** | 100% |

### Score de Risque Global : **CRITIQUE** 🔴

L'application présente des vulnérabilités majeures permettant :
- ✗ Accès complet à la base de données
- ✗ Vol de données sensibles (mots de passe)
- ✗ Exécution de code arbitraire
- ✗ Déni de service

---

## 2. Méthodologie

### 2.1 Approche d'Audit

```
┌─────────────────────────────────────────────────────────────────┐
│                    MÉTHODOLOGIE D'AUDIT                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 📥 COLLECTE                                                 │
│     → Récupération du code source                               │
│     → Identification des technologies                           │
│                                                                 │
│  2. 🔍 ANALYSE STATIQUE                                         │
│     → Revue manuelle du code                                    │
│     → Recherche de patterns vulnérables                         │
│                                                                 │
│  3. 📊 CLASSIFICATION                                           │
│     → Mapping OWASP Top 10                                      │
│     → Évaluation CVSS                                           │
│                                                                 │
│  4. 📝 DOCUMENTATION                                            │
│     → Rédaction des findings                                    │
│     → Recommandations de correction                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Fichiers Analysés

| Fichier | Type | Lignes | Analysé |
|---------|------|--------|---------|
| `backend/server.js` | Backend | 98 | ✅ |
| `backend/package.json` | Config | 15 | ✅ |
| `frontend/src/App.js` | Frontend | 115 | ✅ |
| `frontend/src/index.js` | Frontend | 12 | ✅ |
| `frontend/package.json` | Config | 38 | ✅ |

---

## 3. Vulnérabilités Critiques

### 3.1 VULN-001 : SQL Injection - Exécution Arbitraire de Requêtes

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-001 |
| **Sévérité** | 🔴 CRITIQUE |
| **CVSS Score** | 10.0 |
| **OWASP** | A03:2021 - Injection |
| **CWE** | CWE-89 |
| **Fichier** | `backend/server.js` |
| **Ligne** | 48-50 |

#### Description

Le endpoint `/query` exécute directement le contenu du body HTTP comme requête SQL sans aucune validation ni sanitization.

#### Code Vulnérable

```javascript
// server.js - Ligne 48-50
app.post('/query', async (req, res) => {
  db.run(req.body)  // ⚠️ DANGER : Exécution directe de la requête
  res.send('Inserted 3 users into database.');
});
```

#### Preuve d'Exploitation (PoC)

```bash
# Suppression de toutes les tables
curl -X POST http://localhost:8000/query \
  -H "Content-Type: text/plain" \
  -d "DROP TABLE users; DROP TABLE comments;"

# Extraction de toutes les données
curl -X POST http://localhost:8000/query \
  -H "Content-Type: text/plain" \
  -d "SELECT * FROM users"
```

#### Impact

- 🔴 Accès complet en lecture/écriture à la base de données
- 🔴 Suppression de données
- 🔴 Modification de données
- 🔴 Extraction de données sensibles

#### Recommandation

Supprimer ce endpoint ou implémenter un ORM avec requêtes paramétrées.

---

### 3.2 VULN-002 : SQL Injection - Endpoint /user

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-002 |
| **Sévérité** | 🔴 CRITIQUE |
| **CVSS Score** | 10.0 |
| **OWASP** | A03:2021 - Injection |
| **CWE** | CWE-89 |
| **Fichier** | `backend/server.js` |
| **Ligne** | 63-65 |

#### Description

Le endpoint `/user` exécute le body comme requête SQL SELECT.

#### Code Vulnérable

```javascript
// server.js - Ligne 56-70
app.post('/user', (req, res) => {
    console.log(req.body);
    
    db.all(
        req.body,  // ⚠️ DANGER : Requête SQL directe
        [], 
        (err, rows) => {
            if (err) {
                console.error('SQL Error:', err.message);
                return res.status(500).json({ error: err.message });
            }
            console.log('Query results:', rows);
            res.json(rows);
        }
    );
});
```

#### Preuve d'Exploitation (PoC)

```bash
# Récupérer tous les mots de passe
curl -X POST http://localhost:8000/user \
  -H "Content-Type: text/plain" \
  -d "SELECT * FROM users"

# Union-based injection
curl -X POST http://localhost:8000/user \
  -H "Content-Type: text/plain" \
  -d "SELECT id, name, password FROM users UNION SELECT 1, sql, 3 FROM sqlite_master"
```

#### Impact

Identique à VULN-001.

---

### 3.3 VULN-003 : SQL Injection - Interpolation de Strings

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-003 |
| **Sévérité** | 🔴 CRITIQUE |
| **CVSS Score** | 9.8 |
| **OWASP** | A03:2021 - Injection |
| **CWE** | CWE-89 |
| **Fichier** | `backend/server.js` |
| **Ligne** | 30-31 |

#### Description

Les données utilisateur sont interpolées directement dans la requête SQL via template strings.

#### Code Vulnérable

```javascript
// server.js - Ligne 27-34
users.forEach(u => {
    const fullName = `${u.name.first} ${u.name.last}`;
    const password = u.login.password;

    db.run(
        `INSERT INTO users (name, password) VALUES ('${fullName}', '${password}')`,
        // ⚠️ DANGER : Interpolation directe
        (err) => {
            if (err) console.error(err.message);
        }
    );
});
```

#### Exploitation

Si les données de l'API externe contenaient des caractères malicieux comme `'; DROP TABLE users; --`, la requête serait compromise.

#### Recommandation

Utiliser des requêtes paramétrées :

```javascript
db.run(
    'INSERT INTO users (name, password) VALUES (?, ?)',
    [fullName, password]
);
```

---

### 3.4 VULN-004 : Mots de Passe Stockés en Clair

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-004 |
| **Sévérité** | 🔴 CRITIQUE |
| **CVSS Score** | 9.1 |
| **OWASP** | A02:2021 - Cryptographic Failures |
| **CWE** | CWE-256 |
| **Fichier** | `backend/server.js` |
| **Ligne** | 14-17 |

#### Description

Les mots de passe sont stockés en texte clair dans la base de données.

#### Code Vulnérable

```javascript
// server.js - Ligne 14-17
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  password TEXT NOT NULL  // ⚠️ DANGER : Pas de hachage
)`);
```

#### Impact

- 🔴 En cas de fuite de base de données, tous les mots de passe sont compromis
- 🔴 Violation RGPD et réglementations
- 🔴 Réutilisation de mots de passe sur d'autres sites

#### Recommandation

Utiliser bcrypt avec un coût de 12 minimum :

```javascript
const bcrypt = require('bcryptjs');
const hashedPassword = await bcrypt.hash(password, 12);
```

---

### 3.5 VULN-005 : Exposition des Mots de Passe dans l'UI

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-005 |
| **Sévérité** | 🔴 CRITIQUE |
| **CVSS Score** | 7.5 |
| **OWASP** | A01:2021 - Broken Access Control |
| **CWE** | CWE-200 |
| **Fichier** | `frontend/src/App.js` |
| **Ligne** | 79 |

#### Description

L'interface affiche les mots de passe des utilisateurs.

#### Code Vulnérable

```javascript
// App.js - Ligne 76-81
{queriedUser.map(u => (
  <p key={u.id}>
    ID: {u.id} — Name: {u.name} — Password: {u.password}
    // ⚠️ DANGER : Affichage du mot de passe
  </p>
))}
```

#### Impact

- 🔴 N'importe qui peut voir les mots de passe
- 🔴 Shoulder surfing possible
- 🔴 Capture d'écran expose les données

#### Recommandation

Ne jamais renvoyer le mot de passe depuis l'API. Exclure le champ dans les réponses.

---

## 4. Vulnérabilités Moyennes

### 4.1 VULN-006 : CORS Trop Permissif

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-006 |
| **Sévérité** | 🟠 MOYENNE |
| **OWASP** | A05:2021 - Security Misconfiguration |
| **Fichier** | `backend/server.js` |
| **Ligne** | 10 |

#### Code Vulnérable

```javascript
app.use(cors());  // ⚠️ Accepte TOUTES les origines
```

#### Impact

- N'importe quel site malveillant peut effectuer des requêtes
- Facilite les attaques CSRF

#### Recommandation

```javascript
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

---

### 4.2 VULN-007 : Absence de Rate Limiting

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-007 |
| **Sévérité** | 🟠 MOYENNE |
| **OWASP** | A07:2021 - Identification and Authentication Failures |
| **Fichier** | `backend/server.js` |

#### Description

Aucune limite sur le nombre de requêtes par IP/utilisateur.

#### Impact

- Attaques par brute force possibles
- Déni de service (DoS)
- Enumération d'utilisateurs

#### Recommandation

```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});

app.use(limiter);
```

---

### 4.3 VULN-008 : Headers de Sécurité Manquants

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-008 |
| **Sévérité** | 🟠 MOYENNE |
| **OWASP** | A05:2021 - Security Misconfiguration |
| **Fichier** | `backend/server.js` |

#### Description

Helmet n'est pas utilisé. Les headers de sécurité suivants sont absents :
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- X-XSS-Protection

#### Recommandation

```javascript
const helmet = require('helmet');
app.use(helmet());
```

---

### 4.4 VULN-009 : Absence de Validation des Entrées

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-009 |
| **Sévérité** | 🟠 MOYENNE |
| **OWASP** | A03:2021 - Injection |
| **Fichier** | `backend/server.js` |

#### Description

Aucune validation des données reçues (type, longueur, format).

#### Code Concerné

```javascript
// Aucune validation sur les endpoints
app.post('/comment', (req, res) => {
  const comment = req.body;  // ⚠️ Pas de validation
  // ...
});
```

#### Recommandation

Utiliser express-validator :

```javascript
const { body, validationResult } = require('express-validator');

app.post('/comment',
  body('content').isString().trim().isLength({ min: 1, max: 500 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // ...
  }
);
```

---

## 5. Vulnérabilités Faibles

### 5.1 VULN-010 : Exposition des Erreurs SQL

| Attribut | Valeur |
|----------|--------|
| **ID** | VULN-010 |
| **Sévérité** | 🟡 FAIBLE |
| **OWASP** | A05:2021 - Security Misconfiguration |
| **Fichier** | `backend/server.js` |
| **Ligne** | 66 |

#### Code Vulnérable

```javascript
return res.status(500).json({ error: err.message });
// ⚠️ Révèle la structure SQL à l'attaquant
```

#### Impact

- Information disclosure
- Aide à l'exploitation d'autres vulnérabilités

#### Recommandation

```javascript
return res.status(500).json({ error: 'Une erreur est survenue' });
// Logger l'erreur complète côté serveur
logger.error(err);
```

---

## 6. Analyse des Dépendances

### Backend - package.json

| Dépendance | Version | Vulnérabilités Connues |
|------------|---------|------------------------|
| express | 5.2.1 | ⚠️ Version beta non stable |
| axios | 1.13.2 | ✅ OK |
| cors | 2.8.5 | ✅ OK |
| sqlite3 | 5.1.7 | ⚠️ Pas recommandé en production |
| nodemon | 3.1.11 | ✅ Dev only |

### Recommandations Dépendances

1. Utiliser Express 4.18 (stable) au lieu de 5.x (beta)
2. Remplacer SQLite par PostgreSQL en production
3. Ajouter les dépendances de sécurité manquantes

---

## 7. Recommandations Prioritaires

### Ordre de Correction

| Priorité | Vulnérabilité | Effort | Impact |
|----------|---------------|--------|--------|
| 1️⃣ | VULN-001, 002 - SQL Injection | Moyen | Très élevé |
| 2️⃣ | VULN-003 - Interpolation SQL | Faible | Élevé |
| 3️⃣ | VULN-004 - Mots de passe clair | Moyen | Très élevé |
| 4️⃣ | VULN-005 - Exposition UI | Faible | Élevé |
| 5️⃣ | VULN-006 - CORS | Faible | Moyen |
| 6️⃣ | VULN-007 - Rate Limiting | Faible | Moyen |
| 7️⃣ | VULN-008 - Headers | Faible | Moyen |
| 8️⃣ | VULN-009 - Validation | Moyen | Moyen |
| 9️⃣ | VULN-010 - Erreurs | Faible | Faible |

### Actions Immédiates

1. ⛔ **Désactiver** les endpoints `/query` et `/user` en urgence
2. 🔐 Implémenter un ORM (Sequelize)
3. 🔑 Hasher les mots de passe existants
4. 🛡️ Ajouter Helmet et CORS restrictif
5. 📊 Mettre en place le logging

---

## 📎 Annexes

### A. Références

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)

### B. Outils Utilisés

- Analyse manuelle du code
- npm audit
- ESLint security plugin

---

**Document généré dans le cadre du module Cybersécurité - IPSSI**
