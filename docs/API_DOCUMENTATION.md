# 📡 API Documentation — IPSSI_PATCH_v2.0

Documentation des endpoints REST exposés par l’API backend sécurisée.

Base URL (via Nginx) :  
http://localhost/api

yaml
Copier le code

Toutes les routes sensibles sont protégées par :
- JWT (cookies httpOnly)
- CSRF Token (Double Submit Cookie)
- Rate limiting
- Validation stricte des entrées

---

## 🔐 Authentification (`/api/auth`)

### POST `/api/auth/register`
Créer un compte utilisateur.

**Body (JSON)**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "PasswordSecure123!"
}
Réponse

json
Copier le code
{
  "success": true,
  "message": "Compte créé",
  "data": {
    "user": {
      "id": "uuid",
      "username": "john_doe",
      "email": "john@example.com",
      "role": "user"
    }
  }
}
POST /api/auth/login
Authentification utilisateur.

Body (JSON)

json
Copier le code
{
  "email": "john@example.com",
  "password": "PasswordSecure123!"
}
Sécurité

Rate limit anti-bruteforce

Account lockout après échecs

Cookies httpOnly

POST /api/auth/logout
Déconnexion utilisateur.

Protection

JWT requis

POST /api/auth/refresh
Rafraîchissement du token d’accès.

Utilisation

Appelé automatiquement par le frontend (Axios interceptor)

GET /api/auth/me
Retourne l’utilisateur authentifié.

Protection

JWT requis

👤 Utilisateurs (/api/users)
GET /api/users
Lister les utilisateurs (pagination).

Query params

page (optionnel)

limit (optionnel)

search (optionnel)

Protection

JWT requis

IDOR protégé

GET /api/users/:id
Récupérer un utilisateur par ID.

Protection

JWT requis

Validation UUID

IDOR contrôlé

PUT /api/users/:id
Mettre à jour un utilisateur.

Protection

JWT requis

Owner ou admin uniquement

DELETE /api/users/:id
Supprimer un utilisateur.

Protection

JWT requis

Admin uniquement

💬 Commentaires (/api/comments)
GET /api/comments
Lister les commentaires.

Protection

JWT requis (mode “tout protégé”)

GET /api/comments/:id
Récupérer un commentaire par ID.

Protection

JWT requis

POST /api/comments
Créer un commentaire.

Body (JSON)

json
Copier le code
{
  "content": "Mon commentaire"
}
Protection

JWT requis

Validation serveur

CSRF token requis

DELETE /api/comments/:id
Supprimer un commentaire.

Protection

JWT requis

Owner OU admin (anti-IDOR)

📤 Uploads (/api/uploads)
POST /api/uploads
Upload de fichier (images uniquement).

Sécurité

Multer sécurisé

Vérification MIME

Magic bytes

Extensions interdites

Scan contenu

Stockage non exécutable

Protection

JWT requis

CSRF requis

🩺 Healthcheck
GET /api/health
Vérifier l’état de l’API.

Réponse

json
Copier le code
{
  "status": "healthy",
  "timestamp": "ISO_DATE",
  "uptime": 12345
}


## Sécurité Global

❌ Pas d’auth par header custom

✅ Cookies httpOnly + SameSite

✅ CSRF token obligatoire sur requêtes mutantes

✅ Rate limiting Redis

✅ Validation systématique des entrées

✅ Logs sécurisés (pas de données sensibles)