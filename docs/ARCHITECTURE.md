# 🏗️ Architecture Technique — IPSSI_PATCH v2.0

## Vue d’ensemble

L’application repose sur une architecture conteneurisée sécurisée,
basée sur le principe de Defense in Depth.

## Composants

- Nginx : Reverse proxy sécurisé
- Frontend : React
- Backend : Node.js / Express
- Base de données : PostgreSQL
- Cache / Sécurité : Redis
- Conteneurisation : Docker / Docker Compose

## Flux applicatifs

Utilisateur
→ Nginx (HTTPS, headers sécurité, rate limit, htpasswd admin)
→ Frontend React
→ API Express sécurisée (JWT, validation, rate limiting)
→ PostgreSQL / Redis

## Sécurité intégrée

- Authentification JWT (cookies httpOnly)
- Séparation Frontend / Backend
- ORM Sequelize (anti SQL injection)
- Rate limiting Redis
- Validation serveur systématique
- Upload sécurisé (MIME, magic bytes)
- Logs centralisés

## Déploiement

- Conteneurs isolés
- Réseau Docker interne
- Secrets via variables d’environnement
- Pas d’accès direct à la base de données
