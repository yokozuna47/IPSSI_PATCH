# MAKEFILE - IPSSI_PATCH_SECURE v2.1

.PHONY: help dev prod logs stop clean security htpasswd

help:
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║       IPSSI_PATCH_SECURE v2.1 - Commandes            ║"
	@echo "╚══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  make dev        - Démarrer en développement"
	@echo "  make prod       - Démarrer en production"
	@echo "  make logs       - Voir les logs"
	@echo "  make stop       - Arrêter les conteneurs"
	@echo "  make clean      - Nettoyer tout"
	@echo "  make security   - Audit des dépendances"
	@echo "  make htpasswd   - Générer htpasswd Nginx"
	@echo ""

dev:
	@echo "🚀 Démarrage en développement..."
	docker-compose up -d
	@echo "✅ Démarré !"
	@echo "Frontend: http://localhost"
	@echo "API: http://localhost/api"

prod:
	@echo "🚀 Démarrage en production..."
	docker-compose up -d --build
	@echo "✅ En production !"

logs:
	docker-compose logs -f

stop:
	docker-compose down

clean:
	docker-compose down -v --remove-orphans
	docker system prune -f

security:
	@echo "🔐 Audit de sécurité (dépendances)..."
	cd backend && npm audit || true
	cd frontend && npm audit || true
	@echo "✅ Audit terminé"

htpasswd:
	@echo "🔐 Génération du mot de passe htpasswd..."
	@read -p "Username: " user; \
	read -sp "Password: " pass; \
	echo ""; \
	echo "$$user:$$(openssl passwd -apr1 $$pass)" > nginx/htpasswd
	@echo "✅ nginx/htpasswd mis à jour"
