# ApexMail — Manual Deployment (emergency/hotfix path only)
# =========================================================
#
# CANONICAL production deployment is CI/CD — see deploy/DEPLOYMENT.md (the
# single source of truth):
#   .github/workflows/deploy.yml builds all images and pushes them to GHCR,
#   then .github/workflows/deploy-hetzner.yml SSHes to the host, renders the
#   secrets, pulls the images and runs `docker compose up -d`.
#
# The targets below are a MANUAL FALLBACK for emergency hotfixes and local
# testing — they are NOT the production path. They rsync code to the host and
# run deploy/scripts/deploy.sh, which builds images LOCALLY (tagged with
# GHCR-style names, never pushed). CI/CD remains the single supported path.
#
# Usage:
#   make deploy                         — full manual deploy (sync all + rebuild all)
#   make deploy-service S=api-server    — partial: sync only changed code dirs,
#                                          rebuild only the named service(s)
#   make deploy-service S=mta,imap-server  — rebuild multiple services
#   make deploy-quick                   — run deploy.sh without rsync (rebuild
#                                          whatever is on the server)
#   make deploy-restart                 — just restart containers (no rebuild)
#   make verify                         — check live endpoints
#
# Server-local state NEVER touched by these targets:
#   .env, secrets/, certs/ (not in SYNC_DIRS), target/ (Docker build cache),
#   and deploy/nginx/ssl/ (the Let's Encrypt store — excluded from the rsync
#   of deploy/ with --exclude='ssl'; deleting it would kill live TLS certs).
#

SERVER_HOST := root@95.216.226.51
SSH         := ssh -o StrictHostKeyChecking=no $(SERVER_HOST)
RSYNC       := rsync -avz
RSYNC_SSH   := -e "ssh -o StrictHostKeyChecking=no"

# Code directories that get synced. Each rsync uses --delete so the server
# has EXACTLY the current repo state — no stale files, no old binaries.
SYNC_DIRS := services/mail-server packages/kiwicaptcha packages/kiwicaptcha-wasm apps/marketing-zola deploy
SYNC_FILES := docker-compose.yml docker-compose.prod.yml

# Map service names to the code directories they depend on (for partial deploys).
# When you do `make deploy-service S=api-server`, only these dirs are synced.
SERVICE_DEPS_api-server    := services/mail-server/crates/api-server services/mail-server/crates/ui-foundation services/mail-server/Cargo.toml packages/kiwicaptcha packages/kiwicaptcha-wasm
SERVICE_DEPS_mta           := services/mail-server/crates/mta services/mail-server/crates/mail-common services/mail-server/crates/mail-proto services/mail-server/Cargo.toml
SERVICE_DEPS_imap-server   := services/mail-server/crates/imap-server services/mail-server/crates/mailstore-core services/mail-server/Cargo.toml
SERVICE_DEPS_mailstore     := services/mail-server/crates/mailstore-core services/mail-server/Cargo.toml
SERVICE_DEPS_worker        := services/mail-server/crates/worker-processors services/mail-server/Cargo.toml
SERVICE_DEPS_enterprise    := services/mail-server/crates/enterprise services/mail-server/Cargo.toml
SERVICE_DEPS_observability := services/mail-server/crates/observability-service services/mail-server/Cargo.toml
SERVICE_DEPS_marketing     := apps/marketing-zola
SERVICE_DEPS_tracking      := deploy/Dockerfile.tracking services/mail-server/crates/tracking-service
SERVICE_DEPS_status-server := services/mail-server/crates/auth-server services/mail-server/Cargo.toml

.PHONY: deploy deploy-service deploy-quick deploy-restart verify

## deploy: Full deploy — sync all code + rebuild all images + restart
deploy:
	@echo "==> Syncing ALL code to server (clean — stale files removed)..."
	@for dir in $(SYNC_DIRS); do \
		echo "  $$dir/"; \
		$(RSYNC) --delete \
			--exclude='target' --exclude='node_modules' --exclude='public' --exclude='vendor' \
			--exclude='ssl' \
			$(RSYNC_SSH) ./$$dir/ $(SERVER_HOST):/opt/apexmail/$$dir/; \
	done
	@for file in $(SYNC_FILES); do \
		echo "  $$file"; \
		$(RSYNC) $(RSYNC_SSH) ./$$file $(SERVER_HOST):/opt/apexmail/$$file; \
	done
	@echo "==> Running full deploy on server..."
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh'

## deploy-service S=name: Partial deploy — sync only changed code + rebuild one service
deploy-service:
	@if [ -z "$(S)" ]; then echo "Usage: make deploy-service S=api-server"; exit 1; fi
	@echo "==> Partial deploy: $(S)"
	@echo "==> Syncing only changed code directories..."
	@$(RSYNC) --delete \
		--exclude='target' --exclude='node_modules' --exclude='public' --exclude='vendor' \
		$(RSYNC_SSH) \
		./services/mail-server/ \
		$(SERVER_HOST):/opt/apexmail/services/mail-server/
	@$(RSYNC) --delete $(RSYNC_SSH) \
		./packages/kiwicaptcha/ \
		$(SERVER_HOST):/opt/apexmail/packages/kiwicaptcha/
	@$(RSYNC) --delete \
		--exclude='target' --exclude='node_modules' --exclude='public' --exclude='vendor' \
		$(RSYNC_SSH) \
		./apps/marketing-zola/ \
		$(SERVER_HOST):/opt/apexmail/apps/marketing-zola/
	@$(RSYNC) --delete \
		--exclude='ssl' \
		$(RSYNC_SSH) \
		./deploy/ \
		$(SERVER_HOST):/opt/apexmail/deploy/
	@for file in $(SYNC_FILES); do \
		$(RSYNC) $(RSYNC_SSH) ./$$file $(SERVER_HOST):/opt/apexmail/$$file; \
	done
	@echo "==> Rebuilding service(s): $(S)"
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh --service $(S)'

## deploy-quick: Rebuild + deploy whatever code is already on the server
deploy-quick:
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh'

## deploy-restart: Just restart containers (no rebuild, no sync)
deploy-restart:
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh --no-build'

## verify: Check that all live endpoints respond correctly
verify:
	@echo "Checking live endpoints..."
	@curl -sI https://apexmail.ee 2>&1 | head -1
	@curl -sI https://app.apexmail.ee 2>&1 | head -1
	@curl -sI https://admin.apexmail.ee 2>&1 | head -1
	@echo "Checking mail TLS..."
	@echo Q | timeout 5 openssl s_client -connect mail.apexmail.ee:993 2>&1 | grep "verify return" | tail -1
	@echo Q | timeout 5 openssl s_client -connect mail.apexmail.ee:587 -starttls smtp 2>&1 | grep "verify return" | tail -1
	@echo "Checking autoconfig..."
	@curl -s http://autoconfig.apexmail.ee/mail/config-v1.1.xml | head -1
	@echo "Done."
