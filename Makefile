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
#   make verify-env ENV_FILE=.env.production
#                                       — validate an env file against the
#                                          compose ${VAR:?} contract (same
#                                          gate deploy-hetzner.yml runs)
#
# Server-local state NEVER touched by these targets:
#   .env, secrets/, certs/ (not in SYNC_DIRS), target/ (Docker build cache),
#   and deploy/nginx/ssl/ (the Let's Encrypt store — excluded from the rsync
#   of deploy/ with --exclude='ssl'; deleting it would kill live TLS certs).
#
# USAGE (audit C — no hardcoded host):
#   make deploy DEPLOY_HOST=root@203.0.113.10          — full manual deploy
#   make deploy-service S=api-server DEPLOY_HOST=root@203.0.113.10
#   DEPLOY_HOST is REQUIRED and has NO default: passing it explicitly every
#   time prevents an emergency hotfix from silently going to a stale IP.
#   (The canonical CI/CD path takes the host from the HETZNER_SSH_HOST
#   secret — see deploy/DEPLOYMENT.md.)
#
# SSH options: `accept-new` records the host key on first connection and
# then ENFORCES it (TOFU). The previous `StrictHostKeyChecking=no` accepted
# ANY key on every connection, which defeats MITM protection entirely.

DEPLOY_HOST ?=
SERVER_HOST := $(DEPLOY_HOST)
# Recipe-time guard (a parse-time $(error) would break non-deploy targets
# like `make verify` or `make marketing-check-kiwi`).
define require_deploy_host
	if [ -z "$(SERVER_HOST)" ]; then \
		echo "ERROR: DEPLOY_HOST is required, e.g. make $@ DEPLOY_HOST=root@203.0.113.10 (no default on purpose)" >&2; \
		exit 1; \
	fi
endef
SSH         := ssh -o StrictHostKeyChecking=accept-new $(SERVER_HOST)
RSYNC       := rsync -avz
RSYNC_SSH   := -e "ssh -o StrictHostKeyChecking=accept-new"

# Code directories that get synced. Each rsync uses --delete so the server
# has EXACTLY the current repo state — no stale files, no old binaries.
# NOTE: docs/ is synced because services/mail-server/Dockerfile COPYs it into
# the builder stages (COPY docs /app/docs).
SYNC_DIRS := services/mail-server packages/kiwicaptcha packages/kiwicaptcha-wasm apps/marketing-zola docs deploy
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

.PHONY: deploy deploy-service deploy-quick deploy-restart verify verify-env marketing-check-kiwi

## deploy: Full deploy — sync all code + rebuild all images + restart
deploy:
	@$(require_deploy_host)
	@# Hard pre-flight: KiwiCaptcha must never ship in the marketing build
	@# (audit §6). Fails fast before any sync.
	@bash tools/check-kiwi-marketing-isolation.sh
	@echo "==> Syncing ALL code to server (clean — stale files removed)..."
	@# NOTE: do NOT --exclude 'public' — apps/marketing-zola/public is a
	@# COMMITTED build input (the api-server Docker stage COPYs it); the only
	@# other sync excludes are build outputs (target/, node_modules/, vendor/),
	@# the live LE cert store (deploy/nginx/ssl) and SECRET MATERIAL
	@# (secrets/ — server-side secrets are rendered by CI, never synced).
	@for dir in $(SYNC_DIRS); do \
		echo "  $$dir/"; \
		$(RSYNC) --delete \
			--exclude='target' --exclude='node_modules' --exclude='vendor' \
			--exclude='ssl' --exclude='secrets' \
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
	@$(require_deploy_host)
	@if [ -z "$(S)" ]; then echo "Usage: make deploy-service S=api-server"; exit 1; fi
	@# Hard pre-flight: KiwiCaptcha must never ship in the marketing build.
	@# Runs for every partial deploy (cheap) and explicitly for marketing.
	@bash tools/check-kiwi-marketing-isolation.sh
	@echo "==> Partial deploy: $(S)"
	@echo "==> Syncing only changed code directories..."
	@# Audit C: --exclude='secrets' matches the deploy/ rsync below — local
	@# secret files (services/mail-server/secrets/) must never be copied to
	@# the server; CI renders them there from the secret store.
	@$(RSYNC) --delete \
		--exclude='target' --exclude='node_modules' --exclude='vendor' \
		--exclude='secrets' \
		$(RSYNC_SSH) \
		./services/mail-server/ \
		$(SERVER_HOST):/opt/apexmail/services/mail-server/
	@$(RSYNC) --delete $(RSYNC_SSH) \
		./packages/kiwicaptcha/ \
		$(SERVER_HOST):/opt/apexmail/packages/kiwicaptcha/
	@# apps/marketing-zola/public must sync — it is committed source the
	@# api-server and marketing Docker builds COPY (no 'public' exclude).
	@$(RSYNC) --delete \
		--exclude='target' --exclude='node_modules' --exclude='vendor' \
		$(RSYNC_SSH) \
		./apps/marketing-zola/ \
		$(SERVER_HOST):/opt/apexmail/apps/marketing-zola/
	@$(RSYNC) --delete \
		--exclude='ssl' --exclude='secrets' \
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
	@$(require_deploy_host)
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh'

## deploy-restart: Just restart containers (no rebuild, no sync)
deploy-restart:
	@$(require_deploy_host)
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh --no-build'

## verify: Check that all live endpoints respond correctly
##
## Covers the canonical production surfaces: the api/track/status/enterprise
## health endpoints, the sales-autopilot unsubscribe route (404 on a bogus
## token — anything else, notably 502, means the service is down behind
## nginx), SMTP TLS on 465 and the bounce/FBL ports 2525/2526, plus the
## cache-coherence spot check from deploy/scripts/verify-deployment.sh.
verify:
	@echo "Checking site + admin..."
	@curl -sI https://apexmail.ee 2>&1 | head -1
	@curl -sI https://app.apexmail.ee 2>&1 | head -1
	@curl -sI https://admin.apexmail.ee 2>&1 | head -1
	@echo "Checking service health endpoints..."
	@curl -s -o /dev/null -w 'api      /health -> %{http_code}\n' https://api.apexmail.ee/health
	@curl -s -o /dev/null -w 'track    /health -> %{http_code}\n' https://track.apexmail.ee/health
	@curl -s -o /dev/null -w 'status   /status  -> %{http_code}\n' https://status.apexmail.ee/status
	@curl -s -o /dev/null -w 'enterprise /health -> %{http_code}\n' https://enterprise.apexmail.ee/health
	@echo "Checking sales-api unsubscribe route (expect 404, NOT 502)..."
	@code=$$(curl -s -o /dev/null -w '%{http_code}' https://api.apexmail.ee/sales-api/u/verify-probe); \
		if [ "$$code" = "404" ]; then \
			echo "sales-api /u/ -> 404 OK (sales-autopilot answering behind nginx)"; \
		else \
			echo "sales-api /u/ -> $$code (expected 404; 502/503 = sales-autopilot DOWN)"; \
		fi
	@echo "Checking mail TLS..."
	@echo Q | timeout 5 openssl s_client -connect mail.apexmail.ee:993 2>&1 | grep "verify return" | tail -1
	@echo Q | timeout 5 openssl s_client -connect mail.apexmail.ee:587 -starttls smtp 2>&1 | grep "verify return" | tail -1
	@echo Q | timeout 5 openssl s_client -connect mail.apexmail.ee:465 2>&1 | grep "verify return" | tail -1
	@echo "Checking SMTP ports 2525/2526 (bounce + FBL)..."
	@for port in 2525 2526; do \
		nc -z -w3 mail.apexmail.ee $$port 2>/dev/null && echo "  :$$port OPEN" || echo "  :$$port CLOSED"; \
	done
	@echo "Checking autoconfig..."
	@curl -s http://autoconfig.apexmail.ee/mail/config-v1.1.xml | head -1
	@echo "Running cache-coherence check (deploy/scripts/verify-deployment.sh)..."
	@bash deploy/scripts/verify-deployment.sh https://apexmail.ee || echo "verify-deployment: see output above"
	@echo "Done."

## verify-env: Validate an environment file against the compose contract
##
## Derives the required variable set straight out of docker-compose*.yml
## (${:?} guards) and fails when any value is missing or still a documented
## placeholder — the same check deploy-hetzner.yml runs as an early gate
## against APEXMAIL_PROD_ENV. Default file: .env.production.
verify-env:
	@if [ -z "$(ENV_FILE)" ]; then \
		if [ -f .env.production ]; then ENV_FILE=.env.production; \
		elif [ -f .env ]; then echo "note: falling back to .env (set ENV_FILE to override)"; ENV_FILE=.env; \
		else echo "Usage: make verify-env ENV_FILE=.env.production"; exit 1; fi; \
	fi; \
	bash tools/validate-prod-env.sh "$$ENV_FILE"

## marketing-check-kiwi: Verify no KiwiCaptcha references in marketing source
##
## Enforces the brand-product separation: KiwiCaptcha (the proof-of-work
## CAPTCHA package) must never appear in the ApexMail marketing site. Run
## automatically as a pre-flight on `make deploy` / `make deploy-service`,
## but also exposed standalone for CI and local checks.
## See: marketing_audit.md v2 §6.
marketing-check-kiwi:
	@bash tools/check-kiwi-marketing-isolation.sh
