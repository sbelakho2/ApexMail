# ApexMail — Unified deployment targets
# ======================================
# Prerequisites:
#   SSH config at ~/.ssh/config with a `Host apexmail` block
#   Zola installed (brew install zola) for marketing builds
#   Rust toolchain for auth-server builds

SERVER_HOST := apexmail
SSH         := ssh $(SERVER_HOST)
RSYNC       := rsync -avz
RSYNC_DEST  := $(SERVER_HOST):
DEPLOY      := $(SSH) /opt/apexmail/scripts/deploy.sh
ZOLA_DIR    := apps/marketing-zola
PUBLIC      := $(ZOLA_DIR)/public
NEXT_DIR    := /var/www/.apexmail.ee.next

.PHONY: help deploy-marketing deploy-auth deploy-nginx deploy-mta deploy-all \
        build-marketing push-marketing push-auth push-nginx push-configs \
        rollback-marketing verify deploy-clean test-all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# ── Full deploy targets ──

deploy-marketing: build-marketing push-marketing ## Build + deploy marketing site
	$(DEPLOY) marketing

deploy-auth: push-auth ## Push + rebuild + restart auth-server on server
	$(SSH) 'cd /opt/apexmail/auth-server && cargo build --release 2>&1 | tail -5 && cp target/release/auth-server /opt/apexmail/auth-server/target/release/auth-server'
	$(DEPLOY) auth-server

deploy-nginx: push-nginx ## Deploy nginx config
	$(DEPLOY) nginx

deploy-mta: push-auth ## Deploy MTA (rebuilds from source)
	$(SSH) 'cd /opt/apexmail/services/mail-server && cargo build --release 2>&1 | tail -5'
	$(DEPLOY) mta

deploy-all: deploy-auth deploy-marketing deploy-nginx deploy-mta ## Full deployment in dependency order

# ── Build + push helpers ──

build-marketing: ## Build Zola marketing site locally
	cd $(ZOLA_DIR) && zola build
	@echo "Built $(PUBLIC) ($$(find $(PUBLIC) -type f | wc -l) files)"

push-marketing: ## Rsync built marketing files to server staging directory
	$(SSH) 'mkdir -p $(NEXT_DIR)'
	$(RSYNC) --delete $(PUBLIC)/ $(RSYNC_DEST)$(NEXT_DIR)/
	@echo "Staged $$(find $(PUBLIC) -type f | wc -l) files at $(SERVER_HOST):$(NEXT_DIR)"

push-auth: ## Rsync auth-server source to server
	$(RSYNC) --delete --exclude='target' --exclude='.git' services/mail-server/ $(RSYNC_DEST)/opt/apexmail/services/mail-server/
	$(RSYNC) --delete deploy/scripts/ $(RSYNC_DEST)/opt/apexmail/scripts/
	$(RSYNC) deploy/nginx/apexmail.conf $(RSYNC_DEST)/opt/apexmail/nginx/apexmail.conf
	$(RSYNC) deploy/systemd/auth-server.service $(RSYNC_DEST)/opt/apexmail/systemd/auth-server.service

push-nginx: ## Rsync nginx config to server
	$(RSYNC) deploy/nginx/apexmail.conf $(RSYNC_DEST)/opt/apexmail/nginx/apexmail.conf

push-configs: ## Push all configs and scripts
	$(RSYNC) --delete deploy/scripts/ $(RSYNC_DEST)/opt/apexmail/scripts/
	$(RSYNC) deploy/nginx/apexmail.conf $(RSYNC_DEST)/opt/apexmail/nginx/apexmail.conf
	$(RSYNC) deploy/systemd/ $(RSYNC_DEST)/opt/apexmail/systemd/

# ── Rollback ──

rollback-marketing: ## Rollback marketing site to previous snapshot
	$(DEPLOY) rollback-marketing

# ── Verification ──

verify: ## Run post-deploy verification against live site
	@echo "=== Marketing site ==="
	@curl -sk -o /dev/null -w "Homepage:       %{http_code}\n" https://apexmail.ee
	@curl -sk -o /dev/null -w "German:         %{http_code}\n" https://apexmail.ee/de/
	@curl -sk -o /dev/null -w "French:         %{http_code}\n" https://apexmail.ee/fr/
	@curl -sk -o /dev/null -w "Spanish:        %{http_code}\n" https://apexmail.ee/es/
	@echo "=== Applications ==="
	@curl -sk -o /dev/null -w "App console:    %{http_code}\n" https://app.apexmail.ee/
	@curl -sk -o /dev/null -w "Admin console:  %{http_code}\n" https://admin.apexmail.ee/
	@echo "=== Status API ==="
	@curl -sk https://apexmail.ee/api/status-data 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "FAILED"
	@echo "=== Registry Check ==="
	@if curl -sk https://apexmail.ee 2>/dev/null | grep -q '16942833\|16192499'; then \
		echo "FAIL: OLD REGISTRY CODES DETECTED"; exit 1; \
	else \
		echo "OK: No stale registry codes"; \
	fi
	@echo "=== Template Leak Check ==="
	@if curl -sk https://apexmail.ee 2>/dev/null | grep -q '{% if\|{{ .\|i18n_data\|translation_missing'; then \
		echo "FAIL: RAW TEMPLATE SYNTAX DETECTED"; exit 1; \
	else \
		echo "OK: No template leaks"; \
	fi
	@echo "=== All checks passed ==="

# ── Utility ──

deploy-clean: ## Remove staging directories on server
	$(SSH) 'rm -rf $(NEXT_DIR) /var/www/.apexmail.ee.prev'

test-all: verify ## Run all verification checks

# ── Bare-metal api-server deploy (fast: ~5 min, no Docker build) ──

deploy-api-src: ## Rsync api-server source to server
	$(RSYNC) --delete --exclude=target packages/kiwicaptcha/ $(RSYNC_DEST)/opt/apexmail/packages/kiwicaptcha/
	$(RSYNC) --delete --exclude=target services/mail-server/crates/api-server/ $(RSYNC_DEST)/opt/apexmail/services/mail-server/crates/api-server/
	$(RSYNC) --delete --exclude=target services/mail-server/crates/ui-foundation/ $(RSYNC_DEST)/opt/apexmail/services/mail-server/crates/ui-foundation/
	$(RSYNC) services/mail-server/Cargo.toml $(RSYNC_DEST)/opt/apexmail/services/mail-server/Cargo.toml
	$(RSYNC) docs/development/ui-baseline-manifest.json $(RSYNC_DEST)/opt/apexmail/docs/development/ui-baseline-manifest.json

deploy-api-build: deploy-api-src ## Build api-server on server (incremental, ~3-7 min)
	$(SSH) 'export PATH="/root/.cargo/bin:$$PATH" && cd /opt/apexmail/services/mail-server && cargo build --release --bin api-server 2>&1 | tail -3'

deploy-api-restart: ## Restart api-server via systemd (5s downtime)
	$(SSH) 'systemctl restart api-server && sleep 3 && systemctl is-active api-server'

deploy-api-health: ## Health check API server
	@curl -sk -o /dev/null -w "app.apexmail.ee: %{http_code}\n" https://app.apexmail.ee/login/
	@curl -sk -o /dev/null -w "admin.apexmail.ee: %{http_code}\n" https://admin.apexmail.ee/
	@curl -sk -X POST -o /dev/null -w "kcaptcha challenge: %{http_code}\n" https://app.apexmail.ee/api/kcaptcha/challenge -H "Content-Type: application/json" -d '{"scope":"login"}'

deploy-api: deploy-api-build deploy-api-restart deploy-api-health ## Full API server deploy (~5 min)

deploy-nginx-config: ## Deploy nginx config to server
	$(RSYNC) deploy/nginx/nginx.conf $(RSYNC_DEST)/opt/apexmail/deploy/nginx/nginx.conf
	$(SSH) 'docker restart apexmail-nginx-1'
	@echo "Nginx config deployed and reloaded"
