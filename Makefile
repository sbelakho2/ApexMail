# ApexMail — Deployment
# ======================
#
# There is ONE deploy command: `make deploy`
#
# Procedure (the proper channel — no GitHub Actions, no manual docker run):
#   1. `make deploy` rsyncs the repo to the server over SSH
#   2. SSHes in and runs deploy/scripts/deploy.sh
#   3. deploy.sh builds all Rust binaries + Docker images locally on the server
#   4. docker compose up -d recreates all services from the new images
#
# Usage:
#   make deploy         — rsync code, then build + deploy on the server
#   make deploy-quick   — run deploy.sh without rsync (use what's on the server)
#   make verify         — check live endpoints from your machine
#

SERVER_HOST := root@95.216.226.51
SSH         := ssh -o StrictHostKeyChecking=no $(SERVER_HOST)
RSYNC       := rsync -avz --delete

# Exclude directories that shouldn't be synced to the server
RSYNC_EXCLUDES := \
	--exclude='target' \
	--exclude='node_modules' \
	--exclude='.git' \
	--exclude='.tmp' \
	--exclude='.kilo' \
	--exclude='reports' \
	--exclude='.env'

.PHONY: deploy deploy-quick verify

## deploy: Rsync code to server, then build + deploy
deploy:
	@echo "==> Syncing code to server..."
	$(RSYNC) $(RSYNC_EXCLUDES) ./ $(SERVER_HOST):/opt/apexmail/
	@echo "==> Running deploy script on server..."
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh'

## deploy-quick: Run deploy.sh on the server without rsync
deploy-quick:
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh'

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
