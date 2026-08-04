# ApexMail — Deployment
# ======================
#
# There is ONE deploy command: `make deploy`
#
# It SSHes to the production server and runs deploy/scripts/deploy.sh,
# which is the single source of truth for deployments.
#
# Usage:
#   make deploy         — push code to git, SSH to server, run deploy.sh --pull
#   make deploy-quick   — SSH to server, run deploy.sh (no git push/pull)
#   make verify         — check live endpoints
#

SERVER_HOST := root@95.216.226.51
SSH         := ssh -o StrictHostKeyChecking=no $(SERVER_HOST)

.PHONY: deploy deploy-quick verify

## deploy: Push code to git, then deploy on the server
deploy:
	git push origin main
	$(SSH) 'cd /opt/apexmail && bash deploy/scripts/deploy.sh --pull'

## deploy-quick: Deploy current code on the server (no git push/pull)
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
