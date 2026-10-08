# ApexMail Deployment — Canonical Path

This document defines the **single supported deployment model** for ApexMail.
There is exactly one path; older bare-metal (systemd) and Kubernetes models are
superseded and do not exist in this repository anymore.

## TL;DR

```
push to main
  → the host's pipeline timer (every 5 min, ci/pipeline.sh) fetches the ref
  → 05 images    builds all images ON the host (:latest + :<short-sha>, Trivy-gated)
  → 06 migrate   _sqlx_migrations backup + migrator one-shot
  → 07 deploy    docker compose up -d + nginx reload
  → 08 verify    per-service health, HTTP probes, SMTP banner, TLS
```

GitHub Actions is decommissioned — the workflow files were removed from the
tree on 2026-09-13 (the replacement map lives in `ci/README.md` §2). A
reappearing `.github/workflows/` or `.github/workflows-archive/` fails the
validate stage. The pipeline running on the deploy host IS the CI and the
deployer — there is no runner, no registry, and no SSH hop anymore.

## Deployment methods (when to use which)

| Method | Command / trigger | Use when | Notes |
|---|---|---|---|
| **Pipeline deploy (canonical)** | push to `main`; the host timer runs `ci/pipeline.sh run` (or force it: `cd /opt/apexmail && ci/pipeline.sh run`) | Every production change | Builds + scans all images, runs the migration gate, verifies the rollout (per-service health + HTTP + SMTP checks). The ONLY supported production path. A red stage stops the line before deploy. |
| **Pipeline stages without rebuild** | `ci/pipeline.sh run --stages migrate,deploy,verify` | Re-apply compose/env changes when images are already on the host | Still runs migrations + verification. |
| **Manual fallback (emergency only)** | `make deploy DEPLOY_HOST=root@<host>` / `make deploy-service S=<svc> DEPLOY_HOST=…` | Hotfix when CI is unavailable | Builds images locally on the host via `deploy/scripts/deploy.sh` (never pushed to GHCR). Includes `billing-service`, `sales-autopilot` and the `migrator`; `GHCR_NS` is overridable (`make deploy … GHCR_NS=ghcr.io/<ns>/apexmail`). Runs the same migration gate. |
| **Local production-parity smoke** | `tools/run-compose-smoke.sh full` | Pre-merge validation of the merged compose stack on a dev machine | Brings up the monitoring slice + a prod subset (api-server, enterprise, tracking, sales-autopilot, billing-service, nginx, postgres, redis, clickhouse) with throwaway secrets; verifies health endpoints, TLS vhosts and the sales 404 route; injects a synthetic alert end-to-end. Needs enough Docker VM RAM for the Rust image builds (~8 GB+). |

`make verify` (from anywhere) checks the live production endpoints, and
`make verify-env ENV_FILE=.env.production` validates an env file against the
compose `${VAR:?}` contract — the same gate the pipeline's deploy stage runs
before bringing up the stack.

## Fresh-host bootstrap (one-time)

The deploy pipeline runs ON the host (systemd timer → `ci/pipeline.sh`).
There is no GitHub Actions runner and no registry; bootstrap is done over
SSH once:

1. **Bootstrap the host** — `scp deploy/scripts/hetzner-bootstrap.sh "root@<host>:/root/"` then `ssh root@<host> 'bash /root/hetzner-bootstrap.sh'` (installs Docker + compose plugin, configures UFW, hardens sshd, creates `/opt/apexmail`).
2. **Clone the repository on the host** — `${DEPLOY_DIR}` (`/opt/apexmail`) IS the repository root: the bootstrap pre-creates the directory (with `secrets/`), so initialize the checkout in place — `ssh root@<host> 'cd /opt/apexmail && git init -q && git remote add origin <repo-url> && git fetch origin main && git checkout -f main'` — and keep `.env`, `secrets/`, `certs/` and `backups/` in that same directory (host-local, gitignored). The fetch must be FULL, not `--depth 1`: the REQUIRED gitleaks gate scans the full history, and a shallow checkout would silently degrade it to the current tree. (The fetch stage also unshallows defensively, and the security stage fails closed if it cannot.) The fetch stage refuses to deploy unpushed commits.
3. **Render the production `.env`** at `/opt/apexmail/.env` from `.env.production.example` (generate values with `openssl rand -base64 32`); validate locally with `make verify-env ENV_FILE=.env.production`.
4. **Write the secret files** — for every `PROD_*_FILE` path in the `.env`
   (30 today; see § "Rendered production secrets"), create the file with the
   corresponding value and `chmod 600` it, e.g.:

   ```bash
   install -m 600 <(printf %s "$POSTGRES_PASSWORD") /opt/apexmail/secrets/postgres_password.txt
   ```

   Nothing in the live pipeline renders these files — the archived
   `deploy-hetzner.yml` workflow used to; missing files fail the compose
   `${VAR:?}` gate at deploy time, so verify all of them exist before the first
   pipeline run (`ls /opt/apexmail/secrets | wc -l` — 32 files including
   `redis_password_map.json` and an empty `ai_model_api_key.txt`, generated per the comment in
   `.env.production.example`).
5. **Install the CI pipeline** — `ssh root@<host> 'cd /opt/apexmail && ci/install.sh'` (installs the 5-minute systemd timer, pinned tools — including the `gh` CLI — and the fail-closed tool policy). Then set the token the fetch stage requires: add `export GITHUB_TOKEN=<PAT with Administration:read>` to `/etc/apexmail/pipeline.conf` (the installer prints an ACTION REQUIRED line and `ci/install.sh check` fails without it; `gh` + a readable token are hard prerequisites of the branch-protection release gate, `ci/README.md` §13).
6. **Run the first deploy** — `ssh root@<host> 'cd /opt/apexmail && ci/pipeline.sh run'`. A red stage stops before `docker compose up`; the verify stage probes health, HTTP, and the SMTP banner.
7. **Issue a real certificate** — `ssh root@<host> "cd /opt/apexmail && bash deploy/scripts/issue-letsencrypt.sh"`. Later deploys warn if the cert is still self-signed.

## Rendered production secrets (the real 32)

`docker-compose.prod.yml` guards **30 `PROD_*_FILE` variables** (`${VAR:?}`) plus the redis-exporter JSON-map secret (`redis_password_map`) and the optional-valued `ai_model_api_key` (empty file is fine while no model provider needs a key).
Each guard must have a matching file under `/opt/apexmail/secrets/` (see
Fresh-host bootstrap step 4 — nothing in the live pipeline renders them).
`tools/validate-prod-env.sh` (available as `make verify-env`) derives this
set from the compose file, so it can never drift. AWS/SMTP pairs are *optional-valued* — the files are still
rendered (empty) so the guards stay satisfied when running the SES transport.

| Secret value var in `.env` | `PROD_*_FILE` var |
|---|---|
| `POSTGRES_PASSWORD` | `PROD_POSTGRES_PASSWORD_FILE` |
| `REDIS_PASSWORD` | `PROD_REDIS_PASSWORD_FILE` |
| `CLICKHOUSE_PASSWORD` | `PROD_CLICKHOUSE_PASSWORD_FILE` |
| `CLICKHOUSE_ADMIN_PASSWORD` | `PROD_CLICKHOUSE_ADMIN_PASSWORD_FILE` |
| `API_KEY_HASH_SECRET` | `PROD_API_KEY_HASH_SECRET_FILE` |
| `WEBHOOK_SIGNING_SECRET` | `PROD_WEBHOOK_SIGNING_SECRET_FILE` |
| `TRACKING_SECRET_KEY` | `PROD_TRACKING_SECRET_KEY_FILE` |
| `INTERNAL_SERVICE_TOKEN` | `PROD_INTERNAL_SERVICE_TOKEN_FILE` |
| `AI_ADMIN_TOKEN` | `PROD_AI_ADMIN_TOKEN_FILE` |
| `JWT_SECRET` | `PROD_JWT_SECRET_FILE` |
| `JWT_PRIVATE_KEY_PEM` | `PROD_JWT_PRIVATE_KEY_FILE` |
| `JWT_PUBLIC_KEY_PEM` | `PROD_JWT_PUBLIC_KEY_FILE` |
| `SESSION_SECRET` | `PROD_SESSION_SECRET_FILE` |
| `IMPERSONATION_SECRET` | `PROD_IMPERSONATION_SECRET_FILE` |
| `CSRF_SECRET` | `PROD_CSRF_SECRET_FILE` |
| `DKIM_PRIVATE_KEY_ENCRYPTION_KEY` | `PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE` |
| `KIWI_SECRET_KEY` | `PROD_KIWI_SECRET_KEY_FILE` |
| `STRIPE_SECRET_KEY` | `PROD_STRIPE_SECRET_KEY_FILE` |
| `STRIPE_WEBHOOK_SECRET` | `PROD_STRIPE_WEBHOOK_SECRET_FILE` |
| `AWS_ACCESS_KEY_ID` *(optional)* | `PROD_AWS_ACCESS_KEY_ID_FILE` |
| `AWS_SECRET_ACCESS_KEY` *(optional)* | `PROD_AWS_SECRET_ACCESS_KEY_FILE` |
| `SMTP_USERNAME` *(optional)* | `PROD_SMTP_USERNAME_FILE` |
| `SMTP_PASSWORD` *(optional)* | `PROD_SMTP_PASSWORD_FILE` |
| `SALES_UNSUBSCRIBE_SECRET` | `PROD_SALES_UNSUBSCRIBE_SECRET_FILE` |
| `BACKUP_ENCRYPTION_KEY` | `PROD_BACKUP_ENCRYPTION_KEY_FILE` |

Non-file variables also validated by the compose overlay (`${VAR:?}`):
`BASE_URL`, `OAUTH_REDIRECT_BASE_URL`, `APEXMAIL_API_KEY`, `JWT_SECRET`,
`PLACEMENT_ENCRYPTION_SECRET`, `SALES_CAMPAIGN_FROM_EMAIL`. Bank details
(`BILLING_COMPANY_IBAN`/`_BIC`/`_PHONE`) are OPTIONAL — invoice renderers
omit the fields when unset; `BILLING_COMPANY_BANK` defaults to Wise.

Per-workload internal credentials (P1 #6, REQUIRED in production — each
service refuses to boot without its dedicated token; the universal
`INTERNAL_SERVICE_TOKEN` is refused once the dedicated one is set):

| Secret value var in `.env` | `PROD_*_FILE` var |
|---|---|
| `TEMPLATE_RENDERER_AUTH_TOKEN` | *(compose bridge not wired yet — plain `.env` value)* |
| `PDF_RENDERER_AUTH_TOKEN` | *(compose bridge not wired yet — plain `.env` value)* |
| `DEVEX_AUTH_TOKEN` | *(compose bridge not wired yet — plain `.env` value)* |
| `AI_EMBEDDINGS_AUTH_TOKEN` | *(compose bridge not wired yet — plain `.env` value)* |


## Database migrations (deploy-time gate)

Schema migrations (`services/mail-server/migrations`, sequential 001-122+)
are applied by the **`migrator`** — a one-shot compose job (profile
`migrate`, `restart: no`) whose image embeds the sqlx migration chain at
build time (`services/mail-server/crates/migrator`). Both deploy paths run it
BEFORE `docker compose up -d`, so the stack never starts against an outdated
schema:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env --profile migrate run --rm migrator
```

- The pipeline's `ci/stages/migrate.sh` runs the same command as its own
  stage (gate before `up`); `deploy.sh` runs the same command in its Step 5.
- The migrator image is built in lockstep with the service images by
  `ci/stages/images.sh`, and the image-name drift guard includes it.
- The job is idempotent — re-running against an up-to-date database is a
  no-op that exits 0.
- Manual fallback for operators with direct DB access:
  `sqlx migrate run --source services/mail-server/migrations` with a
  `DATABASE_URL` (see `services/mail-server/migrations/README.md`).

## Canonical service → image map

These are the **only** image names that may appear in a compose file or CI
build step. The namespace (`ghcr.io/<owner>/<repo>`) is derived from
`github.repository` in CI. The manual fallback (`deploy/scripts/deploy.sh`)
defaults its `GHCR_NS` to `ghcr.io/sbelakho2/apexmail` and accepts an
override (`GHCR_NS=ghcr.io/<ns>/apexmail bash deploy/scripts/deploy.sh`) so a
fork can hotfix-deploy without editing the script.

| Compose service key   | Canonical image                              | Dockerfile target (historical `deploy.yml` names) | Dockerfile binary |
| --------------------- | -------------------------------------------- | ---------------------------- | ----------------- |
| `api-server`          | `ghcr.io/<ns>/api-server`                    | `api-server`                 | `api-server`      |
| `mta`                 | `ghcr.io/<ns>/mta`                           | `mta`                        | `mta-server`      |
| `imap-server`         | `ghcr.io/<ns>/imap-server`                   | `imap-server`                | `imap-server`     |
| `mailstore`           | `ghcr.io/<ns>/mailstore`                     | `mailstore`                  | `mailstore`       |
| `worker`              | `ghcr.io/<ns>/worker`                        | `worker`                     | `worker`          |
| `enterprise`          | `ghcr.io/<ns>/enterprise`                    | `enterprise`                 | `enterprise`      |
| `tracking-service`    | `ghcr.io/<ns>/tracking-service`              | (deploy/Dockerfile.tracking) | `tracking-service`|
| `observability`       | `ghcr.io/<ns>/observability`                 | `observability`              | `observability`   |
| `marketing`           | `ghcr.io/<ns>/marketing`                     | (apps/marketing-zola)        | nginx static      |
| `status-server`       | `ghcr.io/<ns>/status-server`                 | `auth-server`                | `auth-server`     |
| `billing-service`     | `ghcr.io/<ns>/billing-service`               | `billing-service`            | `billing-service` |
| `sales-autopilot`     | `ghcr.io/<ns>/sales-autopilot`               | `sales-autopilot`            | `sales-autopilot` |
| `compliance`          | `ghcr.io/<ns>/compliance`                    | `compliance`                 | `compliance`      |
| `analytics-worker`    | `ghcr.io/<ns>/analytics-worker`              | `analytics-worker`           | `analytics-worker`|
| `pdf-renderer`        | `ghcr.io/<ns>/pdf-renderer`                  | `pdf-renderer`               | `pdf-renderer`    |
| `ai-service`          | `ghcr.io/<ns>/ai-service`                    | `ai-service`                 | `ai-service`      |
| `postgres-backup`     | `ghcr.io/<ns>/postgres-backup`               | (deploy/hardening/Dockerfile.postgres-backup) | shell scheduler |
| `clickhouse-backup`   | `ghcr.io/<ns>/clickhouse-backup`             | (deploy/hardening/Dockerfile.clickhouse-backup) | shell scheduler |
| `redis-backup`        | `ghcr.io/<ns>/redis-backup`                  | (deploy/hardening/Dockerfile.redis-backup) | shell scheduler |
| `analytics-backup`    | `ghcr.io/<ns>/analytics-backup`              | (deploy/hardening/Dockerfile.analytics-backup) | shell scheduler |
| `migrator` *(one-shot)* | `ghcr.io/<ns>/migrator`                    | `migrator`                   | `migrator`        |

Notes:

- The four backup schedulers are default-profile services; the deploy stage's
  canonical `up` list and the verify stage's probe list both include them
  (`ci/stages/validate.sh` mechanically fails the run if a `*-backup` service
  in `docker-compose.prod.yml` is missing from either list — the redis and
  analytics schedulers were once built+scanned but never started).

- The MTA image is named **`mta`** (matching the CI build target and the
  compose service key). The binary inside that image is still `mta-server`;
  only the image *name* is unified. There is no `mta-server` image tag.
- `imap-server` and `mailstore` are first-class members of the canonical set:
  they appear in `docker-compose.prod.yml` (ports 993 and gRPC 50051) and are
  built from the `imap-server` / `mailstore` Dockerfile targets by the
  pipeline's images stage. Do not remove them from either place.
- `status-server` (the public status page + status API behind
  `status.apexmail.ee` and `apexmail.ee/api/status-data`) is built from the
  Dockerfile's **`auth-server`** stage — the image is published as
  `status-server`, matching its compose service key and the nginx upstream
  name. The stage is not renamed to avoid touching the `auth-server` crate
  references; only the image name is canonical.
- `billing-service` binds `0.0.0.0:4100` (no host port mapping — it is
  service-auth protected and only reachable on the internal Docker networks).
  Its production Stripe credentials come from the Docker secrets
  `stripe_secret_key` / `stripe_webhook_secret` (`PROD_STRIPE_SECRET_KEY_FILE`
  / `PROD_STRIPE_WEBHOOK_SECRET_FILE` in the deployment `.env`); the webhook
  secret is mandatory — the binary fail-fasts at startup without it.
- `sales-autopilot` (internal sales engine: CRM, campaigns, inbox, scheduler)
  binds port `3010` with no host port mapping — the control plane reaches it
  server-side over `apexmail_backend` (`sales-autopilot:3010`). Its only
  public surface is the CAN-SPAM unsubscribe endpoint routed by nginx at
  `https://api.apexmail.ee/sales-api/u/`.
- The dev `docker-compose.yml` builds the `mta` service from the **`mta`**
  target (same stage as production). There is no separate dev edge listener;
  the legacy `smtp-edge` crate/stage was removed.

## Legacy / removed crates

The following crates were **removed** from the workspace — they were legacy
duplicates that production never used and have no residual references:

- **`submission`** (binary `submission-server`) — duplicate SMTP-submission
  implementation. Production SMTP submission (ports 25/465/587) is served
  exclusively by `mta`.
- **`smtp-edge`** — dev-only edge listener superseded by `mta`; its Dockerfile
  stage and dev-compose target were removed.
- **`ops-service`** — had no compose consumer and existed only as drift; its
  test-only consumers (fuzz/load/perf/smoke/integration tests) were removed
  with it.
- **`bounce-analytics`** — unreferenced; its functionality lives in
  `worker-processors`/`mta`.

> `auth-server` (`services/mail-server/crates/auth-server`) is **deployed**
> — as the `status-server` service/image (see the canonical map above). It is
> not a standalone image name; the crate's binary serves the status page/API.

## TLS certificate management (production)

- All TLS consumers (nginx, mta, imap-server) read from the **single
  certbot-managed tree** `${TLS_CERT_DIR:-./deploy/nginx/ssl}` (host:
  `/opt/apexmail/deploy/nginx/ssl`). The `certbot` service renews it every
  12 h (`deploy/scripts/certbot-renew-loop.sh`); the deploy hook installs
  `fullchain.pem`/`privkey.pem`/`ca-chain.pem` at the tree root chowned to
  uid 101 (nginx) and reopens `live/` + `archive/` to 0755 with 0644 pem
  files so the mta/imap containers (non-root uid 10001) can read them.
- `nginx`, `mta` and `imap-server` load certs at startup; after a renewal
  nginx picks up the new cert on the next reload, while `mta` / `imap-server`
  need a container restart. That restart is **automated**: the renewal loop
  drops `renewal-restart-flag` into the cert tree, and a host-side systemd
  path-unit watcher installed by `deploy.sh`
  (`deploy/hardening/apexmail-tls-renew-restart.path` →
  `deploy/hardening/tls-renew-restart.sh`) runs
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml restart
  mta imap-server` exactly once per renewal (mtime guard; opt out with
  `APEXMAIL_TLS_AUTO_RESTART=0`). When the watcher is absent — non-root
  manual deploy — the certbot container logs the manual restart command.
  Deploys also recreate the containers, covering renewals between deploys
  only via the watcher.
- The host `/etc/letsencrypt` tree is **legacy** — it is no longer mounted
  by any compose service and nothing renews it. Do not use it for new
  TLS wiring.
- **`status.apexmail.ee`** — first-class service (`status-server` in
  `docker-compose.prod.yml`, proxied by nginx). Its A record resolves to the
  production host and the Let's Encrypt certificate covers it — the cert
  currently contains all 13 domains (apexmail.ee, www, api, app, admin,
  control, enterprise, track, mail, smtp, imap, autoconfig, status).
  After a renewal, the certbot deploy-hook copies `live/apexmail.ee/*` to the
  tree root (`fullchain.pem`/`privkey.pem`/`ca-chain.pem`); if you ever issue
  an expanded cert manually, run `deploy/scripts/issue-letsencrypt.sh` again
  (it re-copies and reloads nginx) or re-run the deploy-hook.

## SES configuration set + SNS event destinations (one-time AWS setup)

**Why this is manual.** The codebase *consumes* SES event notifications but
never *provisions* them. `api-server` exposes the public, signature-validated
endpoint `POST https://api.apexmail.ee/v1/ses/notifications`
(`api-server/src/routes/ses_notifications.rs`, nested at `/v1/ses` in
`app.rs`) and handles **Bounce / Complaint / Delivery / Open / Click** events:
message status flips to `delivered`/`complained`/`bounced`, hard bounces and
complaints are auto-suppressed into the `suppressions` table, open/click
counters increment, `events` analytics rows are written, and tenant webhooks
(`email.delivered`, `email.opened`, …) are queued. Both `api-server` (SES
identity creation, `routes/domains.rs`) and the worker (per-send,
`worker-processors/src/email/transport.rs`) attach the configuration set
named by `SES_CONFIGURATION_SET` — but **nothing in the repo creates the
configuration set or its event destinations.** That is an AWS-side, one-time
provisioning step:

```bash
export AWS_REGION=eu-west-1          # MUST match AWS_REGION in the deployment .env
export CONFIG_SET=apexmail-events    # will become SES_CONFIGURATION_SET
export TOPIC_NAME=apexmail-ses-events

# 1. Configuration set (an AlreadyExists error here means it is already set up).
aws sesv2 create-configuration-set \
  --configuration-set-name "$CONFIG_SET" --region "$AWS_REGION"

# 2. SNS topic the api-server handlers consume (skip if it already exists —
#    check `aws sns list-topics` first).
TOPIC_ARN=$(aws sns create-topic --name "$TOPIC_NAME" \
  --region "$AWS_REGION" --query 'TopicArn' --output text)
echo "$TOPIC_ARN"

# 3. HTTPS subscription to the notification endpoint. The api-server handler
#    auto-confirms the SubscriptionConfirmation by fetching the SubscribeURL
#    (SSRF-guarded to amazonaws.com) — no manual confirmation click needed.
aws sns subscribe \
  --topic-arn "$TOPIC_ARN" \
  --protocol https \
  --notification-endpoint https://api.apexmail.ee/v1/ses/notifications \
  --region "$AWS_REGION"

# 4. Event destination: publish the event types the handler processes.
#    Bounce/Complaint power suppression; Delivery/Open/Click power status,
#    engagement counters, analytics, and tenant webhooks.
aws sesv2 put-configuration-set-event-destinations \
  --configuration-set-name "$CONFIG_SET" \
  --region "$AWS_REGION" \
  --event-destinations '[{
        "Enabled": true,
        "MatchingEventTypes": ["BOUNCE", "COMPLAINT", "DELIVERY", "OPEN", "CLICK"],
        "SnsDestination": { "TopicArn": "'"$TOPIC_ARN"'" }
      }]'

# 5. Verify the destination is attached and enabled.
aws sesv2 get-configuration-set-event-destinations \
  --configuration-set-name "$CONFIG_SET" --region "$AWS_REGION"
```

Then wire the deployment to it (in the production `.env` at
`/opt/apexmail/.env` — the `APEXMAIL_PROD_ENV` GitHub secret that used to
supply it is retired with the GitHub workflows):

```
SES_CONFIGURATION_SET=apexmail-events
SNS_ALLOWED_TOPIC_ARNS=<the TOPIC_ARN from step 2>
```

- `SES_CONFIGURATION_SET` is already plumbed into both the `api-server` and
  `worker` service env blocks of `docker-compose.prod.yml`, so setting the
  `.env` value is sufficient.
- `SNS_ALLOWED_TOPIC_ARNS` is read directly from the process environment by
  the notification handler (comma-separated allow-list; **every notification
  is rejected with 503 while it is unset**). The `api-server` service env
  block must pass it through:
  `SNS_ALLOWED_TOPIC_ARNS: ${SNS_ALLOWED_TOPIC_ARNS:-}`.

### Exercising the path in development (no AWS)

The dev compose defaults `SNS_ALLOWED_TOPIC_ARNS` to the local ARN
`arn:aws:sns:eu-central-1:000000000000:apexmail-dev-ses-events` (override it
in `.env`), so the handler no longer answers 503 unconditionally. A
developer can then exercise the FULL signed path without AWS:

1. `openssl genrsa -out sns-dev-key.pem 2048`
2. Put the public key into `.env` as a single line with `\n` escapes:
   `SNS_DEV_SIGNING_KEY_PEM=$(openssl rsa -in sns-dev-key.pem -pubout | awk '{printf "%s\\n", $0}')`
3. Build the SNS string-to-sign (Message/MessageId/Timestamp/TopicArn/Type),
   sign it with `sns-dev-key.pem` (SHA-256 for `SignatureVersion: 2`) and
   POST the JSON envelope to `/v1/ses/notifications` with the dev `TopicArn`.

`SNS_DEV_SIGNING_KEY_PEM` is **ignored in production** (logged as an error;
the AWS-only `SigningCertURL` allowlist + fetch stay authoritative). The
topic allow-list and the timestamp-freshness gate apply in dev too.

**Genuinely unreachable in dev (with proof):** an *authoritative* ARF/FBL
complaint cannot be produced locally — the FBL registry validates the
source by PTR/FCrDNS against a registered provider and rejects loopback
(`complaint_events` records `non-authoritative source 127.0.0.1; claimed
message_id=` for a local injector). Exercising that arm requires a
registered FBL mailbox provider with reverse DNS, which no local stack can
fabricate; the self-hosted VERP bounce path covers the authoritative
suppression behavior instead (mail-plane dogfood Flow 5C).

**What breaks without it.** With no configuration-set event destination
pointing at the topic (or with `SES_CONFIGURATION_SET` left empty — the
compose default), SES publishes nothing and the
`/v1/ses/notifications` handler never fires:

- `messages.status` never transitions to `delivered` (or `bounced` /
  `complained`), and `delivered_at` / open/click timestamps never populate;
- hard bounces and complaints are **never auto-suppressed** — complained and
  hard-bounced addresses keep receiving mail (deliverability and legal
  exposure);
- `events` rows for `delivered` / `complained` / `opened` / `clicked` are
  never written, so admin analytics engagement buckets and complaint-rate
  metrics silently read zero for SES traffic;
- tenant webhooks for `email.delivered` / `email.opened` / `email.clicked` /
  `email.bounced` / `email.complained` never fire.

Verification after setup: send one message through the platform, then check
`SELECT status, delivered_at FROM messages ORDER BY created_at DESC LIMIT 1;`
(flips to `delivered`), and the SNS topic's *NumberOfMessagesPublished*
CloudWatch metric.

## Enterprise SSO (SAML/OIDC) endpoints + keys

The enterprise service (`enterprise.apexmail.ee`, compose service
`enterprise`) serves the tenant SSO flows. The browser-facing routes are
live and rate-limited by the nginx vhost like every other path:

| Route | Purpose |
|-------|---------|
| `GET /sso/login/saml/{domain}` | Start a SAML login (AuthnRequest redirect) |
| `POST /sso/acs/{domain}` | SAML Assertion Consumer Service (session issued); `POST /sso/acs` resolves the domain from RelayState |
| `GET /sso/login/oidc/{domain}` | Start an OIDC login (state + PKCE redirect) |
| `GET /sso/callback/oidc/{domain}` | OIDC callback: code exchange + id_token validation (session issued); `GET /sso/callback/oidc` takes the domain from the state |

IdP material is per-tenant (configured through `POST /sso/configure` — see
`docs/enterprise/sso.md`); the deployment only supplies the SP-side and
crypto settings:

- `SSO_ENCRYPTION_KEY` — **required before any tenant configures an OIDC
  client secret**: `configure` encrypts the secret at rest with it and fails
  closed when it is empty (`openssl rand -base64 36`). Set it for the
  `enterprise` compose service the same way `LOG_STREAM_ENCRYPTION_KEY` is.
- `SAML_ENTITY_ID` — the ApexMail SP entity ID handed to tenant IdPs
  (default `urn:apexmail:enterprise`).
- `SAML_ACS_URL` — the ACS endpoint embedded in AuthnRequests and enforced
  as the assertion audience. Leave the default (`{BASE_URL}/api/sso/saml/callback`,
  a mounted route) or point it at `https://enterprise.apexmail.ee/sso/acs`;
  both resolve the tenant domain (path segment or RelayState).
- `OIDC_REDIRECT_URI` — the redirect URI tenants register with their IdP.
  The default (`{BASE_URL}/api/sso/oidc/callback`) is a mounted route;
  `https://enterprise.apexmail.ee/sso/callback/oidc` also works. The same
  value is used in the authorize redirect and the token exchange, and the
  tenant domain travels in the single-use `state`.
- `OIDC_SCOPES` — requested scopes (default `openid profile email`).

Verification after setup: configure a tenant IdP
(`POST /sso/configure`), open
`https://enterprise.apexmail.ee/sso/login/saml/{domain}`, and confirm the
IdP round-trip issues a session (`GET /sso/validate` with the returned
token). Invalid assertions (unsigned, tampered, expired, replayed) are
refused with 401 and logged with the failing check.

## Image identity (no registry)

There is no registry: the pipeline builds images on the host and tags them
with `ghcr.io/...` NAMES for compatibility, but nothing is pushed or pulled.

- `ci/stages/images.sh` records a SHA256 **digest manifest** for every built
  image; `ci/stages/deploy.sh` refuses to bring up the stack if any image's
  live digest differs from the manifest (tamper/drift guard between build
  and `up`).
- Rollback pins use the recorded digests, not mutable tags — see
  `deploy/rollback-plan.md` (`:<short-sha>`-style tag pins do NOT exist;
  `docker compose pull` cannot work in this model and must not be used).
- **Never** pin services to external `vX.Y.Z` tags.

## Immutable deployment artifacts (digest-pinned compose overrides)

External audit item 5: `docker-compose.prod.yml` references mutable
`:latest` tags, so a manual `docker compose up` resolves whatever the tag
currently points at — not necessarily the content the pipeline built, gated
and deployed. The pipeline therefore renders two release artifacts per run
(both in `ci/runs/<ts>/`, signed together in `SHA256SUMS.images`):

1. **`release-manifest.json`** — the release evidence:

   ```json
   [
     {
       "service": "api-server",
       "image_repository": "ghcr.io/sbelakho2/apexmail/api-server",
       "git_sha": "<40-hex commit sha>",
       "oci_digest": "sha256:<64-hex image digest>",
       "sbom_digest": "sha256:<64-hex digest of the Trivy SPDX SBOM> | null",
       "provenance_digest": null
     }
   ]
   ```

   One entry per canonical + extra image. `oci_digest` is the OCI repo
   digest the daemon recorded (`RepoDigests`; present with the containerd
   image store and after any registry push) or, when none exists, the image
   ID — the exact content the deploy stage's tamper guard re-verifies.
   `sbom_digest` points at the Trivy SPDX SBOM the images stage generated
   for that image (null only when SBOM generation itself failed or trivy was
   unavailable — the backup sidecars outside the blocking gate get SBOMs from
   the advisory scan pass). Nothing in this pipeline produces provenance
   attestations, so `provenance_digest` is always null.

2. **`docker-compose.digest-override.yml`** — a GENERATED compose override
   mapping every first-party service to pinned content, `repo@sha256:<digest>`
   where a repo digest exists locally, else the full `:<git-sha>` rollback
   tag (a daemon without local repo digests cannot resolve a digest ref for a
   locally built image; the tag plus the deploy-stage digest verification are
   the tamper evidence there). Do not edit it; do not commit it.

**Manual compose invocations MUST append the override** — base + prod alone
still resolve `:latest`:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f <run-dir>/docker-compose.digest-override.yml \
  --env-file .env --profile monitoring up -d
```

Enforcement:

- The canonical deploy stage (`ci/stages/deploy.sh`) applies the override to
  every `compose` call and runs `tools/check_image_pinning.py` over the LIVE
  `docker compose config` rendering before `up`: every first-party image must
  be digest- or full-git-sha-pinned, third-party images must be on the
  checker's explicit allowlist. A violation fails the deploy before any
  container is recreated.
- The validate stage proves the checker itself on committed fixtures
  (`tools/fixtures/compose_pinning/`) — a `:latest` first-party image must be
  REJECTED without needing docker.
- The manual path (`deploy/scripts/deploy.sh`) renders the same pair into
  `ci/runs/<UTC-ts>_manual/` right after its builds and appends the override
  to its own compose invocations.
- Known gap (deliberate): `ha`, `isolation` and `outbound-mta` are first-party
  services in `docker-compose.prod.yml` that the pipeline does NOT build and
  the deploy stage's canonical service set does NOT bring up — they are not in
  the manifest/override and stay on `:latest`. Do not add them to a manual
  `up` without pinning their images first. The `migrate` stage likewise runs
  the migrator before the deploy stage's override exists; pinning it is
  follow-up work for `ci/stages/migrate.sh`.

## Drift guard

`ci/stages/validate.sh` (`image_name_guard`, the current port of the retired
`deploy.yml` `deploy-image-name-guard` job) asserts that every `image:`
reference in `docker-compose*.yml` matches the canonical service map above —
including `imap-server`, `mailstore`, `status-server` and `migrator` — and
that no `:vX.Y.Z` style tag sneaks in. If you add a service or rename an
image, update this map **and** the guard together — the validate stage fails
otherwise.

## Manual fallback (NOT the production path)

The `Makefile` targets and `deploy/scripts/deploy.sh` are a manual/emergency
fallback only. They build images **locally on the host** and tag them with
GHCR-style names — those images are never pushed to GHCR, and the produced
stack can drift from CI. Production is deployed exclusively by the two
workflows above. The fallback covers the full canonical set
(`api-server mta imap-server mailstore worker enterprise observability
status-server billing-service sales-autopilot migrator`), honours a
`GHCR_NS` env override, and runs the same migration gate before `up -d`.

## Rollback

See [`rollback-plan.md`](rollback-plan.md) for the full procedure. In short:

1. Identify the last known-good commit and its `<short-sha>` image tags.
2. On the host, either **retag** the known-good SHA images as `:latest`
   (preferred — compose pins `:latest`) or **sed** the `image:` lines in
   `docker-compose.prod.yml` to the pinned SHA, then `docker compose up -d`.
3. Restore the database snapshot only if the bad deploy included migrations
   that are incompatible with the rolled-back images.

Note: re-running the Hetzner workflow with an older `ref` deploys that
commit's *scripts*, not its images — compose always resolves `:latest`.

## Verification checklist

After every deploy (the Hetzner workflow does all of this automatically in
its "Verify rollout" step):

- [ ] Every canonical service reports `running`/`healthy` via
      `docker compose ps` (per-service assertion, incl. billing-service,
      sales-autopilot and postgres-backup).
- [ ] `https://api.apexmail.ee/health` → 200
- [ ] `https://track.apexmail.ee/health` → 200
- [ ] `https://status.apexmail.ee/status` → 200
- [ ] `https://enterprise.apexmail.ee/health` → 200
- [ ] `https://api.apexmail.ee/sales-api/u/<bogus>` → the app's **400**
      `{"error":"invalid or expired unsubscribe token"}` (any 502/503 means
      sales-autopilot is down behind nginx; a 400 proves the request reached
      and was handled by the service)
- [ ] SMTP banner answers on port 25 (and TLS on 465; bounce/FBL ports
      2525/2526 reachable).
- [ ] TLS certificate is Let's Encrypt (workflow warns while self-signed).

From a workstation, `make verify` runs the endpoint/port checks against the
live host and `deploy/scripts/verify-deployment.sh` re-checks cache coherence
of the legal pages; `tools/run-compose-smoke.sh full` is the pre-merge
compose-stack equivalent.

## Alerting / notification receivers

The monitoring stack (prometheus + alertmanager, deployed with the
`monitoring` compose profile) evaluates the rules in
`deploy/alerting-rules.yml` and routes every firing alert through
`deploy/alertmanager.yml.tmpl` (rendered at container start by
`deploy/scripts/render-alertmanager-config.sh`). **Operators MUST set at
least ONE external receiver env var** — the template's only always-on
destination is the *internal* `http://observability:4400/alerts` webhook,
which is useless precisely when the platform itself is failing.

Receiver env vars (any **one** of these is sufficient):

| Receiver | Env var(s) | Notes |
|---|---|---|
| PagerDuty | `PAGERDUTY_ROUTING_KEY` | Critical route |
| OpsGenie | `OPSGENIE_API_KEY` | Critical route (P1) |
| Slack | `SLACK_WEBHOOK_PATH` and `SLACK_WEBHOOK_PATH_LOW` | Path after `https://hooks.slack.com/services/` (high/low channels) |
| Email | `SMTP_HOST` (a real relay — **not** the dead `127.0.0.1` compose default) + `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_EMAIL_CRITICAL`, `ALERT_EMAIL_WARNING` | Warning + critical routes |

If none of them is configured, the render script does not fail the deploy,
but it stamps a `NO EXTERNAL ALERT DELIVERY CHANNEL IS CONFIGURED` banner
into the rendered alertmanager config *and* the container logs — search the
alertmanager logs for it after every bootstrap. You can pre-flight the
wiring anywhere the template is mounted with:

```sh
docker compose exec alertmanager \
    sh /usr/local/bin/render-alertmanager-config.sh --check
```

