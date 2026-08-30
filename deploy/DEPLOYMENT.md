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

GitHub Actions is decommissioned (archived under `.github/workflows-archive/`;
the replacement map lives in `ci/README.md` §2). The pipeline running on the
deploy host IS the CI and the deployer — there is no runner, no registry, and
no SSH hop anymore.

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
2. **Clone the repository on the host** — `ssh root@<host> 'git clone <repo-url> /opt/apexmail/src'` (or grant the deploy key read access and let the pipeline fetch; the fetch stage refuses to deploy unpushed commits).
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
   pipeline run (`ls /opt/apexmail/secrets | wc -l` — 31 files including
   `redis_password_map.json`, generated per the comment in
   `.env.production.example`).
5. **Install the CI pipeline** — `ssh root@<host> 'cd /opt/apexmail/src && ci/install.sh'` (installs the 5-minute systemd timer, pinned tools, and the fail-closed tool policy).
6. **Run the first deploy** — `ssh root@<host> 'cd /opt/apexmail/src && ci/pipeline.sh run'`. A red stage stops before `docker compose up`; the verify stage probes health, HTTP, and the SMTP banner.
7. **Issue a real certificate** — `ssh root@<host> "cd /opt/apexmail/src && bash deploy/scripts/issue-letsencrypt.sh"`. Later deploys warn if the cert is still self-signed.

## Rendered production secrets (the real 31)

`docker-compose.prod.yml` guards **30 `PROD_*_FILE` variables** (`${VAR:?}`) plus the redis-exporter JSON-map secret (`redis_password_map`).
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

| Compose service key   | Canonical image                              | Built by `deploy.yml` target | Dockerfile binary |
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
| `migrator` *(one-shot)* | `ghcr.io/<ns>/migrator`                    | `migrator`                   | `migrator`        |

Notes:

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
  they pick up the new cert on the next container restart / nginx reload
  (deploys do this automatically).
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

Then wire the deployment to it (in the production `.env`, i.e. the
`APEXMAIL_PROD_ENV` GitHub secret):

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

## Drift guard

The CI job `deploy-image-name-guard` (in `deploy.yml`) asserts that every
`image:` reference in `docker-compose*.yml` matches the canonical service map
above — including `imap-server`, `mailstore`, `status-server` and `migrator`. If you add
a service or rename an image, update this map **and** the guard together —
the build will fail otherwise.

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
- [ ] `https://api.apexmail.ee/sales-api/u/<bogus>` → **404** (a 502/503 means
      sales-autopilot is down behind nginx)
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

