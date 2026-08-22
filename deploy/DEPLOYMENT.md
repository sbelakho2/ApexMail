# ApexMail Deployment — Canonical Path

This document defines the **single supported deployment model** for ApexMail.
There is exactly one path; older bare-metal (systemd) and Kubernetes models are
superseded and do not exist in this repository anymore.

## TL;DR

```
push to main
  → .github/workflows/deploy.yml      builds + pushes images to GHCR (:latest + :<sha>)
  → .github/workflows/deploy-hetzner.yml   SSHes to the host, pulls :latest, `docker compose up -d`
```

Local production-parity run:

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env up -d
```

## Canonical service → image map

These are the **only** image names that may appear in a compose file or CI
build step. The namespace (`ghcr.io/<owner>/<repo>`) is derived from
`github.repository` in CI — it is never hardcoded.

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

Notes:

- The MTA image is named **`mta`** (matching the CI build target and the
  compose service key). The binary inside that image is still `mta-server`;
  only the image *name* is unified. There is no `mta-server` image tag.
- `imap-server` and `mailstore` are first-class members of the canonical set:
  they appear in `docker-compose.prod.yml` (ports 993 and gRPC 50051), are
  built by `deploy.yml` from the `imap-server` / `mailstore` Dockerfile
  targets, and are pulled + started by `deploy-hetzner.yml` alongside the
  other services. Do not remove them from any of the three places.
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

## Tag strategy

- CI (`deploy.yml`) publishes **`:<short-sha>`** and **`:latest`** for every
  image on each push to `main`.
- `docker-compose.prod.yml` pins every service to **`:latest`** so
  `docker compose pull` always resolves to a CI-built image.
- Immutable per-commit tracking is preserved via the `:<short-sha>` tags.
- **Never** pin to a `vX.Y.Z` tag unless CI is also taught to produce that tag.
  (Earlier `v1.0.0`/`v1.0.1` pins referred to tags CI never published, which
  broke `docker compose pull`.)

## Required GitHub secrets (no hardcoded defaults)

The deploy workflows fail fast if any of these are absent:

| Secret                    | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `HETZNER_SSH_HOST`        | Production host IP/hostname (**required**, no default)         |
| `HETZNER_SSH_USER`        | SSH user (**required**, no default)                            |
| `HETZNER_SSH_PRIVATE_KEY` | Private key matching the host's `authorized_keys`              |
| `HETZNER_KNOWN_HOSTS`     | Output of `ssh-keyscan -H <HETZNER_SSH_HOST>`                  |
| `APEXMAIL_PROD_ENV`       | Full `.env` contents (see `deploy/scripts/HETZNER_DEPLOY.md`)  |
| `GHCR_DEPLOY_TOKEN`       | PAT with `read:packages` for the host's `docker login ghcr.io` |

## Drift guard

The CI job `deploy-image-name-guard` (in `deploy.yml`) asserts that every
`image:` reference in `docker-compose*.yml` matches the canonical service map
above — including `imap-server`, `mailstore` and `status-server`. If you add
a service or rename an image, update this map **and** the guard together —
the build will fail otherwise.

## Manual fallback (NOT the production path)

The `Makefile` targets and `deploy/scripts/deploy.sh` are a manual/emergency
fallback only. They build images **locally on the host** and tag them with
GHCR-style names — those images are never pushed to GHCR, and the produced
stack can drift from CI. Production is deployed exclusively by the two
workflows above.
