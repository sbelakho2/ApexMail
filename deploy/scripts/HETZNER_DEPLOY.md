# Hetzner Production Deploy — Setup Checklist

This document walks through the **one-time** setup needed before the
`Deploy — Hetzner` GitHub Action (`.github/workflows/deploy-hetzner.yml`)
can roll out the ApexMail Docker Compose stack to the production host.

> **Canonical reference:** this is the operator-facing companion to
> [`../DEPLOYMENT.md`](../DEPLOYMENT.md), which defines the single supported
> deploy model (Docker Compose + GHCR via Hetzner SSH). The bare-metal
> `deploy.sh` and Kubernetes paths under `deploy/legacy-*` are superseded.

The deploy target host and user are provided **entirely** by the
`HETZNER_SSH_HOST` and `HETZNER_SSH_USER` GitHub secrets — there are no
hardcoded IP defaults. Substitute your host below wherever `$HETZNER_HOST`
appears.

---

## 1. Install the local SSH key on the server

Register your public key once on the host (you'll be prompted for the current
root/deploy password):

```sh
HETZNER_HOST=your.host.ip.or.name
ssh-copy-id -i ~/.ssh/hetzner-deploy.pub "${HETZNER_SSH_USER:-root}@${HETZNER_HOST}"

# Verify:
ssh -i ~/.ssh/hetzner-deploy "${HETZNER_SSH_USER:-root}@${HETZNER_HOST}" 'echo OK && uname -a'
```

If you do not have the password, boot the server into Hetzner Rescue from
Robot and append the contents of your public key to
`/mnt/root/.ssh/authorized_keys` after mounting the system disk.

---

## 2. Bootstrap the host

Once SSH works:

```sh
HETZNER_HOST=your.host.ip.or.name
scp -i ~/.ssh/hetzner-deploy \
  deploy/scripts/hetzner-bootstrap.sh \
  "${HETZNER_SSH_USER:-root}@${HETZNER_HOST}:/root/"

ssh -i ~/.ssh/hetzner-deploy "${HETZNER_SSH_USER:-root}@${HETZNER_HOST}" \
  'bash /root/hetzner-bootstrap.sh'
```

This installs Docker + compose plugin, configures UFW, hardens sshd
(password auth disabled, root key-only), and creates `/opt/apexmail`.

---

## 3. Capture the host's SSH host key

```sh
ssh-keyscan -H "${HETZNER_HOST}"
```

Copy the full output — you'll paste it into the `HETZNER_KNOWN_HOSTS`
GitHub secret in step 5.

---

## 4. Render the production `.env`

Start from `.env.production.example` and fill in real values
(generate secrets with `openssl rand -base64 32`). The result is what
goes into the `APEXMAIL_PROD_ENV` GitHub secret as a single blob.

`docker-compose.prod.yml` requires **14 `PROD_*_FILE` variables** (`${VAR:?}`)
that point at the rendered secret files; each must have its value defined
as a plain variable in the `.env`:

| Secret value var in `.env`      | `PROD_*_FILE` var pointing to the rendered file |
| ------------------------------- | ----------------------------------------------- |
| `POSTGRES_PASSWORD`             | `PROD_POSTGRES_PASSWORD_FILE`                   |
| `REDIS_PASSWORD`                | `PROD_REDIS_PASSWORD_FILE`                      |
| `CLICKHOUSE_PASSWORD`           | `PROD_CLICKHOUSE_PASSWORD_FILE`                 |
| `API_KEY_HASH_SECRET`           | `PROD_API_KEY_HASH_SECRET_FILE`                 |
| `WEBHOOK_SIGNING_SECRET`        | `PROD_WEBHOOK_SIGNING_SECRET_FILE`              |
| `TRACKING_SECRET_KEY`           | `PROD_TRACKING_SECRET_KEY_FILE`                 |
| `INTERNAL_SERVICE_TOKEN`        | `PROD_INTERNAL_SERVICE_TOKEN_FILE`              |
| `JWT_SECRET`                    | `PROD_JWT_SECRET_FILE`                          |
| `JWT_PRIVATE_KEY_PEM`           | `PROD_JWT_PRIVATE_KEY_FILE`                     |
| `JWT_PUBLIC_KEY_PEM`            | `PROD_JWT_PUBLIC_KEY_FILE`                      |
| `SESSION_SECRET`                | `PROD_SESSION_SECRET_FILE`                      |
| `IMPERSONATION_SECRET`          | `PROD_IMPERSONATION_SECRET_FILE`                |
| `CSRF_SECRET`                   | `PROD_CSRF_SECRET_FILE`                         |
| `KIWI_SECRET_KEY`               | `PROD_KIWI_SECRET_KEY_FILE`                     |

The workflow renders **all 14** secret files on the host from these values
(see `deploy-hetzner.yml` — "Render docker secret files"), writing each to
the exact path its `PROD_*_FILE` var points at. The `JWT_*_PEM` values must
be quoted PEM blocks (literal newlines inside the quoted value; the workflow
writes them to files verbatim).

Non-file variables also validated by the compose overlay:

- `DATABASE_URL`, `REDIS_URL`, `CLICKHOUSE_URL`
- `BASE_URL`, `OAUTH_REDIRECT_BASE_URL`
- `BILLING_COMPANY_IBAN`, `BILLING_COMPANY_PHONE`
- `GF_SECURITY_ADMIN_PASSWORD` (grafana, when the monitoring profile is up)

---

## 5. Configure GitHub secrets

Set these at the **repository** level (or org level if you manage several
repos under one org). The namespace GHCR publishes to is derived from
`github.repository`, so the secrets must be visible to the repo that runs
the workflow — do not assume a specific org.

| Secret name | Value |
|---|---|
| `HETZNER_SSH_HOST` (**required**) | production host IP/hostname |
| `HETZNER_SSH_USER` (**required**) | SSH user (e.g. `root` or `deploy`) |
| `HETZNER_SSH_PRIVATE_KEY` | `cat ~/.ssh/hetzner-deploy` (full PEM) |
| `HETZNER_KNOWN_HOSTS`     | output of `ssh-keyscan -H <host>` |
| `APEXMAIL_PROD_ENV`       | full rendered `.env` from step 4 |
| `GHCR_DEPLOY_TOKEN`       | PAT with `read:packages` for the GHCR images built by `deploy.yml` |
| `HETZNER_DEPLOY_DIR` (optional) | override remote dir (defaults to `/opt/apexmail`) |

CLI shortcuts (after `gh auth login`):

```sh
gh secret set HETZNER_SSH_HOST       --body "your.host.ip.or.name"
gh secret set HETZNER_SSH_USER       --body "root"
gh secret set HETZNER_SSH_PRIVATE_KEY < ~/.ssh/hetzner-deploy
ssh-keyscan -H your.host.ip.or.name | gh secret set HETZNER_KNOWN_HOSTS
gh secret set APEXMAIL_PROD_ENV < /path/to/rendered.env
gh secret set GHCR_DEPLOY_TOKEN  # paste PAT when prompted
```

---

## 6. Trigger the deploy

Once `deploy.yml` (image build) has pushed images to GHCR for the target
commit, the `Deploy — Hetzner` workflow auto-runs after success. To run
it manually:

```sh
gh workflow run "Deploy — Hetzner" --ref main
gh run watch
```

The workflow:
1. Validates all required secrets exist (fails fast if host/user/key absent)
2. Configures SSH with strict host-key checking from `HETZNER_KNOWN_HOSTS`
3. rsyncs `docker-compose*.yml` + `deploy/` to `/opt/apexmail/` (the Let's
   Encrypt store under `deploy/nginx/ssl/` is protected from `--delete`)
4. Pipes `APEXMAIL_PROD_ENV` to `/opt/apexmail/.env` (mode 0600) without
   touching the runner filesystem
5. Renders **all 14 secret files** required by the compose (`PROD_*_FILE`,
   incl. `api_key_hash_secret`, `webhook_signing_secret`, `tracking_secret_key`,
   `internal_service_token`, `jwt_secret`, `jwt_private_key`, `jwt_public_key`,
   `session_secret`, `impersonation_secret`, `csrf_secret`, `kiwi_secret_key`)
   into `secrets/` on the host
6. Logs in to GHCR on the host, `docker compose pull`, `up -d --remove-orphans`
   over the canonical service set (`api-server mta imap-server mailstore worker
   enterprise tracking observability marketing status-server postgres-backup
   nginx postgres redis clickhouse certbot`)
7. Reloads nginx to re-resolve upstream container IPs
8. Verifies the rollout and the TLS certificate (warns if self-signed)
9. Shreds the SSH key from the runner

---

## 7. Issue a real Let's Encrypt certificate

After the first deploy, nginx will start with a self-signed fallback cert.
Replace it with a real LE cert:

```sh
ssh -i ~/.ssh/hetzner-deploy "${HETZNER_SSH_USER:-root}@${HETZNER_HOST}" \
  "cd /opt/apexmail && bash deploy/scripts/issue-letsencrypt.sh"
```

The `deploy-hetzner.yml` workflow verifies the cert on every subsequent
deploy and warns if it is still self-signed.

---

## 8. Rotation

- **SSH key**: regenerate, append to authorized_keys, then update
  `HETZNER_SSH_PRIVATE_KEY` and `HETZNER_KNOWN_HOSTS` if the host key
  changed.
- **Production secrets**: re-render `.env` and update `APEXMAIL_PROD_ENV`;
  next deploy will overwrite the file on the host.
- **GHCR token**: rotate the PAT and update `GHCR_DEPLOY_TOKEN`.
