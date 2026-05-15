# Hetzner Production Deploy — Setup Checklist

This document walks through the **one-time** setup needed before the
`Deploy — Hetzner` GitHub Action (`.github/workflows/deploy-hetzner.yml`)
can roll out the ApexMail Docker Compose stack to `37.27.119.181`.

The deploy targets the `Bel-Consulting-OU` GitHub org. Mirror or transfer
the repository there first (or set the secrets at org level so they are
available to whichever repo runs the workflow).

---

## 1. Install the local SSH key on the server

The key in `~/.ssh/hetzner-db-mac.pub` is registered in the Hetzner Robot
key list, but Robot only injects it during `installimage` / rescue. It is
**not** automatically present on a running OS. Install it once:

```sh
# From your Mac (you'll be prompted for the current root password):
ssh-copy-id -i ~/.ssh/hetzner-db-mac.pub root@37.27.119.181

# Verify:
ssh -i ~/.ssh/hetzner-db-mac root@37.27.119.181 'echo OK && uname -a'
```

If you do not have the root password, boot the server into Hetzner Rescue
from Robot and append the contents of `hetzner-db-mac.pub` to
`/mnt/root/.ssh/authorized_keys` after mounting the system disk.

---

## 2. Bootstrap the host

Once SSH works:

```sh
scp -i ~/.ssh/hetzner-db-mac \
  deploy/scripts/hetzner-bootstrap.sh \
  root@37.27.119.181:/root/

ssh -i ~/.ssh/hetzner-db-mac root@37.27.119.181 \
  'bash /root/hetzner-bootstrap.sh'
```

This installs Docker + compose plugin, configures UFW, hardens sshd
(password auth disabled, root key-only), and creates `/opt/apexmail`.

---

## 3. Capture the host's SSH host key

```sh
ssh-keyscan -H 37.27.119.181
```

Copy the full output — you'll paste it into the `HETZNER_KNOWN_HOSTS`
GitHub secret in step 5.

---

## 4. Render the production `.env`

Start from `.env.production.example` and fill in real values
(generate secrets with `openssl rand -base64 32`). The result is what
goes into the `APEXMAIL_PROD_ENV` GitHub secret as a single blob.

Required vars (validated by `docker-compose.prod.yml` with `${VAR:?}`):

- `INTERNAL_SERVICE_TOKEN`, `TRACKING_SECRET_KEY`, `API_KEY_HASH_SECRET`,
  `WEBHOOK_SIGNING_SECRET`, `SESSION_SECRET`, `IMPERSONATION_SECRET`,
  `CSRF_SECRET`, `JWT_SECRET`
- `JWT_PRIVATE_KEY_PEM`, `JWT_PUBLIC_KEY_PEM` (RSA keypair, PEM with `\n`
  as literal newlines inside the value)
- `DATABASE_URL`, `REDIS_URL`, `CLICKHOUSE_URL`
- `API_BASE_URL`, `APP_BASE_URL`, `TRACKING_BASE_URL`,
  `OAUTH_REDIRECT_BASE_URL`, `CORS_ORIGINS`
- `BILLING_COMPANY_IBAN`, `BILLING_COMPANY_PHONE`
- `MCAPTCHA_ENABLED`, `MCAPTCHA_SECRET_KEY` (legacy `MCAPTCHA_SECRET`
  also accepted as fallback)
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_*`
- `GF_SECURITY_ADMIN_PASSWORD`

---

## 5. Configure GitHub secrets

Set these at the **organization** level for `Bel-Consulting-OU` (so they
apply to any repo) or at the repo level if you prefer to scope them:

| Secret name | Value |
|---|---|
| `HETZNER_SSH_PRIVATE_KEY` | `cat ~/.ssh/hetzner-db-mac` (full PEM) |
| `HETZNER_KNOWN_HOSTS`     | output of `ssh-keyscan -H 37.27.119.181` |
| `APEXMAIL_PROD_ENV`       | full rendered `.env` from step 4 |
| `GHCR_DEPLOY_TOKEN`       | PAT with `read:packages` for the GHCR images built by `deploy.yml` |
| `HETZNER_SSH_HOST` (optional) | override host (defaults to `37.27.119.181`) |
| `HETZNER_SSH_USER` (optional) | override user (defaults to `root`) |
| `HETZNER_DEPLOY_DIR` (optional) | override remote dir (defaults to `/opt/apexmail`) |

CLI shortcuts (after `gh auth login` to the Bel-Consulting-OU-tied account):

```sh
gh secret set HETZNER_SSH_PRIVATE_KEY < ~/.ssh/hetzner-db-mac
ssh-keyscan -H 37.27.119.181 | gh secret set HETZNER_KNOWN_HOSTS
gh secret set APEXMAIL_PROD_ENV < /path/to/rendered.env
gh secret set GHCR_DEPLOY_TOKEN  # paste PAT when prompted
```

Add `--org Bel-Consulting-OU --visibility selected --repos ApexMail` to
those calls if managing org-level secrets.

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
1. Validates all required secrets exist
2. Configures SSH with strict host-key checking from `HETZNER_KNOWN_HOSTS`
3. rsyncs `docker-compose*.yml` + `deploy/` to `/opt/apexmail/`
4. Pipes `APEXMAIL_PROD_ENV` to `/opt/apexmail/.env` (mode 0600) without
   touching the runner filesystem
5. Logs in to GHCR on the host, `docker compose pull`, `up -d --remove-orphans`
6. Reports `docker compose ps`
7. Shreds the SSH key from the runner

---

## 7. Rotation

- **SSH key**: regenerate, append to authorized_keys, then update
  `HETZNER_SSH_PRIVATE_KEY` and `HETZNER_KNOWN_HOSTS` if the host key
  changed.
- **Production secrets**: re-render `.env` and update `APEXMAIL_PROD_ENV`;
  next deploy will overwrite the file on the host.
- **GHCR token**: rotate the PAT and update `GHCR_DEPLOY_TOKEN`.
