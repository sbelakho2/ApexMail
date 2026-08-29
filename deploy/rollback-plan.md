# Rollback Plan

## Image / tag model (read first)

**Nothing is pulled from a registry.** All images are built **locally on the
deploy host** — by the pipeline (`ci/pipeline.sh` → `ci/stages/images.sh`,
which invokes `deploy/scripts/deploy.sh --build-only`) or by a manual
`deploy/scripts/deploy.sh` run — and tagged with the canonical
`ghcr.io/sbelakho2/apexmail/<service>` *names*. Those tags exist ONLY on the
host; the GHCR-publishing GitHub workflows are gone, so there is no registry
to pull a rollback from and no `gh api .../packages/...` to inspect. Do not
waste incident time hunting for registry tags that do not exist.

The images stage tags every built image with **both** `:<sha>` and `:latest`:

- `:<sha>` — the rollback pins (one set per pipeline run),
- `:latest` — what `docker compose up` resolves.

It also prunes `:<sha>` tags beyond the newest `CI_KEEP_SHAS` (default 5)
per service, so the practical rollback window is the last ~5 deploys.

**What the compose files actually pin.** `docker-compose.prod.yml` references
every service image as **`:latest`** — there is no `IMAGE_TAG` interpolation.
Rolling back therefore means **retagging on the host** (method 1 below) or
sed-pinning the compose file (method 2). Both procedures are the honest,
tested-path versions.

## Identify the rollback target

The pipeline writes the sha of the last fully deployed (but possibly
verify-failed) rollout to `ci/.last-deployed-sha`; `ci/stages/verify.sh`
ALREADY rolls back automatically to that sha when the post-deploy probes
fail. Manual rollback is for when auto-rollback was disabled, incomplete, or
the failure was detected later:

```bash
ssh <deploy-host>
cd /opt/apexmail

cat ci/.last-deployed-sha                 # previous green deploy's sha
docker images 'ghcr.io/sbelakho2/apexmail/*' --format '{{.Repository}}:{{.Tag}}' | sort
# pick a known-good :<sha> that still exists locally (images stage keeps ~5)
```

## Rollback method 1 (preferred — retag as :latest on the host)

Make `:latest` BE the known-good SHA locally, then recreate — no network:

```bash
cd /opt/apexmail
SHA=<known-good-sha>   # must exist: docker images | grep ":${SHA}"

for svc in api-server mta imap-server mailstore worker enterprise \
           tracking-service observability marketing status-server \
           billing-service sales-autopilot migrator; do
  docker image inspect "ghcr.io/sbelakho2/apexmail/${svc}:${SHA}" >/dev/null \
    || { echo "missing ${svc}:${SHA}"; exit 1; }
  docker tag "ghcr.io/sbelakho2/apexmail/${svc}:${SHA}" \
             "ghcr.io/sbelakho2/apexmail/${svc}:latest"
done

docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
    --profile monitoring up -d --remove-orphans
```

The next pipeline run rebuilds `:latest` from the then-current `main`, which
overwrites the local retag. If you deploy again manually before that, a
partial `deploy/scripts/deploy.sh --service ...` run only rebuilds the named
services (and its Step 9 preserves the `:<sha>` pins recorded in
`ci/.last-deployed-sha`).

## Rollback method 2 (fallback — sed the compose pins on the host)

If retagging is not viable, rewrite the `image:` references in place:

```bash
cd /opt/apexmail
SHA=<known-good-sha>

cp docker-compose.prod.yml docker-compose.prod.yml.bak
sed -i.bak -E "s|(ghcr.io/sbelakho2/apexmail/[a-z-]+):latest|\1:${SHA}|" docker-compose.prod.yml

docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
    --profile monitoring up -d --remove-orphans
```

Restore normal operation with `mv docker-compose.prod.yml.bak
docker-compose.prod.yml`. NOTE: the next pipeline deploy re-checks-out the
repo's compose files onto the host, which also reverts the pin — a plain
re-deploy is usually sufficient.

## Database migrations

Restore the database snapshot **only if** the bad deploy included schema
migrations. Deploys run the `migrator` one-shot job before `up` (see
DEPLOYMENT.md § "Database migrations"); if a migration in the bad deploy is
incompatible with the rolled-back images, restore from the most recent
pre-deploy snapshot (encrypted dumps in the `postgres_backups` volume) before
starting the rolled-back images. Migrations themselves are additive by
design and are NOT reverted.

## Rollback Owner

DevOps

## Decision Threshold

Any P0 production issue (site down, broken checkout, incorrect legal info, data
exposure)

## Maximum Response Time

15 minutes from detection to rollback initiation
