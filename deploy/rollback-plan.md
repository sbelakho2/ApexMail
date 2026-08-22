# Rollback Plan

## Image / tag model (read first)

The pipeline images stage (`ci/stages/images.sh`) tags **only** `:<short-sha>` and
`:latest` image tags to GHCR on each push to `main`. It **never** publishes
`vX.Y.Z` version tags, so rollback is git-SHA based, not tag based. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) § "Tag strategy".

Every image carries a `:<short-sha>` tag, so each git commit maps 1:1 to a set
of deployable images: commit `<sha>` → `ghcr.io/<ns>/<service>:<short-sha>` for
every service in the canonical service→image map.

**What the compose files actually pin.** `docker-compose.prod.yml` references
every service image as **`:latest`** — there is no `IMAGE_TAG` interpolation.
Two consequences that older versions of this document glossed over:

1. Re-running the `Deploy — Hetzner` workflow with a `ref` input of an older
   commit does **not** deploy that commit's images. The `ref` only selects
   which version of the *workflow scripts and compose files* are checked out;
   `docker compose pull` still resolves `:latest`.
2. Pinning a rollback therefore means either retagging on the host (preferred)
   or editing the compose `image:` lines on the host (fallback). Both
   procedures below are the honest, tested-path versions.

## Identify the rollback target

1. Find the last known-good commit on `main` (before the bad deploy):

   ```bash
   git log --oneline -20 origin/main
   # pick the SHA whose images were running fine, e.g. 08b778b6
   ```

2. Derive its short SHA (matches the CI image tag):

   ```bash
   git rev-parse --short <sha>      # e.g. 08b778b6
   ```

   Confirm the images exist: `gh api /users/sbelakho2/packages/container/mta/versions`
   (or check GHCR) for a version tagged `<short-sha>`.

## Rollback method 1 (preferred — retag as :latest on the host)

`docker compose pull` always pulls `:latest`, so make `:latest` BE the
known-good SHA locally, then recreate:

```bash
ssh <hetzner-host>
cd /opt/apexmail
SHA=08b778b6   # the known-good short SHA

# Retag every canonical service image back to the known-good SHA.
# GHCR_LOGIN is the same read:packages PAT the deploy uses.
docker login ghcr.io -u <user> --password-stdin <<<"$GHCR_LOGIN"
for svc in api-server mta imap-server mailstore worker enterprise \
           tracking-service observability marketing status-server \
           billing-service sales-autopilot migrator; do
  docker pull "ghcr.io/sbelakho2/apexmail/${svc}:${SHA}" || { echo "missing ${svc}:${SHA}"; exit 1; }
  docker tag  "ghcr.io/sbelakho2/apexmail/${svc}:${SHA}" \
              "ghcr.io/sbelakho2/apexmail/${svc}:latest"
done

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build
```

To return to normal rolling deployments: the next push to `main` re-publishes
`:latest` in GHCR and the next deploy's `docker compose pull` overwrites the
local retag. (If you deploy again before such a push, pass `skip_pull=true`
to the workflow, or the pull will fetch the bad `:latest` again.)

## Rollback method 2 (fallback — sed the compose pins on the host)

If retagging is not viable, rewrite the `image:` references in place and let
compose pull the pinned tags directly:

```bash
ssh <hetzner-host>
cd /opt/apexmail
SHA=08b778b6

cp docker-compose.prod.yml docker-compose.prod.yml.bak
sed -i.bak -E "s|(ghcr.io/sbelakho2/apexmail/[a-z-]+):latest|\\1:${SHA}|" docker-compose.prod.yml

docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env up -d
```

Restore normal operation by reverting the file (`mv docker-compose.prod.yml.bak
docker-compose.prod.yml`) on the next good push to `main`. NOTE: the next
deploy-hetzner run rsyncs the repo's compose file over the host copy, which
also reverts the pin — a plain re-deploy is usually sufficient.

## Database migrations

Restore the database snapshot **only if** the bad deploy included schema
migrations. Deploys run the `migrator` one-shot job before `up` (see
DEPLOYMENT.md § "Database migrations"); if a migration in the bad deploy is
incompatible with the rolled-back images, restore from the most recent
pre-deploy snapshot (encrypted dumps in the `postgres_backups` volume) before
starting the rolled-back images.

## Rollback Owner

DevOps

## Decision Threshold

Any P0 production issue (site down, broken checkout, incorrect legal info, data
exposure)

## Maximum Response Time

15 minutes from detection to rollback initiation
