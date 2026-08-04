# Rollback Plan

## Image / tag model (read first)

CI (`.github/workflows/deploy.yml`) publishes **only** `:<short-sha>` and
`:latest` image tags to GHCR on each push to `main`. It **never** publishes
`vX.Y.Z` version tags, so rollback is git-SHA based, not tag based. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) § "Tag strategy".

Every image carries a `:<short-sha>` tag, so each git commit maps 1:1 to a set
of deployable images: commit `<sha>` → `ghcr.io/<ns>/<service>:<short-sha>` for
every service in the canonical service→image map.

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

## Rollback method (preferred — re-run CI)

1. Trigger the deploy workflow on the target commit, redeploying that SHA's
   already-built images:

   ```bash
   gh workflow run deploy-hetzner.yml \
     -f ref=<short-sha>
   ```

   `deploy-hetzner.yml` accepts a `ref` input; run it against the known-good
   commit so it pulls `:<short-sha>` images instead of `:latest`.

## Rollback method (manual — pull pinned tags)

If CI is unavailable, SSH to the host and pin the prod compose to the previous
SHA's tags directly:

```bash
ssh <hetzner-host>
cd /opt/apexmail

# Set the image tag for every service to the previous good SHA, e.g. 08b778b6
# (override via .env or sed the image: lines in docker-compose.prod.yml):
#   ghcr.io/sbelakho2/apexmail/api-server:08b778b6
#   ghcr.io/sbelakho2/apexmail/mta:08b778b6
#   ...one per service in DEPLOYMENT.md's service→image map

docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

To return to normal rolling deployments, revert the pin back to `:latest` on the
next good push to `main`.

## Database

Restore the database snapshot **only if** the bad deploy included schema
migrations. If it did, restore from the most recent pre-deploy snapshot before
starting the rolled-back images.

## Rollback Owner

DevOps

## Decision Threshold

Any P0 production issue (site down, broken checkout, incorrect legal info, data
exposure)

## Maximum Response Time

15 minutes from detection to rollback initiation
