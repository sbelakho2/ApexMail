# =============================================================================
# deploy/hardening/postgres-wal/Dockerfile — the WAL-archiving Postgres image
# =============================================================================
# Audit 6 remediation #11: the wal-archive overlay used to `apk add` rsync +
# openssh-client DURING DATABASE STARTUP — a package-mirror outage degraded
# the database into "archiving fails until tools exist" (postgres boots,
# segments pile up, alerts burn). This image BAKES the tooling into a pinned
# postgres base so the archive path is hermetic: no network, no apk, no
# startup dependency on a mirror.
#
# Exact package revisions pinned for reproducible builds; bump together
# with the base image tag when the alpine repository moves.
# =============================================================================
FROM postgres:16.8-alpine

# hadolint ignore=DL3018 (alpine carries only -r revisions; the major
# version pins below are the repository's exact offerings on 16.8-alpine)
RUN apk add --no-cache \
        openssh-client-default=9.9_p2-r0 \
        rsync=3.5.0-r0 \
    && rm -rf /var/cache/apk/*
