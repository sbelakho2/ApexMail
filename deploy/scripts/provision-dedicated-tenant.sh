#!/bin/sh
# Provision a Dedicated Tenant (external audit 15 Oct, WP E3).
#
# Validates the tenant's deployment record against the plan, renders the
# deterministic release-pinned bundle, writes it, and prints the bundle
# sha256 + path. Thin wrapper: all logic lives in
# `enterprise/src/bin/dedicated_tenant.rs`.
#
# Usage:
#   deploy/scripts/provision-dedicated-tenant.sh \
#     --deployment-id <uuid> --release-sha <sha> [--output-dir DIR] [--use-container]
#
#   --use-container  exec the CLI inside the running `enterprise` compose
#                    service (the production path; DATABASE_URL comes from the
#                    container). Default: run a local `dedicated-tenant`
#                    binary (DEDICATED_TENANT_BIN overrides) with DATABASE_URL
#                    from the environment.
set -eu

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

deployment_id=""
release_sha=""
output_dir="${DEDICATED_TENANT_OUTPUT_DIR:-/opt/apexmail/dedicated-tenants}"
use_container=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --deployment-id) deployment_id=${2:-}; shift 2 ;;
        --release-sha) release_sha=${2:-}; shift 2 ;;
        --output-dir) output_dir=${2:-}; shift 2 ;;
        --use-container) use_container=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$deployment_id" ] || { echo "--deployment-id is required" >&2; usage; }
[ -n "$release_sha" ] || { echo "--release-sha is required" >&2; usage; }

run() {
    if [ "$use_container" = 1 ]; then
        docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T \
            enterprise dedicated-tenant "$@"
    else
        "$bin" "$@"
    fi
}

bin=""
if [ "$use_container" = 0 ]; then
    if [ -n "${DEDICATED_TENANT_BIN:-}" ]; then
        bin=$DEDICATED_TENANT_BIN
    elif command -v dedicated-tenant >/dev/null 2>&1; then
        bin=$(command -v dedicated-tenant)
    else
        echo "dedicated-tenant binary not found; set DEDICATED_TENANT_BIN or use --use-container" >&2
        exit 1
    fi
    [ -n "${DATABASE_URL:-}" ] || { echo "DATABASE_URL is required" >&2; exit 1; }
fi

run validate --deployment-id "$deployment_id" --release-sha "$release_sha"
run bundle --deployment-id "$deployment_id" --release-sha "$release_sha" \
    --write --output-dir "$output_dir"

echo "dedicated-tenant $deployment_id provisioned: bundle under $output_dir (release $release_sha)"
