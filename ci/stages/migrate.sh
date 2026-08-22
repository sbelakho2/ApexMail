#!/bin/sh
# =============================================================================
# ci/stages/migrate.sh — stage 6: the deployment migration gate.
# =============================================================================
# Replaces the "Run database migrations" steps of deploy-hetzner.yml and
# deploy.sh Step 5: the migrator one-shot compose job applies the embedded
# sqlx chain BEFORE any service is recreated, and `up` only happens when it
# succeeds (enforced by stage order in the pipeline).
#
# Differences from deploy.sh (documented in ci/README.md § deploy decision):
#   * deploy.sh has no migrate-only flag (only --build-only/--no-build), so
#     this stage runs the exact compose invocation itself rather than calling
#     deploy.sh (which would also re-run the migrator during `up`).
#   * Before the run, _sqlx_migrations is dumped to the run dir — the
#     pre-run backup that lets an operator restore the migration ledger
#     precisely if a migration misbehaves (deploy/rollback-plan.md).
#   * After the run, the applied count must never DECREASE.
#
# Skips (exit 75) off-host.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

compose() {
    docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env "$@"
}

psql_exec() {
    compose exec -T postgres psql -U "${POSTGRES_USER:-apexmail}" -d "${POSTGRES_DB:-apexmail}" "$@"
}

applied_count() {
    psql_exec -tAc \
        "SELECT COALESCE((SELECT count(*) FROM _sqlx_migrations), -1)" 2>/dev/null \
        | tr -d '[:space:]'
}

stage_main() {
    if ! ci_on_deploy_host; then
        ci_skip_stage "migrate stage runs only on the deploy host ($CI_DEPLOY_DIR)"
    fi
    cd "$CI_DEPLOY_DIR"

    # --- 1. pre-run backup of the migration ledger ---------------------------------
    _before=$(applied_count)
    ci_info "applied migrations before run: ${_before:-unknown}"
    _backup=$RUN_DIR/sqlx_migrations_backup.sql
    if compose exec -T postgres \
            pg_dump -U "${POSTGRES_USER:-apexmail}" -d "${POSTGRES_DB:-apexmail}" \
            -t _sqlx_migrations --data-only >"$_backup" 2>>"$CI_STAGE_LOG"; then
        ci_info "migration ledger backed up: $_backup ($(wc -c <"$_backup" | tr -d ' ') bytes)"
    else
        ci_warn "could not back up _sqlx_migrations (first boot?) — continuing"
        : >"$_backup"
    fi

    # --- 2. the migrator one-shot (same gate as deploy-hetzner.yml) ----------------
    ci_info "running migrator (compose --profile migrate run --rm migrator)"
    if ! ci_run_logged compose --profile migrate run --rm migrator; then
        ci_err "migrator FAILED — services will NOT be recreated (deploy stage blocked)"
        return "$CI_EXIT_FAIL"
    fi

    # --- 3. post-run assertion --------------------------------------------------------
    _after=$(applied_count)
    ci_info "applied migrations after run: ${_after:-unknown}"
    case "${_before:-x}:${_after:-y}" in
        x:*|*:y)
            ci_warn "could not read the migration ledger (psql unavailable?) — count assertion skipped"
            ;;
        *)
            if [ "$_after" -lt "$_before" ]; then
                ci_err "migration ledger went BACKWARDS ($_before -> $_after); restore from $_backup"
                return "$CI_EXIT_FAIL"
            fi
            ;;
    esac

    ci_info "migrate: ledger at ${_after:-?} migrations, gate passed"
    return "$CI_EXIT_OK"
}

stage_main
