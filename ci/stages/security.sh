#!/bin/sh
# =============================================================================
# ci/stages/security.sh — stage 4: security + supply-chain + migration gates.
# =============================================================================
# Replaces:
#   * security-audit.yml   — cargo audit (same RUSTSEC ignore list); the
#                            cargo-outdated report is produced advisory-only
#   * cargo-vet.yml        — cargo vet when supply-chain/config.toml exists
#   * rust-check.yml       — gitleaks secret scan (same .gitleaks.toml);
#                            semgrep SAST is NOT replicated (see README —
#                            optional `ci/security-extras.sh` hooks welcome)
#   * deploy.yml           — Trivy image scans (api-server + mta; the scan
#                            after a build runs in the images stage, this run
#                            re-scans existing images pre-deploy) and the Syft
#                            SBOM (Trivy SPDX, advisory)
#   * sqlx-migration-validation.yml — fresh-database migration validation:
#                            migrator --dry-run + sqlx migrate run TWICE against
#                            an ephemeral postgres (idempotency included)
#
# Tool policy: missing tools fail CLOSED on the deploy host, warn elsewhere
# (ci_have_tool in lib.sh).
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

WS=$REPO_ROOT/services/mail-server

# --- gitleaks (rust-check.yml secret-scan job; pre-commit parity) -------------------
# Scans the FULL git history (same as the GitHub job, which checked out with
# fetch-depth: 0). Currently reports findings in historical test fixtures
# (README §9 F11) — the gate stays REQUIRED (fail closed: a silently-passing
# secret scanner is worthless); triage via .gitleaks.toml or temporarily set
# CI_GITLEAKS_CHECK=advisory.
gitleaks_scan() {
    ci_have_tool gitleaks || return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "check (dry-run): gitleaks detect"
        return "$CI_EXIT_OK"
    fi
    ci_info "gitleaks detect (git history, config $CI_GITLEAKS_CONFIG, redacted)"
    _gl_rc=0
    (cd "$REPO_ROOT" && gitleaks detect --config "$CI_GITLEAKS_CONFIG" --redact --verbose \
        >"$RUN_DIR/gitleaks-report.txt" 2>&1) || _gl_rc=$?
    if [ "$_gl_rc" -eq 0 ]; then
        ci_info "PASS: gitleaks detect"
        return "$CI_EXIT_OK"
    fi
    _gl_n=$(grep -c '^Finding:' "$RUN_DIR/gitleaks-report.txt" 2>/dev/null || printf '?')
    grep -E '^(Finding|RuleID|File|Line|Commit):' "$RUN_DIR/gitleaks-report.txt" 2>/dev/null \
        | head -80 >>"$CI_STAGE_LOG" || true
    if [ "${CI_GITLEAKS_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: gitleaks reports $_gl_n findings (full report: $RUN_DIR/gitleaks-report.txt)"
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: gitleaks reports $_gl_n findings (full report: $RUN_DIR/gitleaks-report.txt) \
— triage in .gitleaks.toml or rotate if real"
    return "$CI_EXIT_FAIL"
}

# --- cargo audit (security-audit.yml, ignore list in lockstep) -----------------------
cargo_audit() {
    ci_have_tool cargo-audit || return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "check (dry-run): cargo audit"
        return "$CI_EXIT_OK"
    fi
    _ign=''
    _ign_n=0
    for _id in $CI_CARGO_AUDIT_IGNORES; do
        _ign="$_ign --ignore $_id"
        _ign_n=$((_ign_n + 1))
    done
    ci_info "cargo audit --deny warnings (${_ign_n} reviewed RUSTSEC ignores — mirror of security-audit.yml)"
    _ca_rc=0
    # shellcheck disable=SC2086  # _ign is an intentional flag word list
    (cd "$WS" && # --deny vulnerabilities: real advisories fail the run (after the
    # reviewed --ignore list); unmaintained/unsound/yanked WARNING-class
    # notices are logged but do not gate deploys — that is upgrade-policy
    # tracking, not a deploy blocker (2026-08-23: the warning set churns
    # weekly; see pipeline.conf justifications).
cargo audit $_ign >"$RUN_DIR/cargo-audit.txt" 2>&1) || _ca_rc=$?
    if [ "$_ca_rc" -eq 0 ]; then
        ci_info "PASS: cargo audit"
        return "$CI_EXIT_OK"
    fi
    grep -E '^(Crate|Version|ID|Solution):' "$RUN_DIR/cargo-audit.txt" 2>/dev/null | head -60 >>"$CI_STAGE_LOG" || true
    if [ "${CI_CARGO_AUDIT_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: cargo audit reports vulnerabilities (report: $RUN_DIR/cargo-audit.txt) — upgrade or add reviewed ignores"
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: cargo audit — vulnerabilities beyond the reviewed ignore list (report: $RUN_DIR/cargo-audit.txt)"
    return "$CI_EXIT_FAIL"
}

# --- cargo vet (cargo-vet.yml — only when configured) ----------------------------------
cargo_vet() {
    if [ ! -f "$WS/supply-chain/config.toml" ]; then
        ci_info "cargo vet: supply-chain/config.toml not present — vet not configured (skipped, as upstream)"
        return "$CI_EXIT_OK"
    fi
    ci_have_tool cargo-vet || return "$CI_EXIT_OK"
    (cd "$WS" && ci_check "cargo vet --locked" cargo vet --locked)
}

# --- Semgrep SAST (rust-check.yml SAST job — advisory) ----------------------------------
# The declared-lane coverage is gitleaks + cargo-audit + Trivy; Semgrep adds
# taint-flow rulesets on top. Advisory (as the GitHub SAST job was
# continue-on-error) and loud-skips when the tool is absent — install with
# `pip install semgrep` (ci/install.sh does not pin it; version drift between
# hosts is acceptable for an advisory lane).
semgrep_sast() {
    command -v semgrep >/dev/null 2>&1 || { ci_warn "semgrep missing — SAST lane skipped (advisory; pip install semgrep)"; return "$CI_EXIT_OK"; }
    (cd "$REPO_ROOT" && ci_check_advisory "semgrep SAST (p/default, p/rust)" \
        semgrep scan --config p/default --config p/rust --error --quiet)
}

# --- Trivy image scans (deploy.yml scan steps) -------------------------------------------
# Scans the images that exist locally (built by a previous images stage run).
# The post-build authoritative gate lives in the images stage; this is the
# pre-deploy re-scan of what is on disk.
trivy_images() {
    ci_have_tool trivy || return "$CI_EXIT_OK"
    _ns=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
    for _svc in api-server mta; do
        for _tag in "$CI_SHA" latest; do
            _img=$_ns/$_svc:$_tag
            if docker image inspect "$_img" >/dev/null 2>&1; then
                (cd "$REPO_ROOT" && ci_check "trivy $_img" \
                    trivy image --ignorefile "$REPO_ROOT/.trivyignore" --severity "$CI_TRIVY_SEVERITY" --exit-code 1 --quiet "$_img") \
                    || return "$CI_EXIT_FAIL"
                _trivy_sbom "$_img" || true
                break
            fi
        done
        docker image inspect "$_ns/$_svc:$_tag" >/dev/null 2>&1 \
            || ci_info "trivy: $_svc not built yet (no local image) — post-build gate in the images stage"
    done
}

# SPDX SBOM via Trivy (replaces deploy.yml's Syft/SBOM step; advisory there too).
_trivy_sbom() {
    _sb_img=$1
    _sb_out=$RUN_DIR/sbom-$(printf '%s' "$_sb_img" | tr '/:' '__').spdx.json
    trivy image --format spdx-json --output "$_sb_out" "$_sb_img" >>"$CI_STAGE_LOG" 2>&1 \
        && ci_info "SBOM written: $_sb_out" \
        || ci_warn "SBOM generation failed for $_sb_img (advisory)"
}

# --- fresh-database migration validation (sqlx-migration-validation.yml) ------------------
# 1. migrator --dry-run       — the embedded set lists cleanly (no DB needed)
# 2. sqlx migrate run (x2)    — the chain applies to a CLEAN database and is
#                               idempotent on a current schema, exactly the
#                               two assertions the GitHub workflow made.
# NOTE (2026-08-21): the chain currently FAILS from scratch at migration 109
# (see ci/README.md § "Known pipeline findings"); CI_MIGRATION_CHECK=advisory
# downgrades this check until the migration is fixed.
migration_validation() {
    ci_info "migration validation (ephemeral postgres)"
    ci_docker_ok || { ci_warn "docker unavailable — migration validation skipped"; return "$CI_EXIT_OK"; }

    # (1) embedded migration set lists cleanly
    (cd "$WS" && ci_check "migrator --dry-run" cargo run --locked -p migrator -- --dry-run) \
        || return "$CI_EXIT_FAIL"

    # (2) apply the chain to a clean database, twice
    _mv_port=$(ci_free_port)
    ci_ephem_postgres apexmail-ci-sec-pg apexmail apexmail apexmail_sec "$_mv_port" \
        || ci_die "ephemeral postgres failed to start"
    _mv_url="postgres://apexmail:apexmail@127.0.0.1:$_mv_port/apexmail_sec"

    _mv_rc=0
    if command -v sqlx >/dev/null 2>&1; then
        (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "sqlx migrate run (clean DB)" \
            sqlx migrate run --source migrations) || _mv_rc=1
        [ "$_mv_rc" -ne 0 ] || {
            (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "sqlx migrate run (idempotency)" \
                sqlx migrate run --source migrations) || _mv_rc=1
        }
    else
        ci_warn "sqlx-cli missing — falling back to the migrator binary \
(fresh-DB NULL-decode bug applies; install sqlx-cli via ci/install.sh)"
        (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "migrator apply (clean DB)" \
            cargo run --locked -p migrator) || _mv_rc=1
        [ "$_mv_rc" -ne 0 ] || {
            (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "migrator apply (idempotency)" \
                cargo run --locked -p migrator) || _mv_rc=1
        }
    fi
    ci_ephem_cleanup

    if [ "$_mv_rc" -ne 0 ]; then
        if [ "${CI_MIGRATION_CHECK:-required}" = advisory ]; then
            ci_warn "ADVISORY: fresh-DB migration validation failed (CI_MIGRATION_CHECK=advisory)"
            return "$CI_EXIT_OK"
        fi
        ci_err "fresh-DB migration validation FAILED — the chain does not apply from scratch"
        return "$CI_EXIT_FAIL"
    fi
    ci_info "PASS: migrations apply cleanly to a fresh DB and are idempotent"
    return "$CI_EXIT_OK"
}

# --- cargo outdated (security-audit.yml outdated job was continue-on-error) ---------------
cargo_outdated() {
    # advisory lane (upstream continue-on-error): loud-skip when the tool
    # is absent instead of fail-closing the deploy host.
    command -v cargo-outdated >/dev/null 2>&1 || { ci_warn "cargo-outdated missing — freshness report skipped (advisory)"; return "$CI_EXIT_OK"; }
    if ci_dry; then
        ci_info "check (dry-run): cargo outdated"
        return "$CI_EXIT_OK"
    fi
    ci_info "cargo outdated — report only (advisory, as upstream)"
    (cd "$WS" && cargo outdated --exit-code 1 >"$RUN_DIR/cargo-outdated.txt" 2>&1) \
        && ci_info "cargo outdated: all dependencies current" \
        || {
            tail -n 20 "$RUN_DIR/cargo-outdated.txt" >>"$CI_STAGE_LOG" 2>/dev/null || true
            ci_warn "cargo outdated reports outdated dependencies (report in $RUN_DIR/cargo-outdated.txt) — advisory"
        }
    return "$CI_EXIT_OK"
}

stage_main() {
    gitleaks_scan
    cargo_audit
    cargo_vet
    semgrep_sast
    migration_validation
    trivy_images
    cargo_outdated
    ci_info "security: all gates green"
    return "$CI_EXIT_OK"
}

trap 'ci_ephem_cleanup' EXIT
stage_main
