#!/bin/sh
# =============================================================================
# ci/stages/security.sh — stage 4: security + supply-chain + migration gates.
# =============================================================================
# Replaces:
#   * security-audit.yml   — cargo audit (same RUSTSEC ignore list); the
#                            cargo-outdated report is produced advisory-only
#   * cargo-vet.yml        — cargo vet when supply-chain/config.toml exists
#   * rust-check.yml       — gitleaks secret scan (same .gitleaks.toml);
#                            semgrep SAST (p/default + p/rust, REQUIRED —
#                            2026-09-10 expansion, was advisory)
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
#
# DAILY cargo-audit lane (security.cargo-audit-daily, DEP-6/V32):
#   * `cargo_audit_daily` clones the RustSec advisory database FRESH into the
#     run dir for every due invocation (cargo audit --db), then fails on any
#     vulnerability not covered by the two reviewed ledgers
#     (CI_CARGO_AUDIT_IGNORES + the DATED waivers in .cargo/audit.toml).
#   * It runs from every regular security-stage run AND from
#     `ci/pipeline.sh run --daily`, which the 5-minute host timer invokes
#     (ci/units/apexmail-pipeline.service ExecStart). A PASS writes the UTC
#     date to ci/runs/.last-daily-audit; same-day invocations record the lane
#     ok from that marker (no network, no clone), so the 5-minute poll stays
#     cheap while the advisory database is refreshed at least once a day.
#     A failure leaves no marker and fails the run, so the next timer tick
#     retries. CI_DAILY_AUDIT_FORCE=1 re-runs it on demand.
#   * The dated-waiver ledger is validated by tools/check_audit_waivers.py on
#     every audit run: an expired (>90 days) or obsolete waiver FAILS the
#     lane instead of being ignored silently.
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
# gitleaks_history_guard — the lane's contract is a FULL-history scan; on a
# shallow checkout (`git fetch --depth 1`, the old bootstrap) gitleaks sees
# only the current tree while the stage still reports the same green gate
# (audit P2). Fail closed for the REQUIRED gate; the advisory override keeps
# the bounded triage window. ci/stages/fetch.sh unshallows the host checkout
# automatically, so this guard should only fire on a hand-made shallow tree.
gitleaks_history_guard() {
    if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null || printf 'false')" != true ]; then
        return "$CI_EXIT_OK"
    fi
    if [ "${CI_GITLEAKS_CHECK:-required}" = advisory ]; then
        ci_warn "shallow checkout ($REPO_ROOT) — gitleaks will scan only the current tree (CI_GITLEAKS_CHECK=advisory, continuing)"
        return "$CI_EXIT_OK"
    fi
    ci_err "shallow checkout ($REPO_ROOT) — the REQUIRED gitleaks full-history scan would silently degrade to the current tree; run 'git fetch --unshallow' (ci/stages/fetch.sh does this on the deploy host)"
    return "$CI_EXIT_FAIL"
}

gitleaks_scan() {
    gitleaks_history_guard || return "$CI_EXIT_FAIL"
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
# cargo_audit_ignore_flags — the shared ignore set for both audit lanes.
# Sets CA_IGNORE_FLAGS (a --ignore word list) and CA_IGNORE_COUNT from:
#   1. CI_CARGO_AUDIT_IGNORES — the historic reviewed ledger in pipeline.conf
#      (kept in EXACT lockstep with deny.toml and scripts/security-audit.sh by
#      `ci/pipeline.sh selftest` step 9);
#   2. services/mail-server/.cargo/audit.toml — DATED waivers, validated here
#      by tools/check_audit_waivers.py. An expired/malformed waiver, or one
#      whose package/version is no longer in Cargo.lock, returns non-zero and
#      therefore FAILS the lane (fail closed: never run with an unverified
#      ignore set).
cargo_audit_ignore_flags() {
    CA_IGNORE_FLAGS=''
    CA_IGNORE_COUNT=0
    _caif_seen=' '
    for _caif_id in $CI_CARGO_AUDIT_IGNORES; do
        case $_caif_seen in *" $_caif_id "*) continue ;; esac
        _caif_seen="$_caif_seen$_caif_id "
        CA_IGNORE_FLAGS="$CA_IGNORE_FLAGS --ignore $_caif_id"
        CA_IGNORE_COUNT=$((CA_IGNORE_COUNT + 1))
    done
    _caif_file="$WS/.cargo/audit.toml"
    [ -f "$_caif_file" ] || return "$CI_EXIT_OK"
    if ! command -v python3 >/dev/null 2>&1; then
        ci_err "python3 missing — cannot validate the dated audit waivers in $_caif_file (fail closed)"
        return "$CI_EXIT_FAIL"
    fi
    _caif_ids=$(python3 "$REPO_ROOT/tools/check_audit_waivers.py" --print-ignores) || {
        ci_err "cargo-audit waiver ledger FAILED — fix or remove the expired/stale entries in $_caif_file"
        return "$CI_EXIT_FAIL"
    }
    _caif_dated=0
    for _caif_id in $_caif_ids; do
        _caif_dated=$((_caif_dated + 1))
        case $_caif_seen in *" $_caif_id "*) continue ;; esac
        _caif_seen="$_caif_seen$_caif_id "
        CA_IGNORE_FLAGS="$CA_IGNORE_FLAGS --ignore $_caif_id"
        CA_IGNORE_COUNT=$((CA_IGNORE_COUNT + 1))
    done
    ci_info "cargo audit ledgers: ${CA_IGNORE_COUNT} reviewed ignores (${_caif_dated} dated, expiry enforced)"
    return "$CI_EXIT_OK"
}

cargo_audit() {
    ci_have_tool cargo-audit || return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "check (dry-run): cargo audit"
        return "$CI_EXIT_OK"
    fi
    cargo_audit_ignore_flags || return "$CI_EXIT_FAIL"
    ci_info "cargo audit (${CA_IGNORE_COUNT} reviewed RUSTSEC ignores) — vulnerability-class advisories fail the run; unmaintained/unsound/yanked WARNING-class notices are logged but do not gate"
    _ca_rc=0
    # shellcheck disable=SC2086  # CA_IGNORE_FLAGS is an intentional flag word list
    (cd "$WS" && # --deny vulnerabilities: real advisories fail the run (after the
    # reviewed --ignore list); unmaintained/unsound/yanked WARNING-class
    # notices are logged but do not gate deploys — that is upgrade-policy
    # tracking, not a deploy blocker (2026-08-23: the warning set churns
    # weekly; see pipeline.conf justifications).
cargo audit $CA_IGNORE_FLAGS >"$RUN_DIR/cargo-audit.txt" 2>&1) || _ca_rc=$?
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

# --- cargo audit daily (DEP-6: fresh advisory database, once per UTC day) ------------
# Lane id: cargo-audit-daily (row security.cargo-audit-daily in
# ci/required-lanes.txt). Trigger and scheduling contract live in the stage
# header: every regular security run, plus `ci/pipeline.sh run --daily` from
# the 5-minute host timer. Same-day invocations after a PASS record the lane
# ok from ci/runs/.last-daily-audit without touching the network.
cargo_audit_daily() {
    _cad_marker=${CI_DAILY_AUDIT_MARKER:-$CI_ROOT/runs/.last-daily-audit}
    _cad_today=$(date -u +%Y-%m-%d)
    if [ "${CI_DAILY_AUDIT_FORCE:-0}" != 1 ] && [ -f "$_cad_marker" ] \
        && [ "$(head -n 1 "$_cad_marker" 2>/dev/null)" = "$_cad_today" ]; then
        ci_info "cargo audit daily: already PASSED today ($_cad_today, marker $_cad_marker) — lane recorded from the marker"
        ci_lane_record cargo-audit-daily ok
        return "$CI_EXIT_OK"
    fi
    ci_have_tool cargo-audit || return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "check (dry-run): cargo audit daily (FRESH advisory database)"
        return "$CI_EXIT_OK"
    fi
    cargo_audit_ignore_flags || return "$CI_EXIT_FAIL"
    # Fresh database, per run: cargo-audit clones the RustSec repository into
    # the run dir. The shared ~/.cargo/advisory-db cache is deliberately NOT
    # used — a stale cache must never be able to make the daily lane green.
    _cad_db="$RUN_DIR/advisory-db"
    ci_info "cargo audit daily: fetching a FRESH RustSec advisory database (clone into $_cad_db)"
    _cad_rc=0
    # shellcheck disable=SC2086  # CA_IGNORE_FLAGS is an intentional flag word list
    (cd "$WS" && cargo audit --db "$_cad_db" $CA_IGNORE_FLAGS) \
        >"$RUN_DIR/cargo-audit-daily.txt" 2>&1 || _cad_rc=$?
    if [ "$_cad_rc" -eq 0 ]; then
        mkdir -p "$(dirname "$_cad_marker")"
        # Only a PASS writes the marker: a failed audit retries on the next
        # timer tick instead of waiting for tomorrow.
        printf '%s\n%s\n' "$_cad_today" "${CI_SHA:-unknown}" >"$_cad_marker"
        ci_info "PASS: cargo audit daily (fresh database)"
        ci_lane_record cargo-audit-daily ok
        return "$CI_EXIT_OK"
    fi
    grep -E '^(Crate|Version|ID|Solution):' "$RUN_DIR/cargo-audit-daily.txt" 2>/dev/null | head -60 >>"$CI_STAGE_LOG" || true
    if [ "${CI_CARGO_AUDIT_DAILY_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: cargo audit daily reports unignored vulnerabilities or an invalid waiver ledger (report: $RUN_DIR/cargo-audit-daily.txt)"
        ci_lane_record cargo-audit-daily fail
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: cargo audit daily — unignored vulnerability or invalid waiver ledger (report: $RUN_DIR/cargo-audit-daily.txt)"
    ci_lane_record cargo-audit-daily fail
    return "$CI_EXIT_FAIL"
}

# --- cargo vet (supply-chain/config.toml — initialized 2026-09-28; REQUIRED) -----------
# Audit finding: vet "simply skips when supply-chain/config.toml does not
# exist", so third-party provenance vetting was optional by absence. The
# config is now committed — its DISAPPEARANCE is a hard failure, not a skip.
cargo_vet() {
    if [ ! -f "$WS/supply-chain/config.toml" ]; then
        ci_err "supply-chain/config.toml missing — third-party provenance vetting is REQUIRED (restore the file; ci/stages/security.sh no longer skips)"
        return "$CI_EXIT_FAIL"
    fi
    ci_have_tool cargo-vet || return "$CI_EXIT_OK"
    (cd "$WS" && ci_check "cargo vet" cargo vet --locked)
}

# --- Semgrep SAST (rust-check.yml SAST job — now REQUIRED) ------------------------------
# Enterprise coverage expansion (2026-09-10): the lane was advisory with a
# plain warn-skip when semgrep was absent, which meant the deploy host could
# ship without ANY SAST gate. Now fail-closed on the deploy host via
# ci_have_tool (warn-and-skip stays for dev machines — the framework's own
# missing-tool policy) and CI_SEMGREP_CHECK=required by default; every
# finding must be fixed or triaged with a targeted inline
# `# nosemgrep: <rule-id>` comment carrying a justification, so the lane
# exits 0 honestly. `advisory` remains available for a bounded triage
# window. Scan set: repo code dirs — the vendored/generated trees
# (marketing build output, node_modules, cargo target, vendored libs, .git)
# are excluded: they are not reviewable product code and drown the signal.
# workflow YAML (the validate stage enforces .github/workflows/ stays
# empty), so findings there are inert by construction.
# Host pin: semgrep 1.176.x (ci/install.sh venv recipe).
semgrep_sast() {
    ci_have_tool semgrep || return "$CI_EXIT_OK"
    _sg_rc=0
    (cd "$REPO_ROOT" && ci_check "semgrep SAST" \
        semgrep scan --config p/default --config p/rust --error --quiet \
            --exclude apps/marketing-zola/public \
            --exclude node_modules --exclude target --exclude vendor \
            --exclude packages/kiwicaptcha --exclude packages/kiwicaptcha-risk \
            --exclude packages/kiwicaptcha-wasm \
            --exclude docs/audit \
            --exclude services/mail-server/crates/billing-service/src/test_fixtures) || _sg_rc=$?
    if [ "$_sg_rc" -eq 0 ]; then
        return "$CI_EXIT_OK"
    fi
    if [ "${CI_SEMGREP_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: semgrep reported findings (CI_SEMGREP_CHECK=advisory) — fix the code or add targeted '# nosemgrep: <rule-id>' justifications"
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: semgrep findings above — fix the code or add targeted \
'# nosemgrep: <rule-id>' comments with justifications for false positives"
    return "$CI_EXIT_FAIL"
}

# --- Trivy filesystem scan (new lane — REQUIRED) -----------------------------------------
# Source-tree vulnerability + secret scan of the working tree
# (vulnerability DB over manifests/lockfiles + secret patterns), gated on
# CRITICAL/HIGH exactly like the image lanes. Vendored/generated dirs are
# skipped (not reviewable product code; the marketing build output is
# scanned as SOURCE templates by gitleaks + the template-leak gate).
# Triage lives in $REPO_ROOT/.trivyignore (vulnerability IDs) and
# $REPO_ROOT/trivy-secret.yaml (secret allow-rules) — every entry in either
# must carry a justification comment (same contract as the image lanes).
# CI_TRIVY_FS_CHECK=required; advisory exists for a bounded triage window.
trivy_fs_scan() {
    ci_have_tool trivy || return "$CI_EXIT_OK"
    _tf_rc=0
    (cd "$REPO_ROOT" && ci_check "trivy fs" \
        trivy fs --severity "$CI_TRIVY_SEVERITY" --scanners vuln,secret \
            --skip-dirs node_modules,target,public,vendor,.git,secrets,certs,backups \
            --skip-dirs .venv,venv,.tox,__pycache__ \
            --skip-dirs deploy/nginx/ssl,deploy/nginx/ssl-archive \
            --skip-files './.env*' \
            --skip-files './backup-*.dump' \
            --ignorefile "$REPO_ROOT/.trivyignore" \
            --secret-config "$REPO_ROOT/trivy-secret.yaml" \
            --exit-code 1 .) || _tf_rc=$?
    if [ "$_tf_rc" -eq 0 ]; then
        return "$CI_EXIT_OK"
    fi
    if [ "${CI_TRIVY_FS_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: trivy fs reported findings (CI_TRIVY_FS_CHECK=advisory) — triage in .trivyignore with justifications"
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: trivy fs findings above — upgrade the dependency or add a \
justified .trivyignore entry (revisit on every feed refresh)"
    return "$CI_EXIT_FAIL"
}

# --- Trivy image scans (deploy.yml scan steps) -------------------------------------------
# Scans the images that exist locally (built by a previous images stage run).
# The post-build authoritative gate lives in the images stage; this is the
# pre-deploy re-scan of what is on disk.
trivy_images() {
    ci_have_tool trivy || return "$CI_EXIT_OK"
    # Audit SM14 F5: docker-absence used to look identical to "nothing to
    # scan". On the deploy host that is a POLICY failure under
    # CI_MISSING_TOOLS=fail (the pre-deploy re-scan silently vanished); on a
    # CI executor there are BY DESIGN no locally built images to re-scan —
    # the authoritative post-build scan runs in the images stage on the
    # deploy host — so the skip is stated loudly instead of being silent.
    if ! ci_docker_ok; then
        if ci_on_deploy_host && [ "${CI_MISSING_TOOLS:-auto}" = fail ]; then
            ci_err "docker unavailable on the deploy host and CI_MISSING_TOOLS=fail — the pre-deploy image re-scan cannot silently vanish (audit SM14 F5, fail closed)"
            return "$CI_EXIT_FAIL"
        fi
        ci_info "trivy: no local docker images to re-scan (executor context — the authoritative \
post-build image scan runs in the images stage on the deploy host; audit SM14 F5)"
        return "$CI_EXIT_OK"
    fi
    _ns=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
    for _svc in api-server mta; do
        # Stale-image guard: a :latest with no matching :$CI_SHA predates this
        # deploy — it is the artifact being REPLACED, and its findings belong
        # to the old dependency set this build fixes. Scanning it would block
        # the very deploy that replaces it (deploy 2026-10-12). The
        # authoritative gate is the images stage's post-build scan of exactly
        # what this pipeline built from this tree; this pre-deploy re-scan
        # stays hard whenever the sha-pinned image exists.
        if ! docker image inspect "$_ns/$_svc:$CI_SHA" >/dev/null 2>&1 \
            && docker image inspect "$_ns/$_svc:latest" >/dev/null 2>&1; then
            ci_warn "trivy: $_ns/$_svc:latest predates this sha — pre-deploy re-scan skipped (outgoing artifact; the images-stage post-build scan is authoritative)"
            continue
        fi
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
# Fresh-DB TARGET (audit SM14 F5), in priority order:
#   1. TEST_FRESH_DATABASE_URL — a CI executor provides a NEVER-MIGRATED
#      database as a Woodpecker `service` (postgres-fresh in
#      .woodpecker.yml): the full chain-apply proof runs WITHOUT docker
#      inside the executor.
#   2. an ephemeral docker postgres (the deploy-host path).
#   3. NEITHER — under CI_MISSING_TOOLS=fail this is a HARD FAILURE (the
#      gate used to silently vanish on the executor while the pipeline
#      still posted "release gates GREEN"); otherwise a loud skip.
# F7 — same include_dir staleness fix as ci/stages/test.sh apply_test_schema:
# sqlx::migrate! embeds via include_dir; some cargo versions miss new files
# in the tracked dir on incremental rebuilds, so a freshly added migration
# can be silently absent from a cached migrator binary. Force a rebuild of
# the crate before EVERY `cargo run -p migrator` here (dry-run + both
# fallback applies).
# NOTE (2026-08-21): the chain currently FAILS from scratch at migration 109
# (see ci/README.md § "Known pipeline findings"); CI_MIGRATION_CHECK=advisory
# downgrades this check until the migration is fixed.
migration_validation() {
    if ci_dry; then
        ci_info "dry-run: migration validation (migrator --dry-run + fresh-DB chain apply x2)"
        return "$CI_EXIT_OK"
    fi
    ci_info "migration validation"
    _mv_url=''
    if [ -n "${TEST_FRESH_DATABASE_URL:-}" ]; then
        _mv_url=$TEST_FRESH_DATABASE_URL
        ci_info "fresh-DB target: the executor-provided never-migrated database (TEST_FRESH_DATABASE_URL)"
    elif ci_docker_ok; then
        ci_info "fresh-DB target: ephemeral postgres"
        _mv_port=$(ci_free_port)
        ci_ephem_postgres apexmail-ci-sec-pg apexmail apexmail apexmail_sec "$_mv_port" \
            || ci_die "ephemeral postgres failed to start"
        _mv_url="postgres://apexmail:apexmail@127.0.0.1:$_mv_port/apexmail_sec"
    else
        # Audit SM14 F5: route docker-absence through the missing-tools
        # policy instead of silently skipping a REQUIRED gate.
        if [ "${CI_MISSING_TOOLS:-auto}" = fail ]; then
            ci_err "no fresh database available (TEST_FRESH_DATABASE_URL unset, docker unavailable) \
and CI_MISSING_TOOLS=fail — the REQUIRED fresh-DB migration gate cannot silently vanish (fail closed)"
            return "$CI_EXIT_FAIL"
        fi
        ci_warn "docker unavailable — migration validation skipped"
        return "$CI_EXIT_OK"
    fi

    # (1) embedded migration set lists cleanly (touch: see the F7 note above)
    touch "$WS/crates/migrator/src/main.rs"
    (cd "$WS" && ci_check "migrator dry-run" cargo run --locked -p migrator -- --dry-run) \
        || return "$CI_EXIT_FAIL"

    # (2) apply the chain to the fresh database, twice. The retry loop
    # absorbs postgres's first-init restart (the alpine entrypoint's
    # password bootstrap) on BOTH targets: pg_isready can pass against the
    # bootstrap process and the next real connection fails with a protocol
    # reset ("unexpected response from SSLRequest: 0x00"); the idempotency
    # apply then runs against the settled server.
    _mv_settle=0
    if command -v sqlx >/dev/null 2>&1; then
        for _mv_try in 1 2 3; do
            if (cd "$WS" && DATABASE_URL="$_mv_url" sqlx migrate run --source migrations) \
                >>"$CI_STAGE_LOG" 2>&1; then
                _mv_settle=1
                break
            fi
            ci_warn "sqlx connect attempt $_mv_try failed (postgres finishing init?); retrying"
            sleep 3
        done
    fi
    _mv_rc=0
    if command -v sqlx >/dev/null 2>&1 && [ "$_mv_settle" -ne 1 ]; then
        ci_err "sqlx migrate run could not connect after 3 attempts — see $CI_STAGE_LOG"
        _mv_rc=1
    elif command -v sqlx >/dev/null 2>&1; then
        (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "sqlx migrate clean db" \
            sqlx migrate run --source migrations) || _mv_rc=1
        [ "$_mv_rc" -ne 0 ] || {
            (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "sqlx migrate idempotency" \
                sqlx migrate run --source migrations) || _mv_rc=1
        }
    else
        ci_warn "sqlx-cli missing — falling back to the migrator binary \
(fresh-DB NULL-decode bug applies; install sqlx-cli via ci/install.sh)"
        # touch again before EACH cargo run (see the F7 note above)
        touch "$WS/crates/migrator/src/main.rs"
        (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "migrator apply clean db" \
            cargo run --locked -p migrator) || _mv_rc=1
        [ "$_mv_rc" -ne 0 ] || {
            touch "$WS/crates/migrator/src/main.rs"
            (cd "$WS" && DATABASE_URL="$_mv_url" ci_check "migrator apply idempotency" \
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
    # `ci/pipeline.sh run --daily` (the host timer path) runs ONLY the daily
    # audit lane. Same-day no-ops exit through the marker check, so the
    # 5-minute poll pays a shell start and nothing else.
    if [ "${CI_DAILY_AUDIT_ONLY:-0}" = 1 ]; then
        cargo_audit_daily || return "$CI_EXIT_FAIL"
        ci_info "security: daily cargo-audit lane complete"
        return "$CI_EXIT_OK"
    fi
    gitleaks_scan
    cargo_audit
    cargo_audit_daily
    cargo_vet
    semgrep_sast
    migration_validation
    trivy_images
    trivy_fs_scan
    cargo_outdated
    ci_info "security: all gates green"
    return "$CI_EXIT_OK"
}

trap 'ci_ephem_cleanup' EXIT
stage_main
