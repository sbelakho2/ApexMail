#!/bin/sh
# =============================================================================
# ci/stages/test.sh — stage 3: build + lint + test everything.
# =============================================================================
# Replaces:
#   * rust-check.yml  — cargo check/clippy/nextest, cargo cycles, security
#                       feature flags, audit-coverage ledger, machete, deny
#   * release-gates.yml (lint / type-check / unit-tests jobs)
#   * regression_checks.yml compliance-tests job (subsumed by --workspace)
#   * the PHP suites (kiwicaptcha-php, kiwicaptcha-risk-php, kiwicaptcha
#     symfony integration) that previously ran only on dev machines.
#
# Lane (in order):
#   1. zola build when apps/marketing-zola/public is absent — the
#      ui-foundation crate include_str!s the marketing output and cannot
#      compile without it (a fresh checkout has no public/).
#   2. cargo fmt --check
#   3. cargo clippy --workspace --all-targets -- -D warnings
#   4. repo python gates (cycles / feature flags / audit coverage)
#   5. cargo machete + cargo deny (advisories bans sources licenses) —
#      REQUIRED via ci_have_tool (fail-closed on the deploy host, warn-skip
#      on dev machines); licenses gate: inventory-driven deny.toml allow list
#   6. ephemeral services per CI_TEST_DB / CI_TEST_REDIS, then
#      cargo test --workspace
#   6b. coverage ratchet: cargo llvm-cov nextest --workspace →
#      $RUN_DIR/coverage.lcov; OVERALL line coverage compared against
#      ci/coverage-baseline.txt (below = FAIL, CI_COVERAGE_CHECK)
#   7. PHP: three phpunit suites (REQUIRED; composer install when the
#      checkout has no vendor/ yet)
#   8. the five SDK lanes (python/go/java/ruby/php — CI_SDK_CHECK)
#   9. the satellite Rust crates (CI_SATELLITE_CHECK)
#  10. static lint gates: shellcheck/hadolint/py_compile
#      (CI_STATIC_LINT_CHECK)
#
# DB/Redis policy: GitHub-parity by default (CI_TEST_DB=none, CI_TEST_REDIS=0)
# — the DB/Redis-gated tests self-skip exactly as they do on GitHub runners.
# CI_TEST_DB=ephemeral spins a postgres, applies the canonical SCHEMA and
# exports TEST_DATABASE_URL; CI_TEST_REDIS=1 spins a redis and exports
# TEST_REDIS_URL. See ci/README.md § "Known failing tests" before enabling.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

WS=$REPO_ROOT/services/mail-server

# --- 1. marketing output present (compile input for ui-foundation) ----------------
ensure_marketing_output() {
    [ -f "$REPO_ROOT/apps/marketing-zola/public/index.html" ] && return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "dry-run: zola build (marketing output for ui-foundation)"
        return "$CI_EXIT_OK"
    fi
    if ! command -v zola >/dev/null 2>&1; then
        ci_die "apps/marketing-zola/public is missing and zola is not installed — \
ui-foundation cannot compile (install zola or build the site once)"
    fi
    ci_info "building marketing output (required by ui-foundation include_str!)"
    (cd "$REPO_ROOT/apps/marketing-zola" && zola build) >>"$CI_STAGE_LOG" 2>&1 \
        || { ci_err "zola build failed"; return "$CI_EXIT_FAIL"; }
}

# --- 5. required cargo tooling gates ------------------------------------------------
# Enterprise coverage expansion (2026-09-10): machete + deny were plain
# warn-skips when absent, which violated the fail-closed tool policy on the
# deploy host (a host without cargo-deny silently shipped no advisory/ban/
# source/license gate at all). Both lanes now go through ci_have_tool: die on
# the deploy host when missing (fail closed), warn-and-skip on dev machines
# (the framework's own missing-tool policy). The deny invocation is extended
# to `licenses` — services/mail-server/deny.toml carries an inventory-driven
# SPDX allow list (see the 2026-09-10 sweep comments there).
cargo_tool_gates() {
    if ci_have_tool cargo-machete; then
        (cd "$WS" && ci_check "cargo machete (unused deps)" cargo machete) \
            || return "$CI_EXIT_FAIL"
    fi
    if ci_have_tool cargo-deny; then
        if [ ! -f "$WS/deny.toml" ]; then
            ci_err "cargo-deny config missing: $WS/deny.toml — licenses lane cannot run (fail closed)"
            return "$CI_EXIT_FAIL"
        fi
        (cd "$WS" && ci_check "cargo deny (advisories bans sources licenses)" \
            cargo deny check advisories bans sources licenses) \
            || return "$CI_EXIT_FAIL"
    fi
}

# --- 6. ephemeral services + cargo test ------------------------------------------------
# Hermeticity: several integration tests PROBE 127.0.0.1:5432/6379 by default
# when their env var is unset (sales-autopilot SALES_TEST_DATABASE_URL,
# enterprise ENTERPRISE_TEST_DATABASE_URL, api-server TEST_REDIS_URL). On a
# machine with an ambient dev postgres/redis those tests then run against
# whatever schema that DB holds and fail (README §9 F6). Default mode pins
# those probes at an unreachable port so they soft-skip — the exact GitHub
# behaviour, but deterministic on every host.
#
# _provision_test_services (refactored 2026-09-10 out of run_cargo_tests so
# the coverage gate can share the EXACT same hermetic env): starts the
# ephemeral containers per CI_TEST_DB / CI_TEST_REDIS, applies the canonical
# schema when a postgres is up, and leaves the env-assignment word list in
# _TEST_ENV (VAR=val pairs, consumed via `env $_TEST_ENV ...`).
_provision_test_services() {
    _TEST_ENV=''
    if [ "${CI_TEST_DB:-none}" = ephemeral ] || [ "${CI_TEST_REDIS:-0}" = 1 ]; then
        ci_docker_ok || ci_die "ephemeral test services requested but docker is unavailable"
    fi
    if [ "${CI_TEST_DB:-none}" = ephemeral ]; then
        _pg_port=$(ci_free_port)
        ci_ephem_postgres apexmail-ci-test-pg apexmail apexmail apexmail_test "$_pg_port" \
            || ci_die "ephemeral postgres failed to start"
        apply_test_schema
        _TEST_ENV="TEST_DATABASE_URL=postgres://apexmail:apexmail@127.0.0.1:$_pg_port/apexmail_test"
        _TEST_ENV="$_TEST_ENV SALES_TEST_DATABASE_URL=postgres://apexmail:apexmail@127.0.0.1:$_pg_port/apexmail_test"
        _TEST_ENV="$_TEST_ENV ENTERPRISE_TEST_DATABASE_URL=postgres://apexmail:apexmail@127.0.0.1:$_pg_port/apexmail_test"
    else
        _TEST_ENV="SALES_TEST_DATABASE_URL=postgres://127.0.0.1:1/apexmail_test"
        _TEST_ENV="$_TEST_ENV ENTERPRISE_TEST_DATABASE_URL=postgres://127.0.0.1:1/apexmail_test"
        # NOTE: TEST_DATABASE_URL stays UNSET in default mode — the
        # functional-sales suite PANICS when it is set but unreachable.
    fi
    if [ "${CI_TEST_REDIS:-0}" = 1 ]; then
        _redis_port=$(ci_free_port)
        ci_ephem_redis apexmail-ci-test-redis "$_redis_port" \
            || ci_die "ephemeral redis failed to start"
        _TEST_ENV="$_TEST_ENV TEST_REDIS_URL=redis://127.0.0.1:$_redis_port"
    else
        _TEST_ENV="$_TEST_ENV TEST_REDIS_URL=redis://127.0.0.1:1"
    fi

    # macOS (this dev host): rustls-native-certs reads the platform store
    # via the Security framework, which yields nothing in non-GUI shells —
    # the AWS SDK's TLS provider then panics ("no valid root certificates").
    # A portable PEM bundle (present on macOS and Linux) restores it.
    if [ -f /etc/ssl/cert.pem ] && [ -z "${SSL_CERT_FILE:-}" ]; then
        _TEST_ENV="$_TEST_ENV SSL_CERT_FILE=/etc/ssl/cert.pem"
    fi
}

run_cargo_tests() {
    _provision_test_services

    ci_info "running cargo tests --workspace ($(printf '%s' "$_TEST_ENV" | tr ' ' ','))"
    # rust-check.yml ran `cargo nextest run --workspace --all-targets` —
    # nextest isolates every test in its own process, which matters here:
    # under `cargo test`'s threaded model, env-var-mutating tests race each
    # other (README §9 F10). Prefer nextest; fall back to cargo test.
    if command -v cargo-nextest >/dev/null 2>&1; then
        if ci_dry; then
            ci_info "check (dry-run): cargo nextest run --workspace --all-targets"
            return "$CI_EXIT_OK"
        fi
        _nx_args=''
        # Known-failing tests are EXCLUDED, loudly, via CI_NEXTEST_EXCLUDE
        # (README §9): every entry must reference a finding number and be
        # removed once fixed. Empty the list to run everything. (--skip is
        # libtest's substring filter, passed after `--`.)
        for _kft in ${CI_NEXTEST_EXCLUDE:-}; do
            ci_warn "EXCLUDING known-failing test matching '$_kft' (see ci/README.md §9 / pipeline.conf)"
            if [ -z "$_nx_args" ]; then
                _nx_args="-- --skip $_kft"
            else
                _nx_args="$_nx_args --skip $_kft"
            fi
        done
        # shellcheck disable=SC2086  # _TEST_ENV/_nx_args are intentional word lists
        if ! (cd "$WS" && ci_run_logged env $_TEST_ENV CARGO_TERM_COLOR=never \
                cargo nextest run --workspace --all-targets $_nx_args); then
            ci_err "cargo nextest run FAILED — see the output above"
            return "$CI_EXIT_FAIL"
        fi
    else
        ci_warn "cargo-nextest missing — falling back to cargo test (known env-race, §9 F10); install nextest via ci/install.sh"
        # shellcheck disable=SC2086
        if ! (cd "$WS" && ci_run_logged env $_TEST_ENV CARGO_TERM_COLOR=never cargo test --workspace); then
            ci_err "cargo test --workspace FAILED — see the output above"
            return "$CI_EXIT_FAIL"
        fi
    fi
}

# --- 6b. coverage ratchet gate --------------------------------------------------------
# cargo-llvm-cov re-runs the workspace suite under llvm profiling
# instrumentation and writes $RUN_DIR/coverage.lcov; the OVERALL line
# coverage % parsed from that file is compared against ci/coverage-baseline.txt
# (a single float). BELOW baseline = FAIL (a coverage ratchet: the number can
# only go up); at-or-above = PASS, printing the measured value plus a hint
# that raising the baseline in the same PR as the code that earned it is a
# PR-positive action. The baseline ships as 0.0 — the first host run seeds
# the real value (see the comment in ci/coverage-baseline.txt).
# Requires: cargo-llvm-cov + the llvm-tools-preview rustup component +
# cargo-nextest (ci/install.sh installs all three). Missing tooling fails
# CLOSED on the deploy host via ci_have_tool and warns on dev machines.
run_coverage_gate() {
    ci_have_tool cargo-llvm-cov || return "$CI_EXIT_OK"
    _cov_baseline=$CI_ROOT/coverage-baseline.txt
    if [ ! -f "$_cov_baseline" ]; then
        ci_err "coverage baseline missing: $_cov_baseline — the ratchet gate cannot run (fail closed)"
        return "$CI_EXIT_FAIL"
    fi
    if ci_dry; then
        ci_info "check (dry-run): cargo llvm-cov nextest --workspace"
        return "$CI_EXIT_OK"
    fi
    if ! command -v cargo-nextest >/dev/null 2>&1; then
        ci_err "cargo-nextest missing — the coverage gate requires nextest (install via ci/install.sh)"
        return "$CI_EXIT_FAIL"
    fi
    # Same hermetic env as run_cargo_tests (refactored into
    # _provision_test_services): fresh ephemeral postgres/redis per
    # CI_TEST_DB/CI_TEST_REDIS, canonical schema applied, DB/Redis probes
    # pinned when disabled. ci_ephem_postgres removes the previous container
    # of the same name first, and the plain-test containers are finished by
    # the time this lane runs.
    _provision_test_services
    _cov_lcov=$RUN_DIR/coverage.lcov
    ci_info "running cargo llvm-cov nextest --workspace ($(printf '%s' "$_TEST_ENV" | tr ' ' ','))"
    # --ignore-filename-regex keeps the measurement to WORKSPACE sources
    # only (dependency/stdlib code lives under ~/.cargo and target/).
    # shellcheck disable=SC2086  # _TEST_ENV is an intentional word list
    # cargo-llvm-cov consumes its own flags (--lcov --output-path) before
    # `nextest`; --lcov-path is a nextest flag and was rejected there.
    if ! (cd "$WS" && ci_run_logged env $_TEST_ENV CARGO_TERM_COLOR=never \
            cargo llvm-cov nextest --workspace \
            --ignore-filename-regex '/(target|\.cargo|\.rustup)/' \
            --lcov --output-path "$_cov_lcov"); then
        if [ "${CI_COVERAGE_CHECK:-required}" = advisory ]; then
            ci_warn "ADVISORY: instrumented test run FAILED (CI_COVERAGE_CHECK=advisory)"
            return "$CI_EXIT_OK"
        fi
        ci_err "cargo llvm-cov nextest FAILED — see the output above (coverage gate)"
        return "$CI_EXIT_FAIL"
    fi
    if [ ! -s "$_cov_lcov" ]; then
        if [ "${CI_COVERAGE_CHECK:-required}" = advisory ]; then
            ci_warn "ADVISORY: $_cov_lcov empty — coverage not measured"
            return "$CI_EXIT_OK"
        fi
        ci_err "coverage gate produced no lcov output ($_cov_lcov)"
        return "$CI_EXIT_FAIL"
    fi
    # OVERALL line coverage: lcov `DA:<line>,<hits>` records, hits > 0.
    _cov_pct=$(awk -F: '/^DA:/ {
        split(substr($0, 4), p, ",")
        total++
        if (p[2] + 0 > 0) hit++
    } END { printf "%.4f", (total ? 100.0 * hit / total : 0.0) }' "$_cov_lcov")
    _cov_base=$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$_cov_baseline" | head -n 1)
    case $_cov_base in
        ''|*[!0-9.]*) ci_err "invalid baseline '$_cov_base' in $_cov_baseline (expected a single float)"; return "$CI_EXIT_FAIL" ;;
    esac
    if awk -v a="$_cov_pct" -v b="$_cov_base" 'BEGIN { exit !(a + 0 >= b + 0) }'; then
        ci_info "PASS: workspace line coverage $_cov_pct% (baseline $_cov_base%) — lcov artifact: $_cov_lcov"
        ci_info "ratchet: if this is above the baseline, raise ci/coverage-baseline.txt to $_cov_pct in the SAME PR — that is a PR-positive action, not a concession"
        return "$CI_EXIT_OK"
    fi
    if [ "${CI_COVERAGE_CHECK:-required}" = advisory ]; then
        ci_warn "ADVISORY: line coverage $_cov_pct% fell below baseline $_cov_base% (CI_COVERAGE_CHECK=advisory)"
        return "$CI_EXIT_OK"
    fi
    ci_err "FAIL: workspace line coverage $_cov_pct% is BELOW the baseline $_cov_base% \
(ratchet) — add tests or lower the baseline deliberately in a reviewed PR"
    return "$CI_EXIT_FAIL"
}

# Apply the CANONICAL MIGRATION CHAIN to the ephemeral test database.
#
# This used to apply the apexmail-db SCHEMA constant (a hand-maintained DDL
# shadow of the chain) — the two drifted apart wholesale (uuid-vs-text ids on
# campaigns/templates/events, missing columns across users/webhooks/messages/
# events/...), so the DB-backed test suite failed against the bootstrap the
# moment CI_TEST_DB=ephemeral became the default. The chain (embedded by the
# migrator at build time) is the single source of truth the production
# database actually runs — the ephemeral database must be provisioned from
# the SAME chain or the suite validates a schema that does not exist.
apply_test_schema() {
    # Dry-run (selftest) safety: ci_ephem_postgres only ECHOES its docker run
    # in dry-run mode, so no container exists to resolve a port from — the
    # real build/port/migrate steps are skipped and the suite's DB-dependent
    # lanes degrade exactly like the CI_TEST_DB=none path.
    if ci_dry; then
        ci_info "dry-run: ephemeral schema application skipped (no postgres container)"
        return "$CI_EXIT_OK"
    fi
    ci_info "building the migrator (canonical chain embedded at compile time)"
    # sqlx::migrate! embeds via include_dir; some cargo versions miss new
    # files in the tracked dir on incremental rebuilds — force a rebuild so a
    # freshly added migration can never be silently absent from the binary.
    touch "$WS/crates/migrator/src/main.rs"
    (cd "$WS" && cargo build -q -p migrator) >>"$CI_STAGE_LOG" 2>&1 \
        || { ci_err "cargo build -p migrator failed"; return "$CI_EXIT_FAIL"; }
    _pg_port=$(docker port apexmail-ci-test-pg 5432/tcp 2>/dev/null | head -1 | sed 's/.*://')
    [ -n "$_pg_port" ] || { ci_err "could not resolve the ephemeral postgres port"; return "$CI_EXIT_FAIL"; }
    ci_info "applying the canonical chain (migrator) to the ephemeral DB on port $_pg_port"
    # Retry: alpine's entrypoint restarts postgres once after first-init
    # (password setup) — pg_isready can pass against the bootstrap process
    # and the next real connection resets. Three retries absorb it.
    _mig_ok=0
    _mig_try=1
    while [ "$_mig_try" -le 3 ]; do
        if (cd "$WS" && DATABASE_URL="postgres://apexmail:apexmail@127.0.0.1:$_pg_port/apexmail_test" \
            ./target/debug/migrator) >>"$CI_STAGE_LOG" 2>&1; then
            _mig_ok=1
            break
        fi
        ci_warn "migrator attempt $_mig_try against the ephemeral DB failed (postgres may be mid-restart); retrying"
        _mig_try=$((_mig_try + 1))
        sleep 3
    done
    [ "$_mig_ok" = 1 ] || { ci_err "migrator failed against the ephemeral DB — see $CI_STAGE_LOG"; return "$CI_EXIT_FAIL"; }
}

# --- shared lane-tool gating --------------------------------------------------------
# lane_tool_status <tool> <lane-label> <flag> — print the lane disposition on
# stdout: `run`, `skip` (advisory lane, tool absent) or `fail` (required
# lane, tool absent). Backed by ci_have_tool semantics: on the deploy host a
# missing tool DIES (fail closed, CI_MISSING_TOOLS=auto); on a dev machine
# the lane flag decides — REQUIRED turns the gap into a stage failure,
# `advisory` logs and skips. In dry-run (selftest) the lane is assumed
# runnable: presence is a real-run concern and selftest machines are not
# required to carry every toolchain (the deploy host installs them all via
# ci/install.sh).
lane_tool_status() {
    _lt_tool=$1 _lt_lane=$2 _lt_flag=${3:-required}
    if ci_dry; then
        printf 'run\n'
        return "$CI_EXIT_OK"
    fi
    if ci_have_tool "$_lt_tool"; then
        printf 'run\n'
        return "$CI_EXIT_OK"
    fi
    # ci_have_tool has warned already; decide fail-vs-skip.
    if [ "$_lt_flag" = required ]; then
        ci_err "$_lt_lane: '$_lt_tool' missing — lane is REQUIRED \
(install it via ci/install.sh, or set the lane's CI_*_CHECK=advisory for a triage window)"
        printf 'fail\n'
        return "$CI_EXIT_OK"
    fi
    ci_warn "ADVISORY: $_lt_lane skipped — '$_lt_tool' missing"
    printf 'skip\n'
    return "$CI_EXIT_OK"
}

# --- 7. PHP suites (REQUIRED) --------------------------------------------------------
# Previously each suite silently skipped when vendor/bin/phpunit was absent —
# on the deploy host phpunit WAS absent for months, so the lane passed while
# testing nothing. Now php+composer are ci_have_tool-gated (fail closed on
# the deploy host) and composer install provisions vendor/ when missing
# (one-time ~30 s per package, then cached in the checkout).
run_php_tests() {
    _pt_st=$(lane_tool_status php php-suites "${CI_PHP_CHECK:-required}")
    case $_pt_st in
        fail) return "$CI_EXIT_FAIL" ;;
        skip) return "$CI_EXIT_OK" ;;
    esac
    _pt_st=$(lane_tool_status composer php-suites "${CI_PHP_CHECK:-required}")
    case $_pt_st in
        fail) return "$CI_EXIT_FAIL" ;;
        skip) return "$CI_EXIT_OK" ;;
    esac
    for _pkg in packages/kiwicaptcha-php \
                packages/kiwicaptcha-risk-php \
                packages/kiwicaptcha/integrations/symfony; do
        provision_composer_vendor "$_pkg" || return "$CI_EXIT_FAIL"
        (cd "$REPO_ROOT/$_pkg" && ci_check "phpunit $_pkg" ./vendor/bin/phpunit) \
            || return "$CI_EXIT_FAIL"
    done
    return "$CI_EXIT_OK"
}

# provision_composer_vendor <pkg-rel-path> — composer install when the
# checkout carries no vendor/ yet (dry-run safe).
provision_composer_vendor() {
    _cv_dir=$1
    [ -x "$REPO_ROOT/$_cv_dir/vendor/bin/phpunit" ] && return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "dry-run: composer install --quiet --no-interaction ($_cv_dir)"
        return "$CI_EXIT_OK"
    fi
    ci_info "$_cv_dir: vendor/ absent — composer install (cached in the checkout after the first run)"
    (cd "$REPO_ROOT/$_cv_dir" && composer install --quiet --no-interaction) >>"$CI_STAGE_LOG" 2>&1 \
        || { ci_err "composer install failed in $_cv_dir"; return "$CI_EXIT_FAIL"; }
}

# --- 8. SDK lanes (python / go / java / ruby / php) ------------------------------------
# The five first-party SDKs previously had NO CI lane at all. Each lane is
# REQUIRED via CI_SDK_CHECK; the toolchain check fails closed on the deploy
# host and degrades to an explicit advisory skip nowhere else (see
# lane_tool_status). Python runs out of a dedicated cached venv — never the
# user site — so the lane cannot pollute a dev machine's packages.
run_sdk_tests() {
    # sdk-python: shared venv at CI_SDK_VENV_DIR (default
    # /tmp/apexmail-ci-sdks), created once, reused across runs; pytest +
    # pytest-asyncio (the pyproject sets asyncio_mode=auto) + the SDK's two
    # runtime deps (httpx, pydantic[email] — EmailStr needs the extra). The
    # suite imports the src/ layout via PYTHONPATH, so no editable install
    # of the moving checkout is needed (F47 wave: fresh venv → 59 passed).
    _py_venv="${CI_SDK_VENV_DIR:-/tmp/apexmail-ci-sdks}/venv-python"
    _st=$(lane_tool_status python3 sdk-python "${CI_SDK_CHECK:-required}")
    case $_st in
        fail) return "$CI_EXIT_FAIL" ;;
        run)
            provision_sdk_python_venv "$_py_venv" || return "$CI_EXIT_FAIL"
            (cd "$REPO_ROOT/packages/sdk-python" && \
                ci_check "sdk-python (pytest, venv $_py_venv)" \
                env PYTHONPATH=src "$_py_venv/bin/python" -m pytest -q) \
                || return "$CI_EXIT_FAIL"
            ;;
    esac

    _st=$(lane_tool_status go sdk-go "${CI_SDK_CHECK:-required}")
    case $_st in
        fail) return "$CI_EXIT_FAIL" ;;
        run)
            # go.mod has zero external requires — no module downloads.
            (cd "$REPO_ROOT/packages/sdk-go" && ci_check "sdk-go (go test ./...)" \
                go test ./...) || return "$CI_EXIT_FAIL"
            ;;
    esac

    _st=$(lane_tool_status mvn sdk-java "${CI_SDK_CHECK:-required}")
    case $_st in
        fail) return "$CI_EXIT_FAIL" ;;
        run)
            # First run downloads the jackson/jupiter deps into ~/.m2 (~minutes);
            # every later run is cached. -B: no color/progress spam in stage logs.
            (cd "$REPO_ROOT/packages/sdk-java" && ci_check "sdk-java (mvn -B test)" \
                mvn -q -B test) || return "$CI_EXIT_FAIL"
            ;;
    esac

    _st=$(lane_tool_status ruby sdk-ruby "${CI_SDK_CHECK:-required}")
    case $_st in
        fail) return "$CI_EXIT_FAIL" ;;
        run)
            # The contract suite is stdlib-only (F48 wave: 46 checks).
            (cd "$REPO_ROOT/packages/sdk-ruby" && \
                ci_check "sdk-ruby (payload contract suite)" \
                ruby test/payload_contract_test.rb) || return "$CI_EXIT_FAIL"
            ;;
    esac

    _st=$(lane_tool_status php sdk-php "${CI_SDK_CHECK:-required}")
    case $_st in
        fail) return "$CI_EXIT_FAIL" ;;
        run)
            _st=$(lane_tool_status composer sdk-php "${CI_SDK_CHECK:-required}")
            case $_st in
                fail) return "$CI_EXIT_FAIL" ;;
                run)
                    provision_composer_vendor packages/sdk-php || return "$CI_EXIT_FAIL"
                    (cd "$REPO_ROOT/packages/sdk-php" && ci_check "sdk-php (phpunit)" \
                        ./vendor/bin/phpunit) || return "$CI_EXIT_FAIL"
                    ;;
            esac
            ;;
    esac
    return "$CI_EXIT_OK"
}

# provision_sdk_python_venv <venv-path> — create the shared venv once and
# keep its deps satisfied (idempotent pip install; dry-run safe).
provision_sdk_python_venv() {
    _pv_venv=$1
    if [ ! -x "$_pv_venv/bin/python" ]; then
        if ci_dry; then
            ci_info "dry-run: python3 -m venv $_pv_venv"
            return "$CI_EXIT_OK"
        fi
        mkdir -p "$(dirname "$_pv_venv")"
        ci_info "creating the SDK test venv once at $_pv_venv (cached across runs)"
        python3 -m venv "$_pv_venv" >>"$CI_STAGE_LOG" 2>&1 \
            || { ci_err "python3 -m venv $_pv_venv failed"; return "$CI_EXIT_FAIL"; }
    fi
    if ci_dry; then
        ci_info "dry-run: pip install pytest pytest-asyncio httpx pydantic[email] into $_pv_venv"
        return "$CI_EXIT_OK"
    fi
    # Mirror packages/sdk-python/pyproject.toml: requires httpx>=0.25.0 and
    # pydantic[email]>=2.0.0; dev extras add pytest/pytest-asyncio. respx/
    # mypy/ruff are not exercised by this lane (the contract suite mocks
    # httpx transport in-process).
    "$_pv_venv/bin/python" -m pip install --quiet --disable-pip-version-check \
        'pytest>=7.0.0' 'pytest-asyncio>=0.21.0' 'httpx>=0.25.0' 'pydantic[email]>=2.0.0' \
        >>"$CI_STAGE_LOG" 2>&1 \
        || { ci_err "pip install into $_pv_venv failed (network?)"; return "$CI_EXIT_FAIL"; }
}

# --- 9. satellite Rust crates -----------------------------------------------------------
# packages/smtp-auth-proxy and packages/kiwicaptcha-wasm are NOT members of
# the services/mail-server workspace, so `cargo test --workspace` never
# touched them. Each is its own crate root (kiwicaptcha-wasm even declares
# its own [workspace]); cargo test from inside each directory builds only
# that graph.
run_satellite_crates() {
    _sc_st=$(lane_tool_status cargo satellite-crates "${CI_SATELLITE_CHECK:-required}")
    case $_sc_st in
        fail) return "$CI_EXIT_FAIL" ;;
        skip) return "$CI_EXIT_OK" ;;
    esac
    # smtp-auth-proxy path-depends on services/mail-server/crates/apexmail-lib
    # (first build compiles that slice of the graph).
    (cd "$REPO_ROOT/packages/smtp-auth-proxy" && \
        ci_check "cargo test packages/smtp-auth-proxy" cargo test --quiet) \
        || return "$CI_EXIT_FAIL"
    # kiwicaptcha-wasm pins its compiler via rust-toolchain.toml (1.96.0 +
    # wasm32 target). With a rustup-managed cargo (what ci/install.sh
    # installs) the proxy honors the pin and auto-installs that toolchain on
    # first use — the pin is the REQUIRED path, not an obstacle: it is what
    # keeps `cargo test` here reproducible. `cargo test` compiles the crate
    # for the HOST target (the wasm32 target is only needed for the cdylib
    # release build, which build.sh owns).
    (cd "$REPO_ROOT/packages/kiwicaptcha-wasm" && \
        ci_check "cargo test packages/kiwicaptcha-wasm" cargo test --quiet) \
        || return "$CI_EXIT_FAIL"
    return "$CI_EXIT_OK"
}

# --- 10. static lint gates -----------------------------------------------------------------
# Runs shellcheck over EVERY tracked *.sh, hadolint over every tracked
# Dockerfile (repo config .hadolint.yaml: failure-threshold=warning, inline
# ignores only), and a python compile gate over the audit tooling itself.
# All three REQUIRED via CI_STATIC_LINT_CHECK; findings are fixed at the
# source — the repo is clean at `shellcheck -S warning` and `hadolint`
# today, and these gates keep it that way.
run_static_lint_gates() {
    _sl_st=$(lane_tool_status shellcheck shellcheck-gate "${CI_STATIC_LINT_CHECK:-required}")
    case $_sl_st in
        run)
            # -S warning: error+warning findings fail; style/info stay visible
            # but advisory. -z/-0 pairing keeps paths with spaces safe.
            (cd "$REPO_ROOT" && ci_check "shellcheck -S warning (all tracked *.sh)" \
                sh -c 'git ls-files -z -- "*.sh" | xargs -0 shellcheck -S warning') \
                || return "$CI_EXIT_FAIL"
            ;;
        fail) return "$CI_EXIT_FAIL" ;;
    esac

    _sl_st=$(lane_tool_status hadolint hadolint-gate "${CI_STATIC_LINT_CHECK:-required}")
    case $_sl_st in
        run)
            (cd "$REPO_ROOT" && ci_check "hadolint (all tracked Dockerfiles, .hadolint.yaml)" \
                sh -c 'git ls-files -z -- "*Dockerfile*" | xargs -0 hadolint --config .hadolint.yaml') \
                || return "$CI_EXIT_FAIL"
            ;;
        fail) return "$CI_EXIT_FAIL" ;;
    esac

    _sl_st=$(lane_tool_status python3 python-compile-gate "${CI_STATIC_LINT_CHECK:-required}")
    case $_sl_st in
        run)
            # py_compile catches syntax errors in the audit tooling itself
            # (tools/, apps/ai/). PYTHONPYCACHEPREFIX keeps __pycache__ out of
            # the checkout; the rc accumulates across the while loop (which is
            # NOT in a pipeline subshell, so the status survives).
            (cd "$REPO_ROOT" && ci_check "python compile gate (tools/*.py apps/ai/**/*.py)" \
                sh -c '_pc_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-pyc.XXXXXX") || exit 1
export PYTHONPYCACHEPREFIX=$_pc_tmp
_pc_lst=$_pc_tmp/files
git ls-files -- "tools/*.py" "apps/ai/**/*.py" >"$_pc_lst" || { rm -rf "$_pc_tmp"; exit 1; }
_pc_rc=0
while IFS= read -r _pc_f; do
    python3 -m py_compile "$_pc_f" || _pc_rc=1
done <"$_pc_lst"
rm -rf "$_pc_tmp"
exit $_pc_rc') \
                || return "$CI_EXIT_FAIL"
            ;;
        fail) return "$CI_EXIT_FAIL" ;;
    esac
    return "$CI_EXIT_OK"
}

# --- 8. WCAG AA contrast gate -----------------------------------------------------------
# Pixel-confirmed contrast gate (tools/contrast-audit/gate.sh → audit.mjs
# --gate): console + control-plane fixtures in all three themes plus the
# marketing top-20, zero AA text failures required. F52: the gate is
# REQUIRED by default — missing node / gate script / playwright on a
# required runner is a stage FAILURE (the ci_have_tool fail-closed
# pattern), never a silent skip; the only opt-out is the explicit
# CI_CONTRAST_GATE_CHECK=advisory. audit.mjs --gate additionally runs its
# own classifier self-test fixtures BEFORE certifying real pages (a
# white-on-opaque-white-gradient must fail, a good gradient must pass,
# sticky headers must be measured via element screenshots), and gate.sh
# persists an executed/skipped/failed execution record bound to the
# reviewed revision next to the report
# (tools/contrast-audit/reports/gate-execution.json).
_contrast_gate_record() {
    # F52: persist a result bound to the reviewed revision for the
    # prerequisite outcomes where gate.sh itself never ran (it writes the
    # executed/failed records on the paths it owns).
    _cgr_status=$1
    _cgr_detail=$2
    _cgr_dir=$REPO_ROOT/tools/contrast-audit/reports
    mkdir -p "$_cgr_dir" 2>/dev/null || return 0
    _cgr_rev=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
    _cgr_dirty=false
    [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 2>/dev/null)" ] && _cgr_dirty=true
    printf '{\n "tool": "ci/stages/test.sh:run_contrast_gate",\n "gate": "wcag-aa-contrast",\n "revision": "%s",\n "dirtyWorkingTree": %s,\n "status": "%s",\n "detail": "%s",\n "recordedAt": "%s"\n}\n' \
        "$_cgr_rev" "$_cgr_dirty" "$_cgr_status" "$_cgr_detail" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >"$_cgr_dir/gate-execution.json" 2>/dev/null || true
}

run_contrast_gate() {
    _cg_missing=''
    command -v node >/dev/null 2>&1 || _cg_missing='node missing'
    if [ -z "$_cg_missing" ] && [ ! -x "$REPO_ROOT/tools/contrast-audit/gate.sh" ]; then
        _cg_missing='tools/contrast-audit/gate.sh missing'
    fi
    if [ -z "$_cg_missing" ] && [ ! -d "$REPO_ROOT/tools/contrast-audit/node_modules/playwright" ]; then
        _cg_missing="tools/contrast-audit/node_modules (playwright) missing — run '(cd tools/contrast-audit && npm install)'"
    fi
    if [ -n "$_cg_missing" ]; then
        if [ "${CI_CONTRAST_GATE_CHECK:-required}" = advisory ]; then
            ci_warn "ADVISORY: $_cg_missing — WCAG contrast gate skipped (CI_CONTRAST_GATE_CHECK=advisory)"
            _contrast_gate_record skipped "$_cg_missing"
            return "$CI_EXIT_OK"
        fi
        ci_err "$_cg_missing — WCAG contrast gate REQUIRED \
(provision the browser toolchain via ci/install.sh, or set CI_CONTRAST_GATE_CHECK=advisory to disable this gate explicitly)"
        _contrast_gate_record failed "$_cg_missing"
        return "$CI_EXIT_FAIL"
    fi
    (cd "$REPO_ROOT" && ci_check "WCAG AA contrast gate (tools/contrast-audit/gate.sh)" \
        sh tools/contrast-audit/gate.sh) || { ci_err "contrast gate FAILED — see tools/contrast-audit/reports/gate-report.json"; return "$CI_EXIT_FAIL"; }
    return "$CI_EXIT_OK"
}

# --- 8b. Layout-spill + tag-balance gates ------------------------------------------------
# tools/contrast-audit/layout-gate.sh drives every console/CP fixture and
# marketing page at desktop AND mobile widths in all themes, failing on
# document horizontal overflow, content past the viewport, text escaping its
# box, cut-off text, invisible text, broken images, or overlapping cards —
# the defect class browsers silently repair (the CP header-tag bug).
# tools/contrast-audit/tag-balance.py strict-closure-checks every built page
# so an unclosed tag can never again swallow the rest of the document.
# Both self-provision their inputs exactly like the contrast gate.
# F52: both gates here are REQUIRED, and their prerequisites differ. The
# tag-balance gate needs only python3 (no browser toolchain), so it runs
# FIRST and unconditionally — the old node/playwright early-returns let BOTH
# gates pass silently on a runner without the browser stack, tag-balance
# included. For the layout-spill gate a missing browser toolchain is missing
# infrastructure for a required gate: a stage FAILURE with the provisioning
# hint, never a silent skip (matching layout-gate.sh's own loud-failure
# contract). The only intentional opt-out is explicit:
# CI_LAYOUT_GATE_CHECK=advisory. (The WCAG contrast gate above loud-skips by
# design on browser-less runners and is unaffected.)
run_layout_gates() {
    # tag-balance first: pure python3 over the built fixtures/marketing pages,
    # so no browser-toolchain prerequisite can ever skip it (and a
    # layout-spill failure cannot mask it).
    if command -v python3 >/dev/null 2>&1; then
        (cd "$REPO_ROOT" && ci_check "tag-balance gate (tag-balance.py)" \
            python3 tools/contrast-audit/tag-balance.py) || { ci_err "tag-balance gate FAILED — see per-page output above"; return "$CI_EXIT_FAIL"; }
    elif [ "${CI_LAYOUT_GATE_CHECK:-required}" = required ]; then
        ci_err "python3 missing — tag-balance gate REQUIRED \
(install python3, or set CI_LAYOUT_GATE_CHECK=advisory to disable this gate explicitly)"
        return "$CI_EXIT_FAIL"
    else
        ci_warn "ADVISORY: python3 missing — tag-balance gate skipped (CI_LAYOUT_GATE_CHECK=advisory)"
    fi
    # layout-spill gate: node + playwright required — absent toolchain fails.
    _lg_missing=''
    command -v node >/dev/null 2>&1 || _lg_missing='node missing'
    if [ -z "$_lg_missing" ] && [ ! -d "$REPO_ROOT/tools/contrast-audit/node_modules/playwright" ]; then
        _lg_missing="tools/contrast-audit/node_modules (playwright) missing — run '(cd tools/contrast-audit && npm install)'"
    fi
    if [ -z "$_lg_missing" ]; then
        (cd "$REPO_ROOT" && ci_check "layout-spill gate (tools/contrast-audit/layout-gate.sh)" \
            sh tools/contrast-audit/layout-gate.sh) || { ci_err "layout gate FAILED — see tools/contrast-audit/reports/layout/violations.json"; return "$CI_EXIT_FAIL"; }
    elif [ "${CI_LAYOUT_GATE_CHECK:-required}" = required ]; then
        ci_err "$_lg_missing — layout-spill gate REQUIRED \
(provision the browser toolchain, or set CI_LAYOUT_GATE_CHECK=advisory to disable this gate explicitly)"
        return "$CI_EXIT_FAIL"
    else
        ci_warn "ADVISORY: $_lg_missing — layout-spill gate skipped (CI_LAYOUT_GATE_CHECK=advisory)"
    fi
}

# --- 8c. i18n completeness gate ----------------------------------------------------------
# tools/i18n-audit.py enforces the localization contract: i18n.json key parity
# across de/fr/es, every template-referenced key present and non-empty, no
# value equal to its English default (untranslated prose), no mixed-language
# links on locale pages, and every template-linked page carrying all three
# translations. Requires the marketing site to be built (self-provisions via
# zola build when zola is present, mirroring the other marketing gates).
run_i18n_gate() {
    command -v python3 >/dev/null 2>&1 || { ci_warn "python3 missing — i18n gate skipped"; return "$CI_EXIT_OK"; }
    [ -f "$REPO_ROOT/apps/marketing-zola/data/i18n.json" ] || { ci_warn "marketing i18n data missing — i18n gate skipped"; return "$CI_EXIT_OK"; }
    if [ ! -f "$REPO_ROOT/apps/marketing-zola/public/index.html" ]; then
        command -v zola >/dev/null 2>&1 || { ci_warn "marketing public/ not built and zola missing — i18n gate skipped"; return "$CI_EXIT_OK"; }
        (cd "$REPO_ROOT/apps/marketing-zola" && zola build >/dev/null 2>&1) || { ci_err "zola build failed for i18n gate"; return "$CI_EXIT_FAIL"; }
    fi
    (cd "$REPO_ROOT" && ci_check "i18n completeness gate (tools/i18n-audit.py)" \
        python3 tools/i18n-audit.py) || { ci_err "i18n gate FAILED — see output above"; return "$CI_EXIT_FAIL"; }
}

# --- formatting gate ------------------------------------------------------------
# cargo fmt --check is NEW compared to rust-check.yml (GitHub never ran it).
# The tree currently carries committed fmt drift (README §9 F7), so the gate
# defaults to ADVISORY — it records the full diff in the run dir and the first
# 300 lines in the stage log without failing the run. Set CI_FMT_CHECK=required
# (pipeline.conf) once `cargo fmt` has landed on main.
fmt_gate() {
    if ci_dry; then
        ci_info "check (dry-run): cargo fmt --check"
        return "$CI_EXIT_OK"
    fi
    _fmt_rc=0
    (cd "$WS" && cargo fmt --check >"$RUN_DIR/fmt-check.diff" 2>&1) || _fmt_rc=$?
    if [ "$_fmt_rc" -eq 0 ]; then
        ci_info "PASS: cargo fmt --check"
        return "$CI_EXIT_OK"
    fi
    head -n 300 "$RUN_DIR/fmt-check.diff" >>"$CI_STAGE_LOG" 2>/dev/null || true
    _fmt_files=$(grep -c '^Diff in' "$RUN_DIR/fmt-check.diff" 2>/dev/null || printf '?')
    if [ "${CI_FMT_CHECK:-advisory}" = required ]; then
        ci_err "FAIL: cargo fmt --check ($_fmt_files files need formatting; full diff: $RUN_DIR/fmt-check.diff)"
        return "$CI_EXIT_FAIL"
    fi
    ci_warn "ADVISORY: cargo fmt --check reports drift in $_fmt_files files \
(full diff: $RUN_DIR/fmt-check.diff) — set CI_FMT_CHECK=required after running cargo fmt"
    return "$CI_EXIT_OK"
}

# --- clippy gate -------------------------------------------------------------------
# Same lane as rust-check.yml (`--workspace --all-targets -D warnings`). The
# tree currently carries drift against a current toolchain (README §9 F8),
# so like fmt the gate records the full log and defaults to ADVISORY; set
# CI_CLIPPY_CHECK=required once the tree is clippy-clean.
clippy_gate() {
    if ci_dry; then
        ci_info "check (dry-run): cargo clippy -D warnings"
        return "$CI_EXIT_OK"
    fi
    _cl_rc=0
    (cd "$WS" && cargo clippy --workspace --all-targets -- -D warnings \
        >"$RUN_DIR/clippy-check.log" 2>&1) || _cl_rc=$?
    if [ "$_cl_rc" -eq 0 ]; then
        ci_info "PASS: cargo clippy -D warnings"
        return "$CI_EXIT_OK"
    fi
    _cl_n=$(grep -c '^error' "$RUN_DIR/clippy-check.log" 2>/dev/null || printf '?')
    tail -n 120 "$RUN_DIR/clippy-check.log" >>"$CI_STAGE_LOG" 2>/dev/null || true
    if [ "${CI_CLIPPY_CHECK:-advisory}" = required ]; then
        ci_err "FAIL: cargo clippy -D warnings ($_cl_n errors; full log: $RUN_DIR/clippy-check.log)"
        return "$CI_EXIT_FAIL"
    fi
    ci_warn "ADVISORY: cargo clippy -D warnings reports $_cl_n errors \
(full log: $RUN_DIR/clippy-check.log) — set CI_CLIPPY_CHECK=required once clean"
    return "$CI_EXIT_OK"
}

stage_main() {
    ensure_marketing_output

    fmt_gate
    clippy_gate

    if command -v python3 >/dev/null 2>&1; then
        (cd "$REPO_ROOT" && ci_check "workspace dependency cycles" python3 tools/check_cargo_cycles.py)
        (cd "$REPO_ROOT" && ci_check "security feature flags" python3 tools/validate_security_feature_flags.py)
        # WS-ALL audit-coverage ledger: currently lists removed crates
        # (bounce-analytics — README §9 F9), so it reports rather than
        # blocks until the ledger is fixed.
        if ci_dry; then
            ci_info "check (dry-run): WS-ALL audit coverage ledger"
        else
            _ac_rc=0
            (cd "$REPO_ROOT" && python3 tools/check_audit_coverage.py \
                >"$RUN_DIR/audit-coverage.log" 2>&1) || _ac_rc=$?
            if [ "$_ac_rc" -eq 0 ]; then
                ci_info "PASS: WS-ALL audit coverage ledger"
            elif [ "${CI_AUDIT_COVERAGE_CHECK:-advisory}" = required ]; then
                cat "$RUN_DIR/audit-coverage.log" >>"$CI_STAGE_LOG" 2>/dev/null || true
                ci_err "FAIL: WS-ALL audit coverage ledger (see $RUN_DIR/audit-coverage.log)"
                return "$CI_EXIT_FAIL"
            else
                cat "$RUN_DIR/audit-coverage.log" >>"$CI_STAGE_LOG" 2>/dev/null || true
                ci_warn "ADVISORY: audit coverage ledger drift (log: $RUN_DIR/audit-coverage.log) — fix the ledger, then CI_AUDIT_COVERAGE_CHECK=required"
            fi
        fi
    else
        ci_warn "python3 missing — repo python gates skipped"
    fi

    cargo_tool_gates
    run_cargo_tests
    run_coverage_gate
    run_php_tests
    run_static_lint_gates
    run_sdk_tests
    run_satellite_crates
    run_contrast_gate
    run_layout_gates
    run_i18n_gate

    ci_ephem_cleanup
    ci_info "test: all suites green"
    return "$CI_EXIT_OK"
}

trap 'ci_ephem_cleanup' EXIT
stage_main
