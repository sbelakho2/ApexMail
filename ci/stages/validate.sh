#!/bin/sh
# =============================================================================
# ci/stages/validate.sh — stage 2: static validation gates.
# =============================================================================
# Replaces (see ci/README.md for the full map):
#   * deploy-hetzner.yml "Validate APEXMAIL_PROD_ENV"  (tools/validate-prod-env.sh)
#   * deploy.yml "deploy-image-name-guard"            (compose image drift)
#   * sqlx-migration-validation.yml's config-level half (fresh-DB apply is in
#     the security stage)
#   * rust-panic-paths.yml, kiwi-leak-check.yml, legal-identity.yml,
#     pricing-drift.yml, regression_checks.yml, release-gates.yml (zola build,
#     legal constants, rollback doc), html-validation.yml, accessibility-check.yml,
#     seo-audit.yml (advisory), claim-expiry-check.yml (advisory)
#
# Sections (each independent; a hard failure stops the stage):
#   2.1 host env file validation   — skipped on a fresh checkout (no env file)
#   2.2 compose config -q          — base+prod with a generated dummy env
#   2.3 pipeline-config sanity     — ci/ stage contract + README replacement
#                                    map covers every .github workflow
#   2.4 repo gates                 — the cheap PR gates listed above
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

# --- 2.1 host env file -----------------------------------------------------------
# Production env validation. Defaults:
#   * deploy host → $CI_DEPLOY_DIR/.env (THE production env file)
#   * elsewhere   → $REPO_ROOT/.env.production when present (tools'
#                   default name), else SKIPPED — never the DEV .env, which
#                   legitimately contains dev placeholders.
# Set CI_ENV_FILE to validate any explicit file; CI_ENV_STRICT=1 makes a
# missing file fatal (the pipeline then refuses to deploy blind).
validate_env_file() {
    _envf=${CI_ENV_FILE:-}
    if [ -z "$_envf" ]; then
        if ci_on_deploy_host; then
            _envf=$CI_DEPLOY_DIR/.env
        elif [ -f "$REPO_ROOT/.env.production" ]; then
            _envf=$REPO_ROOT/.env.production
        fi
    fi
    if [ -z "$_envf" ] || [ ! -f "$_envf" ]; then
        if [ "${CI_ENV_STRICT:-0}" = 1 ]; then
            ci_die "no production env file found and CI_ENV_STRICT=1"
        fi
        ci_info "no production env file (fresh checkout / dev machine) — env validation skipped"
        return "$CI_EXIT_OK"
    fi
    if ci_on_deploy_host; then
        ci_check "validate-prod-env $_envf" \
            sh "$REPO_ROOT/tools/validate-prod-env.sh" "$_envf"
    else
        # The PROD_*_FILE targets live on the HOST; off-host only the values
        # are checked (same SKIP_FILE_CHECK=1 the GitHub runner used).
        ci_check "validate-prod-env $_envf (values only)" \
            env SKIP_FILE_CHECK=1 sh "$REPO_ROOT/tools/validate-prod-env.sh" "$_envf"
    fi
}

# --- 2.2 compose config with a dummy env ---------------------------------------------
# Generates an env file where every ${VAR:?} guard is satisfied with a dummy
# value (plus every PROD_*_FILE pointing at a temp file) and asks compose to
# render the merged config. Catches YAML/interpolation drift without secrets.
validate_compose() {
    command -v docker >/dev/null 2>&1 \
        || { ci_warn "docker CLI missing — compose config check skipped"; return "$CI_EXIT_OK"; }
    _dummy_dir=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-dummyenv.XXXXXX")
    _dummy_env=$_dummy_dir/env
    _guards=$(grep -ohE '\$\{[A-Z0-9_]+:\?' \
        "$REPO_ROOT/docker-compose.yml" "$REPO_ROOT/docker-compose.prod.yml" 2>/dev/null \
        | grep -oE '[A-Z0-9_]+:' | tr -d ':' | sort -u || true)
    for _v in $_guards; do
        case $_v in
            *_FILE) printf '%s=%s\n' "$_v" "$_dummy_dir/secret" ;;
            *)      printf '%s=ci-dummy-value\n' "$_v" ;;
        esac
    done >"$_dummy_env"
    : >"$_dummy_dir/secret"
    ci_info "compose config -q with dummy env ($(grep -c . "$_dummy_env") guarded vars)"
    _cc_rc=0
    (cd "$REPO_ROOT" && docker compose -f docker-compose.yml -f docker-compose.prod.yml \
        --env-file "$_dummy_env" config -q) >>"$CI_STAGE_LOG" 2>&1 || _cc_rc=$?
    rm -rf "$_dummy_dir"
    if [ "$_cc_rc" -ne 0 ]; then
        ci_err "docker compose config failed (see log above)"
        return "$_cc_rc"
    fi
    ci_info "PASS: compose config renders (base + prod overlay)"
    return "$CI_EXIT_OK"
}

# --- 2.3 pipeline-config sanity -----------------------------------------------------
# The successor of "is the workflow YAML valid": the pipeline is only as good
# as its own configuration, so validate stage contracts, timeouts, and that
# the README replacement map covers EVERY file in .github/workflows/.
validate_pipeline_config() {
    _vp_err=0
    for _st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        _s="$CI_ROOT/stages/$_st.sh"
        [ -x "$_s" ] || { ci_err "stage script missing/not executable: $_s"; _vp_err=1; }
        grep -q 'stage_main' "$_s" 2>/dev/null || { ci_err "no stage_main in $_s"; _vp_err=1; }
        eval "_vp_t=\${CI_TIMEOUT_$_st:-}"
        case $_vp_t in
            ''|*[!0-9]*) ci_err "CI_TIMEOUT_$_st not a number: '$_vp_t'"; _vp_err=1 ;;
        esac
    done
    [ -f "$CI_ROOT/install.sh" ] || { ci_err "ci/install.sh missing"; _vp_err=1; }
    [ -f "$CI_ROOT/units/apexmail-pipeline.service" ] || { ci_err "systemd unit missing"; _vp_err=1; }
    [ -f "$CI_ROOT/units/apexmail-pipeline.timer" ] || { ci_err "systemd timer missing"; _vp_err=1; }

    # Replacement map must account for every workflow file.
    if [ -d "$REPO_ROOT/.github/workflows" ]; then
        for _wf in "$REPO_ROOT"/.github/workflows/*.yml "$REPO_ROOT"/.github/workflows/*.yaml; do
            [ -f "$_wf" ] || continue
            _wfb=$(basename "$_wf")
            if ! grep -q "$_wfb" "$CI_ROOT/README.md" 2>/dev/null; then
                ci_err "workflow '$_wfb' has no row in ci/README.md replacement map"
                _vp_err=1
            fi
        done
    fi
    [ "$_vp_err" -eq 0 ] || return "$CI_EXIT_FAIL"
    ci_info "PASS: pipeline config sane; README map covers all workflows"
    return "$CI_EXIT_OK"
}

# --- 2.4 repo gates --------------------------------------------------------------------
validate_repo_gates() {
    cd "$REPO_ROOT"

    # (a) compose image-name drift guard — port of deploy.yml's
    #     deploy-image-name-guard job (canonical map from deploy/DEPLOYMENT.md).
    image_name_guard || return "$CI_EXIT_FAIL"

    # (b) brand/product isolation (kiwi-leak-check.yml).
    ci_check "kiwi marketing isolation" bash tools/check-kiwi-marketing-isolation.sh

    # (c) panic-path guardrails (rust-panic-paths.yml).
    if command -v python3 >/dev/null 2>&1; then
        ci_check "rust panic paths" python3 tools/check_rust_panic_paths.py
        ci_check "outbound delivery contract" python3 tools/check_outbound_delivery_contract.py
    else
        ci_warn "python3 missing — panic-path guardrails skipped"
    fi

    # (c2) migration SQL lint (enterprise conventions — NEW 2026-09-10):
    # tools/migration_lint.py enforces the chain's idempotency/transaction
    # conventions (IF EXISTS/IF NOT EXISTS or existence guards, Migration N
    # headers, no GRANT ALL/TRUNCATE/explicit COMMIT/CONCURRENTLY).
    # Legacy files recorded in the production _sqlx_migrations ledger are
    # checksum-frozen (editing even a comment breaks sqlx's VersionMismatch
    # validation on the deploy host) — they are grandfathered inside the
    # checker with justifications, NOT edited. CI_MIGRATION_LINT_CHECK
    # downgrades to advisory for a triage window.
    if command -v python3 >/dev/null 2>&1; then
        _ml_rc=0
        (cd "$REPO_ROOT" && ci_check "migration SQL lint (tools/migration_lint.py)" \
            python3 tools/migration_lint.py) || _ml_rc=$?
        if [ "$_ml_rc" -ne 0 ] && [ "${CI_MIGRATION_LINT_CHECK:-required}" = advisory ]; then
            ci_warn "ADVISORY: migration SQL lint reported violations (CI_MIGRATION_LINT_CHECK=advisory)"
        elif [ "$_ml_rc" -ne 0 ]; then
            return "$CI_EXIT_FAIL"
        fi
    else
        ci_warn "python3 missing — migration SQL lint skipped"
    fi

    # (d) legal identity constants (legal-identity.yml rust-legal-entity job,
    #     release-gates.yml legal-identity job).
    legal_constants || return "$CI_EXIT_FAIL"

    # (e) regression_checks.yml: obsolete registry codes + fixes.md evidence.
    regression_gates || return "$CI_EXIT_FAIL"

    # (f) rollback documentation exists (release-gates.yml rollback job).
    ci_check "rollback plan present" test -s deploy/rollback-plan.md

    # (g) claim expiry — advisory (monthly cadence upstream).
    command -v python3 >/dev/null 2>&1 && \
        ci_check_advisory "claim expiry (warn 30d)" python3 tools/check_claim_expiry.py --warn-days 30

    # (h) zola-dependent gates: build the marketing site once, then run the
    #     pricing drift (REQUIRED — a deploy.yml pr-gate check), legal identity
    #     over the built HTML, and the advisory html/a11y/seo validators
    #     (html-validation.yml, accessibility-check.yml, seo-audit.yml).
    zola_gates
}

image_name_guard() {
    _canonical="api-server mta imap-server mailstore worker enterprise tracking-service
                observability marketing status-server billing-service sales-autopilot
                compliance analytics-worker pdf-renderer ai-service migrator"
    _third_party="nginx: certbot/certbot: prodrigestivill/postgres-backup-local:
                 postgres: redis: clickhouse/clickhouse-server:"
    _errs=0
    _refs=$(grep -hE '^[[:space:]]*image:[[:space:]]' \
        "$REPO_ROOT/docker-compose.yml" "$REPO_ROOT/docker-compose.prod.yml" 2>/dev/null \
        | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/^["'"'"']//; s/["'"'"']$//' | sort -u || true)
    for _ref in $_refs; do
        _skip=0
        for _tp in $_third_party; do
            case $_ref in
                "$_tp"*) _skip=1; break ;;
            esac
        done
        [ "$_skip" = 1 ] && continue
        case $_ref in
            ghcr.io/*)
                _base=${_ref##*/}
                _base=${_base%%:*}
                _found=0
                for _c in $_canonical; do
                    [ "$_base" = "$_c" ] && { _found=1; break; }
                done
                if [ "$_found" = 0 ]; then
                    ci_err "non-canonical GHCR image: $_ref (basename '$_base')"
                    _errs=$((_errs + 1))
                fi
                case $_ref in
                    :v[0-9]*)
                        ci_err "version tag in $_ref — only :latest/:<sha> are produced (deploy/DEPLOYMENT.md)"
                        _errs=$((_errs + 1))
                        ;;
                esac
                ;;
        esac
    done
    for _c in $_canonical; do
        if ! grep -qE "image:.*[/:]${_c}(:latest|:[0-9a-f]{7,40])?[[:space:]]*$" \
            "$REPO_ROOT/docker-compose.prod.yml" 2>/dev/null \
            && ! grep -qE "image:.*[/:]${_c}:" "$REPO_ROOT/docker-compose.prod.yml" 2>/dev/null; then
            ci_err "canonical service '$_c' has no image reference in docker-compose.prod.yml"
            _errs=$((_errs + 1))
        fi
    done
    [ "$_errs" -eq 0 ] || return "$CI_EXIT_FAIL"
    ci_info "PASS: compose image references are canonical"
    return "$CI_EXIT_OK"
}

legal_constants() {
    _legal_rs=services/mail-server/crates/compliance/src/legal_entity.rs
    _fields="LEGAL_NAME TRADING_NAME REGISTRY_CODE VAT_NUMBER ADDRESS COUNTRY COUNTRY_CODE
             JURISDICTION GOVERNING_LAW SUPPORT_EMAIL PRIVACY_EMAIL SECURITY_EMAIL
             BILLING_EMAIL DPO_CONTACT COPYRIGHT_ENTITY COPYRIGHT_START_YEAR FOUNDING_DATE"
    _lc_err=0
    for _f in $_fields; do
        grep -q "pub const ${_f}:" "$_legal_rs" || { ci_err "MISSING legal constant: $_f"; _lc_err=1; }
    done
    [ "$_lc_err" -eq 0 ] || return "$CI_EXIT_FAIL"
    ci_info "PASS: all legal entity constants present"
    return "$CI_EXIT_OK"
}

# Tracked-file grep: on GitHub these scans ran against a fresh checkout, so
# only git-tracked files existed. Locally, untracked junk (.tmp/, .venv/,
# node_modules, public/ build output) must not pollute results — use git
# grep when possible, else grep -r with explicit excludes.
# Usage: tracked_grep <pattern> ['*.glob' …] [path …]
tracked_grep() {
    _tg_pat=$1
    shift
    _tg_inc=''
    _tg_paths=''
    for _a in "$@"; do
        case $_a in
            --) ;;
            \*.*) _tg_inc="$_tg_inc $_a" ;;
            *)    _tg_paths="$_tg_paths $_a" ;;
        esac
    done
    if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        # git pathspecs OR together; a bare '.' would cancel the glob filters,
        # so only default to '.' when neither globs nor paths were given.
        if [ -z "$_tg_inc" ] && [ -z "$_tg_paths" ]; then
            _tg_paths='.'
        fi
        # shellcheck disable=SC2086  # git pathspecs/globs are word lists
        git -C "$REPO_ROOT" grep -I -l -e "$_tg_pat" -- $_tg_paths $_tg_inc 2>/dev/null || true
    else
        _tg_cmd='grep -r -I -l'
        for _a in $_tg_inc; do _tg_cmd="$_tg_cmd --include=$_a"; done
        for _d in .git .tmp .venv node_modules public target vendor; do
            _tg_cmd="$_tg_cmd --exclude-dir=$_d"
        done
        [ -n "$_tg_paths" ] || _tg_paths='.'
        # shellcheck disable=SC2086  # intended word lists
        $_tg_cmd -e "$_tg_pat" $_tg_paths 2>/dev/null || true
    fi
}

regression_gates() {
    # obsolete registry codes (fixes.md history + reports/ snapshots excluded)
    _rg_err=0
    for _code in 16192499 16942833; do
        _found=$(tracked_grep "$_code" '*.rs' '*.toml' '*.json' '*.html' '*.yaml' '*.md' \
            | grep -v '^fixes\.md$' | grep -v '^reports/' | grep -v '^ci/' | head -10 || true)
        [ -n "$_found" ] && { ci_err "obsolete registry code $_code in: $_found"; _rg_err=1; }
    done
    # fixes.md evidence for completed items
    if command -v python3 >/dev/null 2>&1 && [ -f fixes.md ]; then
        python3 - fixes.md >>"$CI_STAGE_LOG" 2>&1 <<'PYEOF' || _rg_err=1
import re, sys
content = open(sys.argv[1]).read()
errors = []
for item in re.findall(r'\* \[x\].*', content):
    chunk = content.split(item, 1)
    if len(chunk) > 1 and 'Evidence:' not in chunk[1][:200]:
        errors.append(item.strip()[:80])
if errors:
    for e in errors:
        print(f'MISSING EVIDENCE: {e}')
    sys.exit(1)
print('fixes.md: all completed items carry evidence')
PYEOF
    fi
    # prohibited marketing claims + placeholder scans — advisory upstream
    prohibited_claims || true
    [ "$_rg_err" -eq 0 ] || return "$CI_EXIT_FAIL"
    ci_info "PASS: registry codes + fixes.md evidence"
    return "$CI_EXIT_OK"
}

# Multi-word patterns use underscores (word-split-proof); they are translated
# to spaces before matching. Only the first 10 hits per claim are logged.
prohibited_claims() {
    _claims="100%_GDPR_compliant System_Integrity_Verified 99.9%_delivery_rate
             Guaranteed_inbox_placement Deterministic_deliverability HIPAA_Ready
             global_edge zero_egress sub-millisecond No_tenant_jitter
             Fixed_thirty-day_warm-up Entirely_in_your_hands"
    for _claim in $_claims; do
        _c=$(printf '%s' "$_claim" | tr '_' ' ')
        _found=$(tracked_grep "$_c" '*.html' '*.md' '*.yaml' '*.json' -- \
            'apps/marketing-zola' 'docs' 'deploy' 2>/dev/null | head -10 || true)
        [ -n "$_found" ] && ci_warn "ADVISORY prohibited claim '$_c' in:$(printf '\n%s' "$_found" | tr '\n' ' ')"
    done
    _pats='response_would_contain TODO:_implement FIXME:'
    for _p in $_pats; do
        _pt=$(printf '%s' "$_p" | tr '_' ' ')
        _found=$(tracked_grep "$_pt" '*.rs' '*.html' -- 'services/mail-server/src' 'apps' 2>/dev/null \
            | head -10 || true)
        [ -n "$_found" ] && ci_warn "ADVISORY placeholder text '$_pt' in:$(printf '\n%s' "$_found" | tr '\n' ' ')"
    done
    return "$CI_EXIT_OK"
}

zola_gates() {
    if ! command -v zola >/dev/null 2>&1; then
        if [ "${CI_ZOLA_REQUIRED:-0}" = 1 ]; then
            ci_die "zola missing and CI_ZOLA_REQUIRED=1 — install zola (ci/install.sh)"
        fi
        ci_warn "zola missing — marketing gates (pricing drift, legal HTML, a11y/seo) skipped"
        return "$CI_EXIT_OK"
    fi
    if ci_dry; then
        ci_info "dry-run: zola build + marketing gates"
        return "$CI_EXIT_OK"
    fi
    ci_info "building marketing site (zola)"
    # rm -rf public first: zola only cleans orphan outputs on 0.22+; on
    # older host zolas deleted pages linger in public/ and fail the
    # forbidden-pattern gate with stale content.
    (cd apps/marketing-zola && rm -rf public && zola build) >>"$CI_STAGE_LOG" 2>&1 \
        || { ci_err "zola build failed"; return "$CI_EXIT_FAIL"; }
    [ -f apps/marketing-zola/public/index.html ] || { ci_err "zola build produced no index.html"; return "$CI_EXIT_FAIL"; }

    # Forbidden patterns (legal-identity.yml forbidden-patterns job): scans
    # the BUILT output, so it must run AFTER the zola build — it previously
    # ran earlier against whatever stale public/ was lying around.
    ci_check "forbidden patterns" bash tools/check-forbidden-patterns.sh

    # template-leak gate over the committed/built output (deploy.yml pre-build)
    ci_check "template leaks (marketing public/)" \
        bash deploy/scripts/check-template-leaks.sh apps/marketing-zola/public

    # pricing drift — REQUIRED (one of deploy.yml's pr-gate required checks)
    if command -v python3 >/dev/null 2>&1; then
        ci_check "pricing drift" python3 tools/validate_pricing_drift.py
        ci_check "legal identity (built HTML)" \
            python3 tools/validate_legal_identity.py --build-dir apps/marketing-zola/public
    fi

    # Site-quality validators (html-validation / accessibility / seo — F14).
    # (They are not +x in the tree — the workflows chmod'ed them; use bash.)
    #
    # Gate wiring (F14): each script WRITES a JSON report next to itself
    # (.contrast-check-report.json / .html-validation-report.json /
    # .seo-validation-report.json) AND exits non-zero when it records
    # critical violations — the enforcement exists at the script level. This
    # stage additionally:
    #   * HARD-FAILS when a validator ran but produced no report (the
    #     artifact contract) and preserves every report under $RUN_DIR;
    #   * enforces the scripts' exit codes (ci_check, non-zero exit on
    #     violations) when CI_MARKETING_VALIDATION=required. Default is
    #     `advisory`: these are heuristic grep/awk checkers with a known
    #     false-positive backlog on the current marketing build, and the
    #     AUTHORITATIVE pixel-verified a11y gate is
    #     tools/contrast-audit/gate.sh (REQUIRED, ci/stages/test.sh).
    BUILD_DIR=apps/marketing-zola/public
    _mv_gate() {
        _mvg_script=$1 _mvg_label=$2 _mvg_report=$3
        _mvg_rc=0
        if [ "$CI_MARKETING_VALIDATION" = required ]; then
            ci_check "$_mvg_label" env BUILD_DIR=$BUILD_DIR bash "deploy/tests/$_mvg_script" \
                || _mvg_rc=$CI_EXIT_FAIL
        else
            ci_check_advisory "$_mvg_label" env BUILD_DIR=$BUILD_DIR bash "deploy/tests/$_mvg_script"
        fi
        if [ -f "deploy/tests/$_mvg_report" ]; then
            cp "deploy/tests/$_mvg_report" "$RUN_DIR/$_mvg_report" \
                && ci_info "report artifact: $RUN_DIR/$_mvg_report"
        else
            ci_err "validator $_mvg_script produced no report (deploy/tests/$_mvg_report) — the artifact contract is broken"
            return "$CI_EXIT_FAIL"
        fi
        return "$_mvg_rc"
    }
    [ -f deploy/tests/contrast-check.sh ] && { _mv_gate contrast-check.sh "WCAG contrast (heuristic)" .contrast-check-report.json || return "$CI_EXIT_FAIL"; }
    [ -f deploy/tests/html-validate.sh ] && { _mv_gate html-validate.sh "HTML validation" .html-validation-report.json || return "$CI_EXIT_FAIL"; }
    [ -f deploy/tests/seo-validate.sh ] && { _mv_gate seo-validate.sh "SEO validation" .seo-validation-report.json || return "$CI_EXIT_FAIL"; }
    return "$CI_EXIT_OK"
}

stage_main() {
    validate_env_file
    validate_compose
    validate_pipeline_config
    validate_repo_gates
    ci_info "validate: all gates green"
    return "$CI_EXIT_OK"
}

stage_main
