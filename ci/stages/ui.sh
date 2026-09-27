#!/bin/sh
# =============================================================================
# ci/stages/ui.sh — stage 2.5: UI/UX quality gates (fixtures-driven).
# =============================================================================
# The zero-JavaScript SSR console has no unit-test harness for copy, forms,
# accessibility or navigation — the exported visual fixtures ARE the surface.
# This stage provisions them ONCE (ui-foundation's export_visual_fixtures bin
# with APEX_EXPORT_ALL_UI_ROUTES=1, every manifest route of every surface)
# and runs six static gates over the result + the Rust sources:
#
#   C  ui flash copy        tools/check_flash_copy.py       (CI_UI_FLASH_COPY_CHECK)
#   D  ui form hygiene      tools/check_ui_form_hygiene.py  (CI_UI_FORM_HYGIENE_CHECK)
#   E  ui accessibility     tools/check_ui_a11y.py          (CI_UI_A11Y_CHECK)
#   I  ui dead links        tools/check_ui_links.py         (CI_UI_LINKS_CHECK)
#   J  ui terminology       tools/check_ui_terminology.py   (CI_UI_TERMINOLOGY_CHECK)
#   K  ui strings catalog   tools/extract_ui_strings.py     (CI_UI_STRINGS_CATALOG_CHECK)
#
# ALL SIX GATES SHIP ADVISORY (default): the first run surfaced real P2 drift
# (missing per-form CSRF inputs, duplicate control-plane h1s, tenant wording
# in customer-facing flash strings, manifest link drift). Each gate flips to
# REQUIRED with its CI_UI_*_CHECK=required once its findings are fixed —
# exactly the fmt/clippy advisory→required convention (see ci/pipeline.conf).
# A gate exiting non-zero under the default flags logs the violations and
# NEVER fails the stage.
#
# Fixtures write ONLY into $RUN_DIR/ui-fixtures — never the working tree
# (the in-repo baselines/rust-ui dir belongs to the pixel-parity tooling).
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

WS=$REPO_ROOT/services/mail-server
UI_FIXTURES=$RUN_DIR/ui-fixtures

# ui_gate <flag> <label> <cmd...> — run one UI gate honouring its
# CI_UI_*_CHECK flag: `required` enforces the exit code, any other value
# (the shipped default: advisory) records and swallows the failure.
ui_gate() {
    _ug_flag=$1 _ug_label=$2
    shift 2
    if [ "$_ug_flag" = required ]; then
        ci_check "$_ug_label" "$@"
    else
        ci_check_advisory "$_ug_label" "$@"
    fi
}

# The marketing pages embedded by ui-foundation come from the zola build
# (build.rs falls back to placeholders on a bare clone). Build the real site
# when it is missing and the pinned zola is available so the exported
# marketing fixtures carry the real navigation — otherwise warn and continue
# (the gates stay advisory; the placeholder fallback pages gate fine).
ensure_marketing_output() {
    [ -f "$REPO_ROOT/apps/marketing-zola/public/index.html" ] && return "$CI_EXIT_OK"
    if ci_dry; then
        ci_info "dry-run: zola build (marketing output for the ui fixtures)"
        return "$CI_EXIT_OK"
    fi
    _emo_zola=''
    _emo_zola=$(ci_zola 2>/dev/null) || _emo_zola=''
    if [ -z "$_emo_zola" ]; then
        ci_warn "marketing public/ absent and zola missing — ui fixtures will " \
                "use ui-foundation's placeholder marketing pages (build the " \
                "site for full marketing-fixture coverage)"
        return "$CI_EXIT_OK"
    fi
    ci_info "building marketing output (ui fixtures source of truth)"
    (cd "$REPO_ROOT/apps/marketing-zola" && "$_emo_zola" build) >>"$CI_STAGE_LOG" 2>&1 \
        || ci_warn "zola build failed — continuing with placeholder marketing pages"
    return "$CI_EXIT_OK"
}

# Provision the full-route fixture set ONCE into the run dir. A provisioning
# failure is a stage failure even under advisory gate flags: the gates would
# otherwise silently validate a stale or empty directory.
provision_ui_fixtures() {
    if ci_dry; then
        ci_info "dry-run: APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation --bin export_visual_fixtures -- $UI_FIXTURES"
        return "$CI_EXIT_OK"
    fi
    ci_info "exporting UI fixtures to $UI_FIXTURES (all surfaces)"
    if ! (cd "$WS" && APEX_EXPORT_ALL_UI_ROUTES=1 ci_run_logged \
            cargo run -q -p ui-foundation --bin export_visual_fixtures -- "$UI_FIXTURES"); then
        ci_err "export_visual_fixtures FAILED — ui gates cannot run against stale input"
        return "$CI_EXIT_FAIL"
    fi
    [ -f "$UI_FIXTURES/manifest.json" ] \
        || { ci_err "fixture export produced no manifest at $UI_FIXTURES/manifest.json"; return "$CI_EXIT_FAIL"; }
    return "$CI_EXIT_OK"
}

run_ui_gates() {
    command -v python3 >/dev/null 2>&1 || {
        ci_warn "python3 missing — all six ui gates skipped (install python3)"
        return "$CI_EXIT_OK"
    }
    ui_gate "${CI_UI_FLASH_COPY_CHECK:-advisory}" \
        "ui flash copy (gate C)" \
        python3 tools/check_flash_copy.py
    ui_gate "${CI_UI_FORM_HYGIENE_CHECK:-advisory}" \
        "ui form hygiene (gate D)" \
        python3 tools/check_ui_form_hygiene.py "$UI_FIXTURES"
    ui_gate "${CI_UI_A11Y_CHECK:-advisory}" \
        "ui accessibility (gate E)" \
        python3 tools/check_ui_a11y.py "$UI_FIXTURES"
    ui_gate "${CI_UI_LINKS_CHECK:-advisory}" \
        "ui dead links (gate I)" \
        python3 tools/check_ui_links.py "$UI_FIXTURES"
    ui_gate "${CI_UI_TERMINOLOGY_CHECK:-advisory}" \
        "ui terminology (gate J)" \
        python3 tools/check_ui_terminology.py "$UI_FIXTURES"
    ui_gate "${CI_UI_STRINGS_CATALOG_CHECK:-advisory}" \
        "ui strings catalog drift (gate K)" \
        python3 tools/extract_ui_strings.py --check
    return "$CI_EXIT_OK"
}

stage_main() {
    cd "$REPO_ROOT"
    ensure_marketing_output
    provision_ui_fixtures
    run_ui_gates
    ci_info "ui: stage complete (gates advisory by default — see ci/pipeline.conf)"
    return "$CI_EXIT_OK"
}

stage_main
