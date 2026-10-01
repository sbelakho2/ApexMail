#!/bin/sh
# =============================================================================
# ci/woodpecker/run-dir.sh — the ONE definition of the executor's run dir.
# =============================================================================
# Audit SM14 F14: the notify-github steps in .woodpecker.yml used to grep
# `ci/runs/*/stages/*.log` — on a reused Woodpecker workspace, stale logs
# from earlier pipelines inflated the PASS/FAIL counts in the GitHub commit
# status. Every step of a pipeline therefore resolves the SAME run
# directory, and the status steps grep exactly that directory.
#
# Sourced by:
#   * ci/woodpecker/stage.sh  — uses $WP_RUN_DIR as its RUN_DIR (and mkdirs it);
#   * the notify-github steps — re-derive the path to grep this pipeline's
#     logs only (Woodpecker steps are separate containers, so exported
#     variables do not survive between steps; sourcing this file gives both
#     sides the identical answer, including per-pipeline, clock-independent).
#
# POSIX sh; safe to source repeatedly. Overridable with CI_RUN_DIR (stage.sh
# honours it; the notify steps fall back to WP_RUN_DIR).
# =============================================================================
# Pipeline-scoped and clock-independent: with Woodpecker's CI_PIPELINE_NUMBER
# present, every step of pipeline N — whenever each starts — resolves the
# identical run dir. Without pipeline metadata (local executor-wrapper
# testing) fall back to a per-invocation UTC stamp + pid.
if [ -n "${CI_PIPELINE_NUMBER:-}" ]; then
    WP_RUN_DIR="${CI_ROOT:-$PWD/ci}/runs/wp${CI_PIPELINE_NUMBER}"
else
    WP_RUN_DIR="${CI_ROOT:-$PWD/ci}/runs/$(date -u +%Y%m%dT%H%M%SZ)_wp$$"
fi

# ci_prune_wp_runs <keep_n> — delete the oldest wp<pipeline-number> run dirs
# beyond the newest N (audit SM14 F14: the Woodpecker pipeline never runs the
# notify stage, so nothing else bounds ci/runs/wp* on a persistent workspace).
# The CURRENT run dir is never deleted, and non-numeric dirs (the per-
# invocation fallback above) are left for the host-side ci_prune_runs policy.
ci_prune_wp_runs() {
    _pw_keep=${1:-30}
    _pw_dir=$(dirname "$WP_RUN_DIR")
    _pw_cur=$(basename "$WP_RUN_DIR")
    [ -d "$_pw_dir" ] || return 0
    for _pw_name in $(cd "$_pw_dir" && ls -1d wp* 2>/dev/null || true); do
        [ "$_pw_name" = "$_pw_cur" ] && continue
        _pw_num=${_pw_name#wp}
        case $_pw_num in
            ''|*[!0-9]*) continue ;;
        esac
        printf '%s %s\n' "$_pw_num" "$_pw_name"
    done | sort -rn | awk -v keep="$_pw_keep" 'NR > keep { print $2 }' \
        | while IFS= read -r _pw_old; do
            rm -rf "${_pw_dir:?}/$_pw_old"
        done
    return 0
}
