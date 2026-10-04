#!/bin/sh
# =============================================================================
# ci/stages/docs.sh — stage 2.5: documentation architecture-truth gates.
# =============================================================================
# Audit EXT-E #11 (2026-10-02): the authoritative architecture is a SINGLE
# HETZNER HOST with Docker Compose (ARCHITECTURE.md — "no Kubernetes"), yet
# production runbooks still taught `kubectl`/`helm` operations that cannot
# work on this deployment. Every such command has been rewritten to its real
# Compose equivalent, and this stage keeps the tree honest:
#
#   A  docs architecture truth   tools/check_docs_architecture_truth.py
#                                (CI_DOCS_TRUTH_CHECK)
#
# The gate fails any PRODUCTION runbook / operational doc under docs/
# containing kubectl|helm|k9s|istioctl|argocd|"namespace apexmail" unless the
# document carries the ARCHITECTURE-TRUTH: HISTORICAL|ROADMAP|ALTERNATIVE
# marker in its first 15 lines (which is how genuinely historical/roadmap
# documents — e.g. the Redis Cluster roadmap — stay in the tree without
# posing as runbooks). Non-operational record trees (docs/audit/, docs/adr/,
# …) are excluded outright by the checker.
#
# REQUIRED by default (CI_DOCS_TRUTH_CHECK=required in ci/pipeline.conf):
# the K8s drift landed once and this gate exists to stop it landing again.
# `advisory` remains available only as a bounded triage-window override,
# mirroring the fmt/clippy convention. The checker also has a built-in
# drift-injection selftest: `python3 tools/check_docs_architecture_truth.py
# --selftest` (run manually or in ci/pipeline.sh selftest mode — this stage
# runs it alongside the real gate so the rule proves itself every run).
#
# Deliberately NOT in ci/stages/validate.sh: that stage is a different
# owner's surface; this is an independent stage so the gate cannot be lost
# in a validate-stage refactor.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

# docs_gate <flag> <label> <cmd...> — honour CI_DOCS_TRUTH_CHECK: `required`
# (the default in ci/pipeline.conf) enforces the exit code; `advisory` records
# and swallows the failure (bounded triage window only).
docs_gate() {
    _dg_flag=$1 _dg_label=$2
    shift 2
    if [ "$_dg_flag" = required ]; then
        ci_check "$_dg_label" "$@"
    else
        ci_check_advisory "$_dg_label" "$@"
    fi
}

stage_main() {
    _truth_flag=${CI_DOCS_TRUTH_CHECK:-required}

    # The real gate over the live docs tree.
    docs_gate "$_truth_flag" "docs architecture truth (no K8s operations in production docs)" \
        python3 tools/check_docs_architecture_truth.py

    # The rule's own proof: drift-injection selftest (throwaway tree — never
    # touches docs/). Same severity as the gate it demonstrates.
    docs_gate "$_truth_flag" "docs architecture truth selftest (drift injection)" \
        python3 tools/check_docs_architecture_truth.py --selftest

    return "$CI_EXIT_OK"
}

stage_main
