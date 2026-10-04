#!/bin/sh
# =============================================================================
# ci/ci-image/toolchain.sh — the apexmail-ci image's pinned-toolchain check.
# =============================================================================
# Baked into the image as /usr/local/bin/apexmail-ci-toolchain (the Dockerfile
# COPYs this file) and runs in two places:
#   * at IMAGE BUILD time — the Dockerfile ends with
#     `apexmail-ci-toolchain --assert`, so an image whose installed tool
#     versions disagree with /etc/apexmail-ci/toolchain-versions.env cannot
#     even be built, let alone pushed;
#   * as the FIRST WOODPECKER STEP — `apexmail-ci-toolchain --assert` in
#     .woodpecker.yml re-proves the executor image before any gate runs.
# Expected versions live in toolchain-versions.env (COPYed to
# /etc/apexmail-ci/toolchain-versions.env) and MUST equal the Dockerfile's
# ARGs — see that file's header for the bump procedure.
#
# Audit SM14 F1: neither this script nor the versions file existed in the
# repo, so the "hermetic" image could not be built from source and the pushed
# image was unverifiable drift.
# =============================================================================
set -u

# Only --assert (no-op default): the flag is documentation — this script has
# exactly one mode. An unknown flag must fail closed, never silently scan.
case "${1:-}" in
    ''|--assert) ;;
    *) echo "usage: apexmail-ci-toolchain [--assert]" >&2; exit 2 ;;
esac

TOOLCHAIN_ENV=${TOOLCHAIN_ENV:-/etc/apexmail-ci/toolchain-versions.env}

# PATH wiring: the rust image keeps cargo under /usr/local/cargo/bin and the
# Dockerfile unpacks go under /usr/local/go — make the assertion independent
# of whatever PATH the invoking shell happens to carry.
PATH="/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export PATH

if [ ! -f "$TOOLCHAIN_ENV" ]; then
    echo "FAIL toolchain: $TOOLCHAIN_ENV missing — the image build is broken \
(Dockerfile must COPY toolchain-versions.env, audit SM14 F1)" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$TOOLCHAIN_ENV"

fail=0

# Every pin the env file must carry (a missing pin is a broken env file, not
# an optional check — fail closed). Presence-pin-only tools (distro packages
# without a version pin: docker/compose plugin, php, mvn, java, ruby, npm,
# python3) are asserted below but intentionally not listed here.
for _v in NEXTEST_VERSION LLVMCOV_VERSION DENY_VERSION MACHETE_VERSION \
          AUDIT_VERSION SQLX_VERSION GITLEAKS_VERSION TRIVY_VERSION \
          SEMGREP_VERSION HADOLINT_VERSION PRE_COMMIT_VERSION \
          COMPOSER_VERSION ZOLA_VERSION NODE_MAJOR GO_VERSION PLAYWRIGHT_VERSION; do
    eval "_pin=\${$_v:-}"
    if [ -z "$_pin" ]; then
        echo "FAIL toolchain: $_v is not set in $TOOLCHAIN_ENV" >&2
        fail=$((fail + 1))
    fi
done

# assert <tool> <version-command> <pinned-substring | ->
#   The installed tool must exist and its first version-output line must
#   CONTAIN the pinned substring (matching on the raw substring — not a
#   command-name-prefixed regex — keeps the assertion robust across the
#   different version-output formats). '-' pins presence only: apt-installed
#   tools track distro security updates by design. <tool> may be multiword
#   ("docker compose"): presence is checked on its FIRST word, the version
#   command still exercises the plugin (and fails if it is absent).
assert() {
    _a_name=$1
    _a_cmd=$2
    _a_want=${3:--}
    _a_bin=${_a_name%% *}   # "docker compose" -> presence via `docker`
    if ! command -v "$_a_bin" >/dev/null 2>&1; then
        echo "FAIL toolchain: $_a_bin MISSING — the image diverged from its Dockerfile" >&2
        fail=$((fail + 1))
        return 0
    fi
    # The version command itself must SUCCEED: a presence pin on a subcommand
    # (e.g. the compose plugin) fails here when the plugin is absent, instead
    # of "passing" on docker's error text.
    # shellcheck disable=SC2086  # _a_cmd is an intentional multiword command
    _a_rc=0
    _a_out=$($_a_cmd 2>&1) || _a_rc=$?
    if [ "$_a_rc" -ne 0 ]; then
        echo "FAIL toolchain: '$_a_cmd' exited non-zero — the component is absent (image diverged from its Dockerfile)" >&2
        fail=$((fail + 1))
        return 0
    fi
    # 2>&1 already folded above; DISPLAY the first line, but match the pin
    # across the WHOLE output: some tools print a warning banner to stderr
    # before the version (composer, when run non-interactively as root),
    # and first-line-only matching made the assert fail on a correctly
    # pinned tool (found by the first real image build — external audit
    # 2026-10-02 item 1).
    _a_got=$(printf '%s' "$_a_out" | head -n 1)
    if [ "$_a_want" = "-" ]; then
        echo "toolchain: $_a_name — ${_a_got:-(no version output)} (presence pin)"
        return 0
    fi
    if printf '%s' "$_a_out" | grep -qF -- "$_a_want"; then
        echo "toolchain: $_a_name — $_a_got (pin $_a_want)"
    else
        echo "FAIL toolchain: $_a_name reports '$_a_got' — does not carry the pinned \
version '$_a_want' (toolchain-versions.env vs Dockerfile ARGs are out of sync?)" >&2
        fail=$((fail + 1))
    fi
}

# Rust + the cargo lane (exact pins).
assert cargo          'cargo --version'
assert rustc          'rustc --version'
assert cargo-nextest  'cargo nextest --version'  "${NEXTEST_VERSION:-}"
assert cargo-llvm-cov 'cargo llvm-cov --version' "${LLVMCOV_VERSION:-}"
assert cargo-deny     'cargo deny --version'     "${DENY_VERSION:-}"
assert cargo-machete  'cargo machete --version'  "${MACHETE_VERSION:-}"
assert cargo-audit    'cargo audit --version'    "${AUDIT_VERSION:-}"
assert sqlx           'sqlx --version'           "${SQLX_VERSION:-}"

# Security + supply chain (exact pins).
assert gitleaks    'gitleaks version'  "${GITLEAKS_VERSION:-}"
assert trivy       'trivy --version'   "${TRIVY_VERSION:-}"
# semgrep's python wrapper execs the OCaml core with the version flag and
# misroutes it on some emulated builders (core answers "unknown option
# '--version'") — the hermeticity contract is "the pinned package is
# installed", which pip's own metadata proves deterministically on every
# builder. The wrapper's runtime behaviour is exercised for real by the
# security stage's semgrep lane (ci_have_tool + semgrep scan) on the
# executor host.
assert semgrep     'pip3 show semgrep' "${SEMGREP_VERSION:-}"
assert pre-commit  'pre-commit --version' "${PRE_COMMIT_VERSION:-}"
assert hadolint    'hadolint --version' "${HADOLINT_VERSION:-}"

# docker CLI + compose plugin (audit SM14 F5): CLIENT-SIDE only — the
# compose-contract gate renders `docker compose config` without a daemon.
# Presence pins: both track their vendor repo's bookworm security updates.
# The NAME is 'docker compose' (space!) so the helper's presence check
# resolves the `docker` binary; invoked as 'docker-compose' it looked for a
# `docker-compose` executable the plugin never ships and the assert could
# never pass (found by the first real image build — external audit
# 2026-10-02 item 1).
assert docker           'docker --version'
assert 'docker compose' 'docker compose version'

# Languages / site tooling.
assert composer 'composer --version' "${COMPOSER_VERSION:-}"
assert zola     'zola --version'     "${ZOLA_VERSION:-}"
assert go       'go version'         "go${GO_VERSION:-}"
assert node     'node --version'     "v${NODE_MAJOR:-}."
assert npm      'npm --version'
assert python3  'python3 --version'
assert php      'php --version'
assert mvn      'mvn --version'
assert java     'java -version'
assert ruby     'ruby --version'

# Playwright browsers: the contrast/layout gates (ci/stages/test.sh F2
# provisioning) run the WORKSPACE playwright — npm ci of
# tools/contrast-audit, whose lockfile pin PLAYWRIGHT_VERSION mirrors —
# against the browser binaries baked in at build time. No chromium in the
# cache means a silently broken browser layer.
_pw_dir=${PLAYWRIGHT_BROWSERS_PATH:-${HOME:-/root}/.cache/ms-playwright}
# shellcheck disable=SC2010  # chromium-<rev> dirs are the documented layout
if [ -d "$_pw_dir" ] && ls "$_pw_dir" 2>/dev/null | grep -q '^chromium'; then
    echo "toolchain: playwright browsers — chromium present in $_pw_dir (pin ${PLAYWRIGHT_VERSION:-?})"
else
    echo "FAIL toolchain: no chromium under $_pw_dir — the Dockerfile browser layer \
(playwright@${PLAYWRIGHT_VERSION:-?}) did not install (audit SM14 F2)" >&2
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    echo "TOOLCHAIN FAILURES: $fail — the image cannot be trusted as hermetic" >&2
    exit 1
fi
echo "toolchain: all pinned tools present at their pins"
exit 0
