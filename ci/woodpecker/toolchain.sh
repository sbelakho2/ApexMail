# =============================================================================
# ci/woodpecker/toolchain.sh — first-stage toolchain assertion.
# =============================================================================
# Prints the exact version of every tool the pipeline stages require, then
# FAILS if any is missing (or, for the pinned security/cargo binaries, on a
# major-version mismatch). With the hermetic apexmail-ci image this proves
# the executor can reproduce the host pipeline; on an under-provisioned
# executor it fails LOUDLY instead of letting gates warn-and-skip.
#
# Runs as the first Woodpecker step, and at image build time (the Dockerfile
# ends with `apexmail-ci-toolchain --assert` so a broken image cannot be
# pushed).
# =============================================================================
set -u

fail=0

# name, version-command, expected-regex (empty = presence is enough)
check() {
    _c_name=$1; _c_cmd=$2; _c_want=${3:-}
    if ! command -v "$_c_name" >/dev/null 2>&1; then
        echo "FAIL toolchain: $_c_name MISSING — the executor image is under-provisioned"
        fail=$((fail + 1))
        return 0
    fi
    _c_got=$($_c_cmd 2>/dev/null | head -1)
    echo "toolchain: $_c_name — $_c_got"
    if [ -n "$_c_want" ] && ! printf '%s' "$_c_got" | grep -Eq "$_c_want"; then
        echo "FAIL toolchain: $_c_name version '$_c_got' does not match required /$_c_want/"
        fail=$((fail + 1))
    fi
}

# Rust + the cargo lane (pinned majors).
check cargo          'cargo --version'
check rustc          'rustc --version'
check cargo-nextest  'cargo nextest --version'   '^cargo-nextest 0\.9\.'
check cargo-llvm-cov 'cargo llvm-cov --version'  '^cargo-llvm-cov 0\.9\.'
check cargo-deny     'cargo deny --version'
check cargo-machete  'cargo machete --version'   '^0\.9\.'
check cargo-audit    'cargo audit --version'
check sqlx           'sqlx --version'

# Security + supply chain (required binaries, period).
check gitleaks       'gitleaks version'
check trivy          'trivy --version'
check semgrep        'semgrep --version'
check shellcheck     'shellcheck --version'
check hadolint       'hadolint --version'

# Languages the SDK/marketing lanes need.
check python3        'python3 --version'
check php            'php --version'
check composer       'composer --version'
check go             'go version'
check mvn            'mvn --version'
check java           'java -version'
check ruby           'ruby --version'
check node           'node --version'
check npm            'npm --version'
check zola           'zola --version'            '^zola 0\.22\.'

if [ "$fail" -gt 0 ]; then
    echo "TOOLCHAIN FAILURES: $fail — set CI_MISSING_TOOLS=warn ONLY as an explicit triage override"
    if [ "${CI_MISSING_TOOLS:-fail}" = fail ]; then
        exit 1
    fi
    echo "CI_MISSING_TOOLS≠fail — continuing under the explicit triage override"
    exit 0
fi
echo "toolchain: all required tools present"
