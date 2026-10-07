#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Can-fail self-test for security-audit.sh (coverage audit U-1).
#
# Runs the REAL script against a fake cargo-audit so every failure
# shape is exercised without needing the network or a vulnerable
# lockfile. Fails before the U-1 fix: the "offline" case exited 0
# and printed "Security audit passed".
#
# Usage: bash services/mail-server/scripts/security-audit-selftest.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/security-audit.sh"

if [ ! -f "${AUDIT_SCRIPT}" ]; then
    echo "selftest: ${AUDIT_SCRIPT} not found" >&2
    exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-security-audit-selftest.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

mkdir -p "${TMP}/bin" "${TMP}/reports"

# Fake toolchain: `cargo audit --json` and `cargo audit` read their
# payload and exit code from the environment, so the test controls
# exactly what cargo-audit "reported".
cat > "${TMP}/bin/cargo" <<'FAKE'
#!/usr/bin/env bash
if [ "${1:-}" = "audit" ]; then
    case " $* " in
        *" --json "*)
            printf '%s' "${FAKE_JSON:-}"
            exit "${FAKE_JSON_RC:-0}"
            ;;
        *)
            printf '%s\n' "${FAKE_HUMAN:-human audit output}"
            exit "${FAKE_HUMAN_RC:-0}"
            ;;
    esac
fi
echo "fake cargo: unsupported invocation: $*" >&2
exit 1
FAKE
chmod +x "${TMP}/bin/cargo"

cat > "${TMP}/bin/cargo-audit" <<'FAKE'
#!/usr/bin/env bash
exit 0
FAKE
chmod +x "${TMP}/bin/cargo-audit"

PASS=0
FAIL=0

# run_case <name> <expected-exit> <json> <json-rc> <human-rc> [expected-output] [env...]
run_case() {
    local name="$1" expected="$2" json="$3" json_rc="$4" human_rc="$5" needle="${6:-}"
    shift 6 || true
    local out="${TMP}/out.log"
    set +e
    env PATH="${TMP}/bin:${PATH}" \
        REPORT_DIR="${TMP}/reports" \
        FAKE_JSON="${json}" \
        FAKE_JSON_RC="${json_rc}" \
        FAKE_HUMAN_RC="${human_rc}" \
        "$@" \
        bash "${AUDIT_SCRIPT}" > "${out}" 2>&1
    local rc=$?
    set -e

    local ok=1
    [ "${rc}" -eq "${expected}" ] || ok=0
    if [ -n "${needle}" ]; then
        grep -qF -- "${needle}" "${out}" || ok=0
    fi

    if [ "${ok}" -eq 1 ]; then
        echo "  ✓ ${name} (exit ${rc})"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${name}: expected exit ${expected} and output ${needle:-<any>}, got exit ${rc}"
        sed 's/^/      | /' "${out}" | tail -8
        FAIL=$((FAIL + 1))
    fi
}

CLEAN_JSON='{"database":{"advisory-count":1},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{"unmaintained":[],"unsound":[]}}'
VULN_JSON='{"database":{"advisory-count":1},"vulnerabilities":{"found":true,"count":2,"list":[{"advisory":{"severity":"high","id":"RUSTSEC-0000-0001","title":"fake"},"package":{"name":"fake@1.0.0","version":"1.0.0"}}]},"warnings":{"unmaintained":[],"unsound":[]}}'
WARN_JSON='{"database":{"advisory-count":1},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{"unmaintained":[{"advisory":{"id":"RUSTSEC-0000-0002"}}],"unsound":[]}}'

echo "security-audit-selftest:"
# 1. Offline auditor: error text lands in the JSON file, non-zero exit.
#    Pre-fix this printed "Security audit passed" and exited 0.
run_case "offline auditor fails closed" 3 \
    "error: could not fetch advisory database (network unreachable)" 1 1 \
    "did not produce parseable JSON"
# 2. Non-zero exit with an otherwise valid clean JSON payload (tool error
#    after parsing): not a clean audit.
run_case "tool error with clean-looking JSON fails" 2 \
    "${CLEAN_JSON}" 2 2 \
    "could not be completed"
# 3. Real clean run: the pass path stays real.
run_case "clean audit passes" 0 "${CLEAN_JSON}" 0 0 "passed"
# 4. Vulnerabilities: failed run.
run_case "vulnerabilities fail" 1 "${VULN_JSON}" 1 1 "vulnerabilities found"
# 5. Warning-class notices are advisory by default…
run_case "warnings advisory by default" 0 "${WARN_JSON}" 0 0 "passed"
# 6. …and gate when FAIL_ON_WARNINGS=1.
run_case "warnings gate when configured" 1 "${WARN_JSON}" 0 0 \
    "warning-class advisories" \
    env FAIL_ON_WARNINGS=1

echo "security-audit-selftest: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
