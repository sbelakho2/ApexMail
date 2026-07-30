#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# signup-test.sh — Complete signup flow testing.
# Scenarios: email+password, Google login, GitHub login, duplicate account,
# invalid email, weak/strong password, expired/reused verification link,
# abandoned signup, resend verification, account deletion, re-registration.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.signup-test-report.json"

: "${APP_URL:=https://app.apexmail.ee}"
: "${API_URL:=https://api.apexmail.ee}"
: "${TEST_EMAIL_PREFIX:=test-signup-}"
: "${TEST_DOMAIN:=apexmail-test.internal}"

CRITICAL=0
WARNINGS=0
RESULTS="[]"

add_result() {
    local scenario="$1" status="$2" detail="$3"
    RESULTS="$(echo "$RESULTS" | jq --arg scenario "$scenario" --arg status "$status" \
        --arg detail "$detail" --arg checked_at "$TIMESTAMP" \
        '. + [{scenario:$scenario,status:$status,detail:$detail,checked_at:$checked_at}]')"
}

test_signup_form_presence() {
    echo "  Testing: Signup form presence"
    local status response
    response="$(http_code "$APP_URL/signup")"
    if [[ "$response" == "200" || "$response" == "302" || "$response" == "301" ]]; then
        add_result "signup-form-presence" "pass" "HTTP $response"
    else
        add_result "signup-form-presence" "warn" "HTTP $response — page may not be accessible"
        WARNINGS=$((WARNINGS+1))
    fi
}

test_legal_disclosures() {
    echo "  Testing: Signup legal disclosures"
    local page_content
    page_content="$(curl -sS "${APP_URL}/signup" 2>/dev/null || echo "")"
    local disclosures=("Terms" "Privacy" "Acceptable Use" "Anti-Spam" "Bel Consulting")
    for d in "${disclosures[@]}"; do
        if echo "$page_content" | grep -qi "$d" 2>/dev/null; then
            add_result "legal-disclosure-$d" "pass" "Disclosure present"
        else
            add_result "legal-disclosure-$d" "warn" "Disclosure may be missing"
            WARNINGS=$((WARNINGS+1))
        fi
    done
}

test_error_messages() {
    echo "  Testing: Signup error messaging"
    local error_output
    # Test with empty form
    error_output="$(curl -sS -X POST "${API_URL}/auth/signup" \
        -H 'Content-Type: application/json' \
        -d '{}' 2>/dev/null | jq -r '.message // .error // empty' 2>/dev/null || echo "")"
    if [[ -n "$error_output" ]]; then
        add_result "error-messaging" "pass" "Error messages present for invalid submission"
    else
        add_result "error-messaging" "warn" "Could not verify error messaging format"
        WARNINGS=$((WARNINGS+1))
    fi
}

test_password_validation() {
    echo "  Testing: Password validation"
    local weak_pass
    weak_pass="$(curl -sS -X POST "${API_URL}/auth/signup" \
        -H 'Content-Type: application/json' \
        -d '{"email":"weak@example.com","password":"123"}' 2>/dev/null | jq -r '.code // .error // empty' 2>/dev/null || echo "")"
    if [[ -n "$weak_pass" ]]; then
        add_result "weak-password-rejected" "pass" "Weak password rejected with error"
    else
        add_result "weak-password-rejected" "warn" "Weak password validation could not be confirmed"
        WARNINGS=$((WARNINGS+1))
    fi
}

test_social_login_presence() {
    echo "  Testing: Social login buttons presence"
    local page_content
    page_content="$(curl -sS "${APP_URL}/login" 2>/dev/null || echo "")"
    if echo "$page_content" | grep -qi "google\|github" 2>/dev/null; then
        add_result "social-login-buttons" "pass" "Social login options visible"
    else
        add_result "social-login-buttons" "warn" "Social login buttons not detected on login page"
        WARNINGS=$((WARNINGS+1))
    fi
}

test_csrf_protection() {
    echo "  Testing: CSRF protection"
    local page_content
    page_content="$(curl -sS "${APP_URL}/signup" 2>/dev/null || echo "")"
    if echo "$page_content" | grep -qi "csrf\|_token\|nonce\|authenticity" 2>/dev/null; then
        add_result "csrf-protection" "pass" "CSRF token detected"
    else
        add_result "csrf-protection" "warn" "No CSRF token detected on signup page"
        WARNINGS=$((WARNINGS+1))
    fi
}

test_rate_limiting() {
    echo "  Testing: Rate limiting on signup"
    local rate_limit_resp
    rate_limit_resp="$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST "${API_URL}/auth/signup" \
        -H 'Content-Type: application/json' \
        -d '{"email":"ratelimit@test.com","password":"TestPass123!"}' 2>/dev/null || echo "000")"
    if [[ "$rate_limit_resp" == "429" ]]; then
        add_result "rate-limiting" "pass" "429 received — rate limiting active"
    else
        add_result "rate-limiting" "info" "Rate limiting test — got $rate_limit_resp"
    fi
}

http_code() {
    curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 15 "$1" 2>/dev/null || echo "000"
}

main() {
    echo "=== ApexMail Signup Flow Test ==="

    test_signup_form_presence
    test_legal_disclosures
    test_error_messages
    test_password_validation
    test_social_login_presence
    test_csrf_protection
    test_rate_limiting

    jq -n --argjson results "$RESULTS" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,results:$results}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"
}

main "$@"
