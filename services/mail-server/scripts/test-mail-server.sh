#!/bin/bash
#
# Test the deployed ApexMail mail-server edges.
#
# Prerequisites:
# - Mail server running (docker-compose up)
# - A verified sender domain with encrypted DKIM material
#
# Exit code (coverage audit U-8): 0 only when every executed check passed.
# A closed SMTP port or an unavailable worker health endpoint is a FAILURE
# (exit 1); a missing local tool is an explicit skip, not a pass. The script
# previously ended every check in `|| true` and always exited 0.

set -uo pipefail

WORKER_HEALTH_URL=${WORKER_HEALTH_URL:-http://localhost:9090/health}

FAILURES=0
SKIPS=0

fail() {
    echo "✗ $1"
    FAILURES=$((FAILURES + 1))
}

skip() {
    echo "⚠ $1 (skipped)"
    SKIPS=$((SKIPS + 1))
}

echo "==================================="
echo "ApexMail Mail Server Test"
echo "==================================="
echo ""
echo "Worker health URL: $WORKER_HEALTH_URL"
echo ""

# Test 1: SMTP connectivity
echo ""
echo "Test 1: Testing SMTP connectivity..."
if command -v nc &> /dev/null; then
    for port in 25 587; do
        label=$([ "$port" = "25" ] && echo "SMTP" || echo "Submission")
        if nc -z -w 5 localhost "$port" &>/dev/null; then
            echo "Port $port ($label): ✓ Open"
        else
            fail "Port $port ($label): closed or unreachable"
        fi
    done
else
    skip "nc not available; SMTP port checks not executed"
fi

# Test 2: Confirm the sole outbound sender is healthy. This script never uses
# the retired global-DKIM gRPC queue or its `send-email` client.
echo ""
echo "Test 2: Checking unified worker health..."
if command -v curl &> /dev/null; then
    if curl --fail --silent --show-error --max-time 10 "$WORKER_HEALTH_URL" >/dev/null; then
        echo "✓ Worker healthy"
    else
        fail "Worker health endpoint unavailable: $WORKER_HEALTH_URL"
    fi
else
    skip "curl not available; worker health check not executed"
fi

echo ""
echo "==================================="
if [ "$FAILURES" -gt 0 ]; then
    echo "Tests FAILED: $FAILURES check(s) failed, $SKIPS skipped"
    exit 1
fi
echo "Tests completed: all executed checks passed ($SKIPS skipped)"
echo "==================================="
exit 0
