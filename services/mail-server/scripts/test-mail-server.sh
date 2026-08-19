#!/bin/bash
#
# Test the deployed ApexMail mail-server edges.
#
# Prerequisites:
# - Mail server running (docker-compose up)
# - A verified sender domain with encrypted DKIM material

set -e

WORKER_HEALTH_URL=${WORKER_HEALTH_URL:-http://localhost:9090/health}

echo "==================================="
echo "ApexMail Mail Server Test"
echo "==================================="
echo ""
echo "Worker health URL: $WORKER_HEALTH_URL"
echo ""

# Test 1: Test SMTP connectivity
echo ""
echo "Test 1: Testing SMTP connectivity..."
if command -v nc &> /dev/null; then
    echo "QUIT" | nc -w 5 localhost 25 2>/dev/null || true
    echo "Port 25 (SMTP): $(nc -zv localhost 25 2>&1 | grep -q 'succeeded' && echo '✓ Open' || echo '✗ Closed')"
    echo "Port 587 (Submission): $(nc -zv localhost 587 2>&1 | grep -q 'succeeded' && echo '✓ Open' || echo '✗ Closed')"
fi

# Test 2: Confirm the sole outbound sender is healthy. This script never uses
# the retired global-DKIM gRPC queue or its `send-email` client.
echo ""
echo "Test 2: Checking unified worker health..."
if command -v curl &> /dev/null; then
    curl --fail --silent --show-error "$WORKER_HEALTH_URL" >/dev/null \
        && echo "✓ Worker healthy" \
        || echo "✗ Worker health endpoint unavailable"
else
    echo "⚠ curl not available; skipped worker health check"
fi

echo ""
echo "==================================="
echo "Tests completed"
echo "==================================="
