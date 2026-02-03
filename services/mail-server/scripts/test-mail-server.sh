#!/bin/bash
#
# Test the ApexMail mail server
#
# Prerequisites:
# - Mail server running (docker-compose up)
# - DKIM keys generated
# - DNS records configured

set -e

MAIL_SERVER_URL=${MAIL_SERVER_URL:-http://localhost:50052}
FROM_EMAIL=${FROM_EMAIL:-test@apexmail.ee}
TO_EMAIL=${TO_EMAIL:-test@example.com}

echo "==================================="
echo "ApexMail Mail Server Test"
echo "==================================="
echo ""
echo "Server URL: $MAIL_SERVER_URL"
echo "From: $FROM_EMAIL"
echo "To: $TO_EMAIL"
echo ""

# Test 1: Send a test email using the CLI tool
echo "Test 1: Sending test email..."
if command -v send-email &> /dev/null; then
    send-email send \
        --server "$MAIL_SERVER_URL" \
        --from "$FROM_EMAIL" \
        --to "$TO_EMAIL" \
        --subject "ApexMail Test Email" \
        --text "This is a test email from ApexMail's self-hosted mail server.

Features:
- Direct SMTP delivery (no third-party services)
- DKIM signing enabled
- Full delivery tracking

Sent at: $(date)"
    echo "✓ Test email sent"
else
    echo "⚠ send-email CLI not found. Install with: cargo install --path crates/outbound-queue"
fi

# Test 2: Check queue stats
echo ""
echo "Test 2: Checking queue stats..."
if command -v send-email &> /dev/null; then
    send-email stats --server "$MAIL_SERVER_URL"
else
    echo "⚠ Skipped (CLI not available)"
fi

# Test 3: Test SMTP connectivity
echo ""
echo "Test 3: Testing SMTP connectivity..."
if command -v nc &> /dev/null; then
    echo "QUIT" | nc -w 5 localhost 25 2>/dev/null || true
    echo "Port 25 (SMTP): $(nc -zv localhost 25 2>&1 | grep -q 'succeeded' && echo '✓ Open' || echo '✗ Closed')"
    echo "Port 587 (Submission): $(nc -zv localhost 587 2>&1 | grep -q 'succeeded' && echo '✓ Open' || echo '✗ Closed')"
fi

# Test 4: Test gRPC endpoint
echo ""
echo "Test 4: Testing gRPC endpoint..."
if command -v grpc_health_probe &> /dev/null; then
    grpc_health_probe -addr=localhost:50052 && echo "✓ gRPC endpoint healthy" || echo "✗ gRPC endpoint unhealthy"
else
    # Simple HTTP check as fallback
    curl -s -o /dev/null -w "%{http_code}" "$MAIL_SERVER_URL/health" 2>/dev/null | grep -q "200" && echo "✓ HTTP endpoint accessible" || echo "⚠ HTTP check inconclusive"
fi

echo ""
echo "==================================="
echo "Tests completed"
echo "==================================="
