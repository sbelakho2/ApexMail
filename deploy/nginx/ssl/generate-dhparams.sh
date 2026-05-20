#!/bin/sh
# =============================================================================
# Generate unique Diffie-Hellman parameters for this deployment
# =============================================================================
# Run this script at deployment time to generate unique DH params.
# This prevents precomputation attacks on shared DH groups.
#
# Usage:
#   ./deploy/nginx/ssl/generate-dhparams.sh
#
# The generated dhparam.pem will be picked up by Nginx via the volume mount
# in docker-compose.prod.yml (TLS_CERT_DIR).
#
# NOTE: If using TLS 1.3 only (which doesn't use DHE), DH params are not
# needed. However, we generate them anyway for TLS 1.2 backward compatibility
# with ECDHE cipher suites that may negotiate DHE key exchange.
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/dhparam.pem"
BITS=4096

echo "Generating ${BITS}-bit Diffie-Hellman parameters..."
echo "This may take several minutes..."
openssl dhparam -out "${OUTPUT_FILE}" "${BITS}"
echo "DH parameters written to ${OUTPUT_FILE}"
echo "File size: $(wc -c < "${OUTPUT_FILE}" | tr -d ' ') bytes"
