#!/bin/sh
# =============================================================================
# ApexMail Container Vulnerability Scanner
# =============================================================================
# Scans all ApexMail container images for known vulnerabilities using Trivy.
#
# Prerequisites:
#   - Trivy installed: https://trivy.dev/latest/getting-started/installation/
#     or: brew install trivy
#
# Usage:
#   ./scripts/scan-vulnerabilities.sh              # Scan all images
#   ./scripts/scan-vulnerabilities.sh --ci          # CI mode (exit 1 on CRITICAL/HIGH)
#   ./scripts/scan-vulnerabilities.sh --image nginx:1.27-alpine  # Scan specific image
# =============================================================================
set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

CI_MODE=false
SPECIFIC_IMAGE=""

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=true ;;
        --image=*|--image) 
            if echo "$arg" | grep -q '='; then
                SPECIFIC_IMAGE="${arg#*=}"
            else
                # Next arg is the image
                shift
                SPECIFIC_IMAGE="$1"
            fi
            ;;
    esac
    shift
done

# Check if trivy is installed
if ! command -v trivy >/dev/null 2>&1; then
    echo "${RED}ERROR: trivy is not installed.${NC}"
    echo "Install it: brew install trivy"
    echo "Or: https://trivy.dev/latest/getting-stalled/installation/"
    exit 1
fi

# Define images to scan
IMAGES="
nginx:1.27-alpine
postgres:16.8-alpine
redis:7.4-alpine
clickhouse/clickhouse-server:24.8-alpine
prom/prometheus:v2.55.1
grafana/grafana:11.3.0
grafana/tempo:2.6.1
grafana/loki:3.0.0
prom/alertmanager:v0.27.0
otel/opentelemetry-collector-contrib:0.106.1
prom/blackbox-exporter:v0.25.0
prom/node-exporter:v1.8.2
prometheuscommunity/postgres-exporter:v0.15.0
oliver006/redis_exporter:v1.62.0
axllent/mailpit:v1.21
certbot/certbot:v2.11.0
"

# shellcheck disable=SC3043  # `local` is a widespread POSIX-sh extension
# (dash/busybox/bash all provide it); this script runs on the deploy host's
# /bin/sh, never on a strict POSIX shell without it.
scan_image() {
    local image="$1"
    echo "${YELLOW}Scanning: ${image}${NC}"
    
    if [ "$CI_MODE" = true ]; then
        trivy image --exit-code 1 --severity CRITICAL,HIGH --no-progress "$image"
        local exit_code=$?
        if [ $exit_code -eq 1 ]; then
            echo "${RED}CRITICAL/HIGH vulnerabilities found in ${image}${NC}"
            return 1
        fi
    else
        trivy image --severity CRITICAL,HIGH,MEDIUM --no-progress "$image"
        local exit_code=$?
        if [ $exit_code -eq 1 ]; then
            echo "${RED}Vulnerabilities found in ${image}${NC}"
        fi
    fi
    echo ""
}

OVERALL_EXIT=0

if [ -n "$SPECIFIC_IMAGE" ]; then
    scan_image "$SPECIFIC_IMAGE" || OVERALL_EXIT=1
else
    echo "${GREEN}Scanning all ApexMail container images...${NC}"
    echo ""
    
    for image in $IMAGES; do
        [ -z "$image" ] && continue
        scan_image "$image" || OVERALL_EXIT=1
    done
    
    echo "${GREEN}All scans complete.${NC}"
fi

exit $OVERALL_EXIT
