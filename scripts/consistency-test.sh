#!/usr/bin/env bash
# Validate deployable company identity and pricing artifacts.
#
# Runtime billing facts are checked by tools/validate_pricing_drift.py. The
# company/claims snapshot is intentionally not a commercial catalog.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL_JSON="$PROJECT_ROOT/apps/marketing-zola/data/canonical.json"
LEGAL_ENTITY_RS="$PROJECT_ROOT/compliance/src/legal_entity.rs"
ZOLA_DIR="$PROJECT_ROOT/apps/marketing-zola"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

printf 'ApexMail production consistency checks\n'

[[ -f "$CANONICAL_JSON" ]] || fail "missing company/claims snapshot"
[[ -f "$LEGAL_ENTITY_RS" ]] || fail "missing legal-entity constants"

python3 - "$CANONICAL_JSON" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)

company = data.get("company", {})
assert company.get("legal_name") == "Bel Consulting OÜ"
assert company.get("registry_code") == "16588745"
assert data.get("_pricing_authority") == (
    "services/mail-server/crates/billing-service/src/plans.rs "
    "(plus active plans table and verified Stripe webhooks)"
)
assert "pricing_plans" not in data
assert "HIPAA not currently available" in data.get("claims", {}).get(
    "compliance_status_wording", ""
)
assert "active deployment" in data.get("claims", {}).get(
    "data_residency_wording", ""
)
PY
printf 'PASS: company/claims snapshot has no duplicate pricing catalog\n'

grep -Fq 'RUNTIME_PRICING_AUTHORITY' "$LEGAL_ENTITY_RS" || fail "legal constants do not identify the billing authority"
grep -Fq 'pub plans:' "$LEGAL_ENTITY_RS" && fail "legal constants must not contain a pricing catalog"
grep -Fq 'SINGLE SOURCE OF TRUTH' "$LEGAL_ENTITY_RS" && fail "legal constants still claim global authority"
grep -Fq 'active deployment' "$LEGAL_ENTITY_RS" || fail "legal residency wording is not deployment-qualified"
printf 'PASS: legal constants are correctly scoped\n'

grep -Fq 'region: ${LOKI_S3_REGION:-eu-central-1}' "$PROJECT_ROOT/deploy/loki/loki-config.yaml" || fail "Loki telemetry storage must default to an EEA region"
grep -Fq 'region: ${TEMPO_S3_REGION:-eu-central-1}' "$PROJECT_ROOT/deploy/tempo/tempo.yaml" || fail "Tempo telemetry storage must default to an EEA region"
printf 'PASS: supplied telemetry defaults target an EEA region\n'

grep -Fq '[extra.company]' "$ZOLA_DIR/config.toml" || fail "Zola company configuration is missing"
grep -Fq 'registry_code' "$ZOLA_DIR/config.toml" || fail "Zola registry code is missing"
printf 'PASS: Zola company configuration is present\n'

if [[ ! -f "$ZOLA_DIR/public/index.html" || ! -f "$ZOLA_DIR/public/pricing/index.html" ]]; then
    command -v zola >/dev/null 2>&1 || fail "generated marketing output is missing and zola is unavailable"
    zola --root "$ZOLA_DIR" build
fi

python3 "$PROJECT_ROOT/tools/validate_pricing_drift.py"
printf 'PASS: runtime-linked pricing validation passed\n'
