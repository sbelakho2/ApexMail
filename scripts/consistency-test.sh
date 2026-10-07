#!/usr/bin/env bash
# Validate deployable company identity and pricing artifacts.
#
# Runtime billing facts are checked by tools/validate_pricing_drift.py. The
# company/claims snapshot is intentionally not a commercial catalog.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL_JSON="$PROJECT_ROOT/apps/marketing-zola/data/canonical.json"
# The root compliance/ package was removed in the 2026-09-30 audit campaign
# (SM8 F9: dead drifted duplicate); the live legal-entity module is the crate
# copy. Pointing at the removed path made this script fail unconditionally.
LEGAL_ENTITY_RS="$PROJECT_ROOT/services/mail-server/crates/compliance/src/legal_entity.rs"
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
# The constant and the marketing claims snapshot must carry the SAME sentence
# (the two drifted apart when the root legal-entity copy was deleted).
python3 - "$LEGAL_ENTITY_RS" "$CANONICAL_JSON" <<'PY'
import json
import re
import sys

legal_path, json_path = sys.argv[1], sys.argv[2]
legal = open(legal_path, encoding="utf-8").read()
match = re.search(r'DATA_RESIDENCY_WORDING: &str =\s*\n?\s*"([^"]+)"', legal)
assert match, "DATA_RESIDENCY_WORDING missing from the legal constants"
const_wording = match.group(1)
claims = json.load(open(json_path, encoding="utf-8")).get("claims", {})
assert claims.get("data_residency_wording") == const_wording, (
    "canonical.json data_residency_wording drifted from the legal constant:\n"
    f"  json: {claims.get('data_residency_wording')!r}\n  rust: {const_wording!r}"
)
PY
printf 'PASS: legal constants are correctly scoped\n'

# Telemetry object storage (2026-10-07): the pinned images' expand-env has no
# default syntax, so the shipped configs carry STATIC EEA defaults instead of
# ${VAR:-eu-central-1} forms — Loki runs the on-host filesystem store (S3 is a
# documented manual switch with LOKI_S3_REGION=eu-central-1), Tempo ships its
# s3 block with region eu-central-1. Pin the shipped reality.
grep -Fq 'object_store: filesystem' "$PROJECT_ROOT/deploy/loki/loki-config.yaml" || fail "Loki default object store must stay on-host (filesystem)"
grep -Fq 'LOKI_S3_REGION=eu-central-1' "$PROJECT_ROOT/deploy/loki/loki-config.yaml" || fail "Loki S3 guidance must document the EEA region default"
if grep -Eq '^[[:space:]]+region:' "$PROJECT_ROOT/deploy/loki/loki-config.yaml"; then
    grep -Eq '^[[:space:]]+region:[[:space:]]*eu-[a-z0-9-]+' "$PROJECT_ROOT/deploy/loki/loki-config.yaml" || fail "Loki S3 region must be an EEA region"
fi
grep -Eq '^[[:space:]]+region:[[:space:]]*(eu-[a-z0-9-]+|\$\{TEMPO_S3_REGION:-eu-[a-z0-9-]+\})[[:space:]]*$' "$PROJECT_ROOT/deploy/tempo/tempo.yaml" || fail "Tempo S3 region must default to an EEA region"
printf 'PASS: telemetry storage stays on-host; configured S3 regions are EEA\n'

grep -Fq '[extra.company]' "$ZOLA_DIR/config.toml" || fail "Zola company configuration is missing"
grep -Fq 'registry_code' "$ZOLA_DIR/config.toml" || fail "Zola registry code is missing"
printf 'PASS: Zola company configuration is present\n'

if [[ ! -f "$ZOLA_DIR/public/index.html" || ! -f "$ZOLA_DIR/public/pricing/index.html" ]]; then
    command -v zola >/dev/null 2>&1 || fail "generated marketing output is missing and zola is unavailable"
    zola --root "$ZOLA_DIR" build
fi

python3 "$PROJECT_ROOT/tools/validate_pricing_drift.py"
printf 'PASS: runtime-linked pricing validation passed\n'
