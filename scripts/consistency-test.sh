#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# scripts/consistency-test.sh
# Production consistency test — validates all rendered pages against
# the canonical configuration at apps/marketing-zola/data/canonical.json
# and compliance/src/legal_entity.rs.
#
# Run on every production build. Deployment must fail when this fails.
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL_JSON="$PROJECT_ROOT/apps/marketing-zola/data/canonical.json"
ZOLA_OUTPUT_DIR="$PROJECT_ROOT/apps/marketing-zola/public"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0; FAIL=0; WARN=0

log_pass()  { printf "  ${GREEN}PASS${NC} %s\n" "$*"; PASS=$((PASS + 1)); return 0; }
log_fail()  { printf "  ${RED}FAIL${NC} %s\n" "$*"; FAIL=$((FAIL + 1)); return 0; }
log_warn()  { printf "  ${YELLOW}WARN${NC} %s\n" "$*"; WARN=$((WARN + 1)); return 0; }

echo ""
echo -e "${BOLD}=== ApexMail Canonical Consistency Tests ===${NC}"
echo "Canonical config: $CANONICAL_JSON"
echo "Zola output dir:  $ZOLA_OUTPUT_DIR"

# ─── Verify canonical JSON exists ──────────────────────────────

echo ""
if [[ ! -f "$CANONICAL_JSON" ]]; then
    echo -e "${RED}FATAL: canonical.json not found at $CANONICAL_JSON${NC}"
    exit 1
fi

# ─── Helper: extract JSON value ─────────────────────────────────

json_val() {
    python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
keys = '$1'.split('.')
val = data
for k in keys:
    if isinstance(val, list):
        val = [item.get(k, item) for item in val]
    elif isinstance(val, dict):
        val = val.get(k, '')
    else:
        val = ''
print(str(val) if not isinstance(val, (list, dict)) else json.dumps(val))
" 2>/dev/null || echo ""
}

# ─── Check if HTML output is available ──────────────────────────

html_count=$(find "$ZOLA_OUTPUT_DIR" -name "*.html" -maxdepth 3 2>/dev/null | wc -l | tr -d ' ')
HAS_HTML=false
if [[ "${html_count:-0}" -gt 0 ]]; then
    HAS_HTML=true
    echo "HTML output:    ${html_count} pages"
else
    echo "HTML output:    none (pre-build check — skipping page-level tests)"
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 1: Canonical JSON structural validation (ALWAYS runs)
# ══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── Canonical JSON Structural Validation ──${NC}"

# 1. Valid JSON
python3 -c "import json; json.load(open('$CANONICAL_JSON'))" 2>/dev/null && \
    log_pass "canonical.json is valid JSON" || \
    log_fail "canonical.json is NOT valid JSON"

# 2. All required company fields
REQUIRED_COMPANY_FIELDS=(
    "trading_name" "legal_name" "registry_code" "vat_number"
    "address_street" "address_city" "address_postal_code" "address_country"
    "address_country_code" "jurisdiction" "governing_law"
    "support_email" "privacy_email" "security_email" "sales_email" "billing_email"
    "copyright_entity" "copyright_start_year"
)
ALL_OK=true
for field in "${REQUIRED_COMPANY_FIELDS[@]}"; do
    val=$(json_val "company.$field")
    if [[ -z "$val" || "$val" == "None" || "$val" == "null" ]]; then
        log_fail "Company field '$field' is empty or null"
        ALL_OK=false
    fi
done
$ALL_OK && log_pass "All ${#REQUIRED_COMPANY_FIELDS[@]} required company fields present"

# 3. Registry code is exactly 16588745
REGISTRY_CODE=$(json_val "company.registry_code")
if [[ "$REGISTRY_CODE" == "16588745" ]]; then
    log_pass "Registry code is 16588745 in canonical.json"
else
    log_fail "Registry code mismatch: expected 16588745, got '$REGISTRY_CODE'"
fi

# 4. Legal entity is exactly Bel Consulting OÜ
LEGAL_NAME=$(json_val "company.legal_name")
if [[ "$LEGAL_NAME" == "Bel Consulting OÜ" ]]; then
    log_pass "Legal entity is Bel Consulting OÜ in canonical.json"
else
    log_fail "Legal entity mismatch: expected 'Bel Consulting OÜ', got '$LEGAL_NAME'"
fi

# 5. All 8 pricing plans present
REQUIRED_PLANS=("Free" "Developer" "Pro" "Growth" "Business" "Enterprise" "Dedicated Tenant" "BYOC")
ALL_OK=true
for plan_name in "${REQUIRED_PLANS[@]}"; do
    FOUND=$(python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
found = any(p['name'] == '$plan_name' for p in data.get('pricing_plans', []))
print('yes' if found else 'no')
" 2>/dev/null)
    if [[ "$FOUND" != "yes" ]]; then
        log_fail "Pricing plan '$plan_name' missing"
        ALL_OK=false
    fi
done
$ALL_OK && log_pass "All ${#REQUIRED_PLANS[@]} required pricing plans present"

# 6. Enterprise plan has correct price
ENTERPRISE_PRICE=$(python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
for p in data['pricing_plans']:
    if p['name'] == 'Enterprise':
        print(p['price_eur_monthly'])
        break
" 2>/dev/null)
if [[ "$ENTERPRISE_PRICE" == "3000" ]]; then
    log_pass "Enterprise price is €3,000 in canonical.json"
else
    log_fail "Enterprise price mismatch: expected 3000, got '$ENTERPRISE_PRICE'"
fi

# 7. Enterprise has 5M emails
ENTERPRISE_EMAILS=$(python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
for p in data['pricing_plans']:
    if p['name'] == 'Enterprise':
        print(p['monthly_emails'])
        break
" 2>/dev/null)
if [[ "$ENTERPRISE_EMAILS" == "5000000" ]]; then
    log_pass "Enterprise has 5,000,000 emails in canonical.json"
else
    log_fail "Enterprise email volume mismatch: expected 5000000, got '$ENTERPRISE_EMAILS'"
fi

# 8. Enterprise has 10 dedicated IPs
ENTERPRISE_IPS=$(python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
for p in data['pricing_plans']:
    if p['name'] == 'Enterprise':
        print(p['included_dedicated_ips'])
        break
" 2>/dev/null)
if [[ "$ENTERPRISE_IPS" == "10" ]]; then
    log_pass "Enterprise has 10 included dedicated IPs in canonical.json"
else
    log_fail "Enterprise dedicated IPs mismatch: expected 10, got '$ENTERPRISE_IPS'"
fi

# 9. Free plan has correct allowance
FREE_EMAILS=$(python3 -c "
import json
with open('$CANONICAL_JSON') as f:
    data = json.load(f)
for p in data['pricing_plans']:
    if p['name'] == 'Free':
        print(p['monthly_emails'])
        break
" 2>/dev/null)
if [[ "$FREE_EMAILS" == "30000" ]]; then
    log_pass "Free plan has 30,000 emails in canonical.json"
else
    log_fail "Free plan volume mismatch: expected 30000, got '$FREE_EMAILS'"
fi

# 10. Required claims fields
CLAIMS_FIELDS=(
    "api_latency_target" "api_latency_p99_target"
    "sandbox_latency_target" "private_cloud_latency_statement"
    "delivery_processing_target"
    "recipient_server_acceptance_target"
    "platform_uptime_target" "webhook_processing_target"
    "data_residency_wording"
    "certification_status" "penetration_test_status"
)
ALL_OK=true
for field in "${CLAIMS_FIELDS[@]}"; do
    val=$(json_val "claims.$field")
    if [[ -z "$val" || "$val" == "None" || "$val" == "null" ]]; then
        log_fail "Claims field '$field' is empty or null"
        ALL_OK=false
    fi
done
$ALL_OK && log_pass "All ${#CLAIMS_FIELDS[@]} required claim fields present"

# ══════════════════════════════════════════════════════════════════
# SECTION 2: Rust <-> JSON Cross-Reference (ALWAYS runs)
# ══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── Rust ↔ JSON Cross-Reference ──${NC}"

RUST_LEGAL="$PROJECT_ROOT/compliance/src/legal_entity.rs"
if [[ -f "$RUST_LEGAL" ]]; then
    grep -q "16588745" "$RUST_LEGAL" && \
        log_pass "Rust: registry_code = 16588745" || \
        log_fail "Rust: registry_code mismatch"

    grep -q 'LEGAL_NAME.*"Bel Consulting OÜ"' "$RUST_LEGAL" && \
        log_pass "Rust: LEGAL_NAME = Bel Consulting OÜ" || \
        log_fail "Rust: LEGAL_NAME mismatch"

    grep -q 'ENTERPRISE_PRICE_EUR_MONTHLY.*3_000' "$RUST_LEGAL" && \
        log_pass "Rust: ENTERPRISE_PRICE_EUR_MONTHLY = 3_000" || \
        log_fail "Rust: ENTERPRISE_PRICE_EUR_MONTHLY mismatch"

    grep -q 'ENTERPRISE_MONTHLY_EMAILS.*5_000_000' "$RUST_LEGAL" && \
        log_pass "Rust: ENTERPRISE_MONTHLY_EMAILS = 5_000_000" || \
        log_fail "Rust: ENTERPRISE_MONTHLY_EMAILS mismatch"

    grep -q 'ENTERPRISE_INCLUDED_DEDICATED_IPS.*10' "$RUST_LEGAL" && \
        log_pass "Rust: ENTERPRISE_INCLUDED_DEDICATED_IPS = 10" || \
        log_fail "Rust: ENTERPRISE_INCLUDED_DEDICATED_IPS mismatch"

    grep -q 'FREE_MONTHLY_EMAILS.*30_000' "$RUST_LEGAL" && \
        log_pass "Rust: FREE_MONTHLY_EMAILS = 30_000" || \
        log_fail "Rust: FREE_MONTHLY_EMAILS mismatch"
else
    log_warn "Rust legal_entity.rs not found at $RUST_LEGAL"
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 3: Rendered HTML validation (runs only if HTML exists)
# ══════════════════════════════════════════════════════════════════

if $HAS_HTML; then
    echo ""
    echo -e "${BOLD}── Rendered HTML Validation ──${NC}"

    # Company identity in rendered pages
    grep -rq "16588745" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: Registry code 16588745 found" || \
        log_fail "HTML: Registry code 16588745 NOT found"

    grep -rq "Bel Consulting OÜ" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: Legal entity 'Bel Consulting OÜ' found" || \
        log_fail "HTML: Legal entity 'Bel Consulting OÜ' NOT found"

    # No old/obsolete registry codes
    for OLD_CODE in "12345678" "00000000" "XX-XXXXX"; do
        grep -rq "$OLD_CODE" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
            log_fail "HTML: Forbidden value '$OLD_CODE' found in rendered pages" || \
            log_pass "HTML: No obsolete registry code '$OLD_CODE'"
    done

    # Pricing consistency
    grep -rq "30,000 emails" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: Free-plan 30,000 emails found" || \
        log_warn "HTML: Free-plan allowance not found (may be in JS)"

    grep -rq "€3,000" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: Enterprise €3,000 found" || \
        log_warn "HTML: Enterprise €3,000 not found (may be dynamically loaded)"

    # SLA
    grep -rq "99\.9%" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: SLA 99.9% found" || \
        log_warn "HTML: SLA 99.9% not found"

    # Certifications
    grep -rqi "SOC 2" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: SOC 2 references found" || \
        log_warn "HTML: SOC 2 references not found"

    grep -rqi "penetration test" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: Penetration test references found" || \
        log_warn "HTML: Penetration test references not found"

    # Prohibited absolute claims (12.1)
    grep -rq "GDPR-ready" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Prohibited 'GDPR-ready' absolute claim found" || \
        log_pass "HTML: No prohibited 'GDPR-ready' claim"

    grep -rq "100% GDPR" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Prohibited '100% GDPR' absolute claim found" || \
        log_pass "HTML: No prohibited '100% GDPR' claim"

    # Prohibited vague comparison labels (10.4, 17.1)
    grep -rq "Stochastic" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_warn "HTML: 'Stochastic' comparison label found (use factual comparison)" || \
        log_pass "HTML: No 'Stochastic' vague comparison label"

    # No incorrect entity names
    grep -rq "Bel Consulting LLC" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Incorrect 'Bel Consulting LLC' found" || \
        log_pass "HTML: No incorrect 'Bel Consulting LLC'"

    # No obsolete registry codes (17.1)
    grep -rq "16192499" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Obsolete registry code 16192499 found" || \
        log_pass "HTML: No obsolete registry code 16192499"

    grep -rq "16942833" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Obsolete registry code 16942833 found" || \
        log_pass "HTML: No obsolete registry code 16942833"

    # No €1,750 Enterprise price (2.1)
    grep -rq "€1,750" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Obsolete €1,750 Enterprise price found" || \
        log_pass "HTML: No obsolete €1,750 Enterprise price"

    # 8.1 Latency label consistency — distinct labels must exist, no conflicting generic labels
    grep -rq "Production API SLA" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: 'Production API SLA' label found" || \
        log_warn "HTML: 'Production API SLA' label not in rendered pages"

    grep -rq "Sandbox validation target" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: 'Sandbox validation target' label found" || \
        log_warn "HTML: 'Sandbox validation target' label not in rendered pages"

    grep -rq "Private Cloud.*architecture-dependent" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_pass "HTML: 'Private Cloud architecture-dependent' disclaimer found" || \
        log_warn "HTML: 'Private Cloud architecture-dependent' disclaimer not in rendered pages"

    # Prohibited performance claims (CL-025-027)
    grep -rq "zero egress" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Prohibited 'zero egress' claim found" || \
        log_pass "HTML: No prohibited 'zero egress' claim"

    grep -rq "sub-millisecond" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Prohibited 'sub-millisecond latency' claim found" || \
        log_pass "HTML: No prohibited 'sub-millisecond latency' claim"

    grep -rq "ApexMail Inc" "$ZOLA_OUTPUT_DIR"/*.html "$ZOLA_OUTPUT_DIR"/**/*.html 2>/dev/null && \
        log_fail "HTML: Incorrect 'ApexMail Inc' found" || \
        log_pass "HTML: No incorrect 'ApexMail Inc'"

    # Localized pages
    for lang_dir in "de" "fr" "es"; do
        lang_path="$ZOLA_OUTPUT_DIR/$lang_dir"
        if [[ -d "$lang_path" ]]; then
            grep -rq "16588745" "$lang_path"/*.html 2>/dev/null && \
                log_pass "HTML $lang_dir: Registry code found" || \
                log_warn "HTML $lang_dir: Registry code not found (may be template-driven)"
        fi
    done
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 4: Hard-coded duplicate detection in source
# ══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── Source Code Duplicate Detection ──${NC}"

ZOLA_DIR="$PROJECT_ROOT/apps/marketing-zola"

# Templates should not hardcode registry code
HARDCODED=$(grep -rl "16588745" "$ZOLA_DIR/templates" 2>/dev/null || true)
if [[ -z "$HARDCODED" ]]; then
    log_pass "Zola templates: no hardcoded registry code 16588745"
else
    log_warn "Zola templates: registry code found hardcoded in: $(echo "$HARDCODED" | head -3 | tr '\n' ' ')"
fi

# Config.toml should have company data
grep -q '\[extra.company\]' "$ZOLA_DIR/config.toml" 2>/dev/null && \
    log_pass "Zola config.toml: [extra.company] section present" || \
    log_fail "Zola config.toml: [extra.company] section missing"

grep -q 'registry_code' "$ZOLA_DIR/config.toml" 2>/dev/null && \
    log_pass "Zola config.toml: registry_code in [extra.company]" || \
    log_fail "Zola config.toml: registry_code missing from [extra.company]"

# Footer template uses config.extra.company
grep -q 'config.extra.company' "$ZOLA_DIR/templates/partials/footer.html" 2>/dev/null && \
    log_pass "Footer partial: uses config.extra.company" || \
    log_warn "Footer partial: does not reference config.extra.company"

# Base template uses config.extra.company
grep -q 'config.extra.company' "$ZOLA_DIR/templates/base.html" 2>/dev/null && \
    log_pass "Base template: uses config.extra.company" || \
    log_fail "Base template: does not reference config.extra.company"

# ══════════════════════════════════════════════════════════════════
# Report
# ══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
printf "  ${GREEN}PASS: %d${NC}  ${RED}FAIL: %d${NC}  ${YELLOW}WARN: %d${NC}\n" "$PASS" "$FAIL" "$WARN"
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}DEPLOYMENT BLOCKED: $FAIL consistency test(s) failed.${NC}"
    echo "Fix the failures above before deploying to production."
    exit 1
fi

echo -e "${GREEN}All consistency tests passed.${NC}"
exit 0
