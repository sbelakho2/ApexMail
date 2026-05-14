#!/usr/bin/env bash
# Static route audit: every public/auth route + dashboard route renders 200.
# Authenticates via the e2e flow first, then probes protected routes.
set -uo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3001}"
PG_CONTAINER="${PG_CONTAINER:-apexmail-postgres}"
PG_USER="${PG_USER:-apexmail}"
PG_DB="${PG_DB:-apexmail}"

PUBLIC_ROUTES=(
  "/" "/login" "/signup" "/forgot-password" "/reset-password"
  "/verify-email"
)
# Marketing routes (/pricing, /features, /docs etc.) are served by the
# separate Zola static site under apexmail.ee — out of scope for the
# Rust API server route audit.

# Routes that need auth.
AUTH_ROUTES=(
  "/dashboard" "/campaigns" "/campaigns/new" "/contacts" "/contacts/new"
  "/lists" "/lists/new" "/templates" "/templates/new" "/reports"
  "/reports/deliverability" "/analytics" "/inbox-placement"
  "/inbox-placement/new" "/events" "/domains" "/domains/new"
  "/settings" "/settings/api-keys" "/settings/team" "/settings/billing"
  "/settings/dedicated-ips" "/settings/webhooks" "/settings/profile"
)

CP_ROUTES=(
  "/cp" "/cp/tenants" "/cp/infra" "/cp/security" "/cp/audit" "/cp/sales"
)

pass=0; fail=0; failures=()

probe() {
  local path="$1" cookie="${2:-}" expect="${3:-200}"
  local code
  if [[ -n "$cookie" ]]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" "$BASE_URL$path")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL$path")
  fi
  if [[ "$code" == "$expect" ]]; then
    pass=$((pass+1))
    printf '  \033[32m✓\033[0m %-40s %s\n' "$path" "$code"
  else
    fail=$((fail+1))
    failures+=("$path expected $expect got $code")
    printf '  \033[31m✗\033[0m %-40s %s (expected %s)\n' "$path" "$code" "$expect"
  fi
}

echo "=== PUBLIC ROUTES (no auth) ==="
for p in "${PUBLIC_ROUTES[@]}"; do probe "$p"; done

echo
echo "=== Establishing authenticated session via E2E flow ==="
EMAIL="apex-route-audit-$(date +%s%N)@example.test"
PASS='Apex!Audit2026Pass'
NAME='Route Audit'; COMPANY='Audit Co'

curl -fsS -X POST "$BASE_URL/v1/auth/signup" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg e "$EMAIL" --arg p "$PASS" --arg n "$NAME" --arg c "$COMPANY" \
        '{email:$e,password:$p,name:$n,company_name:$c}')" >/dev/null \
  || { echo "signup failed"; exit 1; }

TOKEN=""
for i in 1 2 3 4 5; do
  HTML=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -At -c \
    "SELECT html_body FROM messages WHERE to_emails::text ILIKE '%${EMAIL}%' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null)
  TOKEN=$(echo "$HTML" | grep -oE 'token=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2)
  [[ -n "$TOKEN" ]] && break; sleep 1
done
[[ -n "$TOKEN" ]] || { echo "token not found"; exit 1; }
curl -fsS "$BASE_URL/v1/auth/verify-email?token=$TOKEN" >/dev/null

LOGIN_BODY=$(curl -sS -X POST "$BASE_URL/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg e "$EMAIL" --arg p "$PASS" '{email:$e,password:$p}')")
CHALLENGE=$(echo "$LOGIN_BODY" | jq -r '.challengeToken // empty')
SECRET=$(echo "$LOGIN_BODY" | jq -r '.secret // empty')
COOKIE=""
if [[ -n "$CHALLENGE" && -n "$SECRET" ]]; then
  CODE=$(python3 -c "
import hmac, hashlib, struct, time, base64
key=base64.b32decode('$SECRET'); counter=int(time.time())//30
msg=struct.pack('>Q', counter); h=hmac.new(key, msg, hashlib.sha256).digest()
o=h[-1]&0x0f; print(f'{(struct.unpack(\">I\", h[o:o+4])[0]&0x7fffffff)%1000000:06d}')")
  HEADERS=$(curl -sS -D - -o /dev/null -X POST "$BASE_URL/v1/auth/mfa/verify" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg t "$CHALLENGE" --arg c "$CODE" '{challenge_token:$t,mfaCode:$c}')")
  COOKIE=$(echo "$HEADERS" | grep -i '^set-cookie:' | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*//; s/;.*$//' | grep '^am_session=' | head -1)
fi
[[ -n "$COOKIE" ]] || { echo "could not establish session cookie"; exit 1; }
echo "session cookie: ${COOKIE:0:30}..."

echo
echo "=== AUTHENTICATED APP ROUTES ==="
for p in "${AUTH_ROUTES[@]}"; do probe "$p" "$COOKIE"; done

echo
echo "=== CONTROL-PLANE ROUTES (Host: localhost — own auth context) ==="
for p in "${CP_ROUTES[@]}"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $COOKIE" "$BASE_URL$p")
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "303" || "$code" == "401" || "$code" == "403" ]]; then
    pass=$((pass+1))
    printf '  \033[32m✓\033[0m %-40s %s\n' "$p" "$code"
  else
    fail=$((fail+1))
    failures+=("$p got $code")
    printf '  \033[31m✗\033[0m %-40s %s\n' "$p" "$code"
  fi
done

echo
echo "================================"
echo "PASS: $pass  FAIL: $fail"
if (( fail > 0 )); then
  printf '\nfailures:\n'
  for f in "${failures[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "ALL ROUTES OK"
