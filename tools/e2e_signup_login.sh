#!/usr/bin/env bash
# End-to-end smoke test: signup -> extract verification token from email
# queue -> verify-email -> login -> dashboard. Exits 0 on success.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3001}"
PG_CONTAINER="${PG_CONTAINER:-apexmail-postgres}"
PG_USER="${PG_USER:-apexmail}"
PG_DB="${PG_DB:-apexmail}"

EMAIL="apexmail-e2e-$(date +%s%N)@example.test"
PASSWORD='Apex!Test2026Pass'
NAME='Apex E2E'
COMPANY='Apex E2E Co'

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

step "Health check $BASE_URL"
curl -fsS "$BASE_URL/healthz" >/dev/null || curl -fsS "$BASE_URL/health/live" >/dev/null \
  || fail "server not reachable at $BASE_URL"
ok "server reachable"

step "GET /signup (verifies form renders + script tag)"
SIGNUP_HTML=$(curl -fsS -H 'Host: app.apexmail.local' "$BASE_URL/signup")
echo "$SIGNUP_HTML" | grep -q 'name="company_name"' || fail "signup form missing company_name field"
echo "$SIGNUP_HTML" | grep -q 'data-authBound\|authBound' || fail "auth-form bridge script missing"
echo "$SIGNUP_HTML" | grep -q 'action="/v1/auth/signup"' || fail "signup form action wrong"
ok "signup form OK"

step "POST /v1/auth/signup as JSON ($EMAIL)"
SIGNUP_RES=$(curl -sS -o /tmp/e2e_signup.json -w '%{http_code}' \
  -X POST "$BASE_URL/v1/auth/signup" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d "$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" --arg n "$NAME" --arg c "$COMPANY" \
        '{email:$e,password:$p,name:$n,company_name:$c}')")
[[ "$SIGNUP_RES" == "202" || "$SIGNUP_RES" == "200" || "$SIGNUP_RES" == "201" ]] \
  || fail "signup expected 2xx got $SIGNUP_RES (body: $(cat /tmp/e2e_signup.json))"
ok "signup accepted ($SIGNUP_RES)"

step "Extract verification token from messages queue"
# Wait briefly for the INSERT to be visible
TOKEN=""
for i in 1 2 3 4 5; do
  HTML_BODY=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -At -c \
    "SELECT html_body FROM messages WHERE to_emails::text ILIKE '%${EMAIL}%' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null || true)
  TOKEN=$(echo "$HTML_BODY" | grep -oE 'token=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2 || true)
  [[ -n "$TOKEN" ]] && break
  sleep 1
done
[[ -n "$TOKEN" ]] || fail "verification token not found in messages table for $EMAIL"
ok "token extracted (${TOKEN:0:8}...)"

step "GET /v1/auth/verify-email"
VERIFY_RES=$(curl -sS -o /tmp/e2e_verify.json -w '%{http_code}' \
  "$BASE_URL/v1/auth/verify-email?token=$TOKEN")
[[ "$VERIFY_RES" == "200" ]] \
  || fail "verify expected 200 got $VERIFY_RES (body: $(cat /tmp/e2e_verify.json))"
grep -q '"success":true' /tmp/e2e_verify.json || fail "verify response missing success:true"
ok "email verified"

step "GET /login (renders form + bridge script)"
LOGIN_HTML=$(curl -fsS -H 'Host: app.apexmail.local' "$BASE_URL/login")
echo "$LOGIN_HTML" | grep -q 'action="/v1/auth/login"' || fail "login form action wrong"
ok "login form OK"

step "POST /v1/auth/login as JSON (initial)"
LOGIN_RES=$(curl -sS -o /tmp/e2e_login.json -D /tmp/e2e_login.headers -w '%{http_code}' \
  -X POST "$BASE_URL/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d "$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{email:$e,password:$p}')")

# If owner/admin signup triggers MFA setup challenge, complete it.
if [[ "$LOGIN_RES" == "202" ]]; then
  STATUS=$(jq -r '.status // ""' /tmp/e2e_login.json)
  if [[ "$STATUS" == "mfa_setup_required" ]]; then
    step "MFA setup required → completing TOTP challenge"
    CHALLENGE=$(jq -r '.challengeToken' /tmp/e2e_login.json)
    SECRET=$(jq -r '.secret' /tmp/e2e_login.json)
    [[ -n "$CHALLENGE" && -n "$SECRET" ]] || fail "missing challengeToken/secret in MFA payload"
    CODE=$(python3 -c "
import hmac, hashlib, struct, time, base64, sys
secret='$SECRET'
key=base64.b32decode(secret)
counter=int(time.time())//30
msg=struct.pack('>Q', counter)
h=hmac.new(key, msg, hashlib.sha256).digest()
o=h[-1] & 0x0f
code=(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print(f'{code:06d}')
")
    [[ -n "$CODE" ]] || fail "could not compute TOTP"
    ok "TOTP computed: $CODE"
    LOGIN_RES=$(curl -sS -o /tmp/e2e_login.json -D /tmp/e2e_login.headers -w '%{http_code}' \
      -X POST "$BASE_URL/v1/auth/mfa/verify" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json' \
      -d "$(jq -n --arg t "$CHALLENGE" --arg c "$CODE" '{challenge_token:$t, mfaCode:$c}')")
  fi
fi

[[ "$LOGIN_RES" == "200" ]] \
  || fail "login expected 200 got $LOGIN_RES (body: $(cat /tmp/e2e_login.json))"
grep -qi '^set-cookie:.*am_session=' /tmp/e2e_login.headers \
  || fail "login response missing am_session Set-Cookie ($(grep -i set-cookie /tmp/e2e_login.headers || echo none))"
ok "login OK + am_session cookie set"

# Capture cookie for dashboard request
COOKIE=$(grep -i '^set-cookie:' /tmp/e2e_login.headers \
  | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*//; s/;.*$//' \
  | grep '^am_session=' | head -1)
[[ -n "$COOKIE" ]] || fail "could not parse am_session cookie"

step "GET /dashboard with session cookie"
DASH_HTML=$(curl -fsS -H 'Host: app.apexmail.local' -H "Cookie: $COOKIE" "$BASE_URL/dashboard")
echo "$DASH_HTML" | grep -qi '<main\|dashboard\|sent\|emails' \
  || fail "dashboard render did not contain expected content"
ok "dashboard rendered for authenticated user"

printf '\n\033[1;32m================================\nE2E PASS: signup → verify → login → dashboard\n================================\033[0m\n'
