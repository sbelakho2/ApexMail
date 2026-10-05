# Authentication API

The Auth API handles user authentication, session management, API key management, and account registration.

Browser sign-in is session-cookie based: `POST /v1/auth/login` sets an `am_session`
HttpOnly cookie (`SameSite=Strict`), and state-changing browser requests must present
`X-CSRF-Token` from `GET /v1/auth/csrf`. See [authentication.md](../authentication.md)
for the full session/CSRF contract.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/register` | Create a new account (alias: `POST /v1/auth/signup`) |
| POST | `/v1/auth/login` | Authenticate and receive session |
| POST | `/v1/auth/logout` | Invalidate current session |
| POST | `/v1/auth/refresh` | Refresh session token |
| POST | `/v1/auth/forgot-password` | Request password reset email |
| POST | `/v1/auth/reset-password` | Reset password with token |
| POST | `/v1/auth/verify-email` | Verify email address (token in JSON body) |
| GET | `/v1/auth/verify-email/:token` | Verify email address (link form used by emails) |
| POST | `/v1/auth/mfa/setup` | Begin TOTP enrollment (authenticated) |
| POST | `/v1/auth/mfa/confirm-setup` | Confirm TOTP enrollment with a code |
| POST | `/v1/auth/mfa/disable` | Disable MFA (current password + a valid second factor) |
| POST | `/v1/auth/mfa/verify` | Complete an MFA login challenge |
| GET | `/v1/auth/mfa/status` | MFA status for the current user |
| GET | `/v1/auth/me` | Current user profile |
| GET | `/v1/auth/api-keys` | List API keys |
| POST | `/v1/auth/api-keys` | Create API key |
| DELETE | `/v1/auth/api-keys/:id` | Revoke API key |
| POST | `/v1/auth/change-password` | Change password (revokes all OTHER sessions; current session stays signed in) |
| GET | `/v1/auth/sessions` | List the caller's active sessions |
| POST | `/v1/auth/sessions/revoke` | Revoke sessions: `{"session_id"}` targets one session, `{}` revokes all others, `{"revoke_all": true}` revokes every session including the current one |

---

## Register

Create a new ApexMail account. `POST /v1/auth/signup` is an alias for the
same handler.

### Request

```http
POST /v1/auth/register
Content-Type: application/json
X-CSRF-Token: <token from GET /v1/auth/csrf>
```

### Request Body

```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!",
  "name": "John Doe"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | ✓ | Email address |
| `password` | string | ✓ | Password (min 12 characters, must include uppercase, lowercase, number, special char) |
| `name` | string | | Display name (defaults to the email local-part) |
| `company_name` | string | | Workspace name (defaults to the email local-part) |
| `plan` | string | | Onboarding intent only: `free` (default), `starter`, `pro`, `growth`, `scale`. Never grants an entitlement by itself. |

### Response (202)

The response is deliberately generic — it is identical for a fresh signup
and an already-registered address, so the endpoint cannot be used to
enumerate accounts. The verification email carries a single-use,
24-hour link (`GET /v1/auth/verify-email/:token`).

```json
{
  "success": true,
  "message": "If the email is eligible, a verification message has been sent."
}
```

Rate-limited per IP: 20 requests per 10 minutes.

---

## Login

Authenticate with email and password.

### Request

```http
POST /v1/auth/login
Content-Type: application/json
X-CSRF-Token: <token from GET /v1/auth/csrf>
```

### Request Body

```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!"
}
```

### Response (200)

Sets the `am_session` HttpOnly cookie (`SameSite=Strict`). The session JWT
is never returned in the response body.

```json
{
  "expires_at": "2026-01-01T00:00:00+00:00",
  "user": {
    "id": "01HF...",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "owner",
    "tenant_id": "01TG..."
  }
}
```

### MFA Challenge (202)

When the account (or its role policy) requires MFA, login returns `202`
with a single-use challenge instead of a session. Complete it at
`POST /v1/auth/mfa/verify` with `challengeToken` and either `mfaCode`
(TOTP) or `recoveryCode`.

```json
{
  "status": "mfa_required",
  "challengeToken": "mfa_..."
}
```

Enrollment-forcing policies return `202` with `"status": "mfa_setup_required"`
plus `secret` and `otpauthUrl` for authenticator provisioning.

### Rate Limiting

Login attempts are rate-limited per IP (20 requests per 15 minutes). Failed
attempts trigger escalating Redis-backed account lockouts (15 min → 24 hours,
requires corroboration from a second source IP). `429` responses carry a
`Retry-After` header.

---

## Logout

Invalidate the current session (cookie revocation + JWT blacklist).

### Request

```http
POST /v1/auth/logout
Cookie: am_session=<session>
X-CSRF-Token: <token from GET /v1/auth/csrf; must match the csrf_token cookie>
```

### Response (204)

No body. The `am_session` cookie is cleared and the token is blacklisted;
replaying it returns `401 UNAUTHORIZED`.

---

## Refresh Session

Refresh an expiring session token.

### Request

```http
POST /v1/auth/refresh
Cookie: am_session=<current session>; csrf_token=<same token>
X-CSRF-Token: <token from GET /v1/auth/csrf>
```

### Response (200)

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-02-15T10:30:00Z"
}
```

---

## Forgot Password

Request a password reset email.

### Request

```http
POST /v1/auth/forgot-password
Content-Type: application/json
X-CSRF-Token: <token from GET /v1/auth/csrf>
```

### Request Body

```json
{
  "email": "user@example.com"
}
```

### Response (200)

```json
{
  "success": true
}
```

The response is identical whether or not the address is registered (anti-
enumeration). Rate-limited per IP (5 requests per 15 min) and per email
(3 requests per 15 min).

---

## Reset Password

Reset password using the token from the reset email. The email links to
`/reset-password/:token`; the API exchange requires the token AND the
account address.

### Request

```http
POST /v1/auth/reset-password
Content-Type: application/json
X-CSRF-Token: <token from GET /v1/auth/csrf>
```

### Request Body

```json
{
  "token": "reset_token_from_email",
  "email": "user@example.com",
  "password": "NewSecureP@ssw0rd!"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | ✓ | Reset token from the email link (single-use, 1-hour TTL, 24h absolute cap) |
| `email` | string | ✓ | The account's email address |
| `password` | string | ✓ | New password (same strength policy as signup) |
| `confirmPassword` | string | | Optional confirmation; must match `password` when present |

### Response (200)

All existing sessions are revoked on success.

```json
{
  "success": true,
  "message": "Password updated successfully."
}
```

---

## Verify Email

Verify email address using the verification token. Two forms:

- `POST /v1/auth/verify-email` with the token in the JSON body — the
  documented API form (the token never touches a URL).
- `GET /v1/auth/verify-email/:token` — the link form the emails use
  (single-use, 24-hour expiry; HTML clients are redirected to a
  token-free page after success).

### Request

```http
POST /v1/auth/verify-email
Content-Type: application/json
```

### Request Body

```json
{
  "token": "verification_token"
}
```

### Response (200)

```json
{
  "success": true,
  "message": "Email verified successfully. You can now log in."
}
```

---

## Multi-Factor Authentication (TOTP)

MFA enrollment is TOTP-based (SHA-256, 6 digits, 30-second period). Codes
are single-use (replay-guarded), challenges are single-attempt, and the
session rotates on every enrollment/verification.

Disabling MFA requires the account's CURRENT password plus a currently
valid second factor (TOTP code or recovery code) — a stolen session alone
is never sufficient.

### Begin Enrollment

```http
POST /v1/auth/mfa/setup
X-API-Key: {{api_key}}   (or an am_session cookie)
```

Response (200):

```json
{
  "challengeToken": "mfa_...",
  "secret": "GAQH2ICTBN5LA3EEPF5UJNKRM2NBCWQZ",
  "otpauthUrl": "otpauth://totp/ApexMail:user%40example.com?secret=...&issuer=ApexMail&algorithm=SHA256&digits=6&period=30"
}
```

### Confirm Enrollment

```http
POST /v1/auth/mfa/confirm-setup
X-API-Key: {{api_key}}
Content-Type: application/json

{ "challenge_token": "mfa_...", "mfaCode": "123456" }
```

Response (200) — the session is rotated and one-time recovery codes are
returned (each consumable once at `/v1/auth/mfa/verify`). The codes ride
under BOTH spellings (`recoveryCodes` and `recovery_codes`, identical
contents) so clients pinned to either shape keep working:

```json
{
  "mfaEnabled": true,
  "recoveryCodes": ["BZDPKHWR2H7X", "..."],
  "recovery_codes": ["BZDPKHWR2H7X", "..."]
}
```

### Complete an MFA Login Challenge

```http
POST /v1/auth/mfa/verify
Content-Type: application/json
X-CSRF-Token: <token from GET /v1/auth/csrf>

{ "challenge_token": "mfa_...", "mfaCode": "123456" }
```

Recovery codes are supplied as `"recoveryCode": "..."` — a body may carry
`mfaCode` (TOTP) or `recoveryCode`, not both being required. For
compatibility a recovery code sent in the `mfaCode` field is also accepted
(it fails the 6-digit TOTP format check and is then tried as a recovery
code). Either way every challenge token is single-use: a failed or
successful verification burns it. On success the endpoint
returns the same session shape as login (`expires_at` + `user`, plus
`recovery_codes` / `recoveryCodes` when the challenge was an enrollment)
and sets the `am_session` cookie.

### MFA Status

```http
GET /v1/auth/mfa/status
```

Response: `{ "mfaEnabled": bool, "roleRequiresMfa": bool }`

### Disable MFA

Requires the CURRENT password AND a currently-valid second factor — a
phished or stolen session can never strip the account's protection on its
own.

```http
POST /v1/auth/mfa/disable
X-CSRF-Token: <token from GET /v1/auth/csrf>
Content-Type: application/json

{ "current_password": "...", "mfaCode": "123456" }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current_password` | string | ✓ | The account's current password |
| `mfaCode` | string | one of | A current TOTP code (alias: `mfa_code`) |
| `recoveryCode` | string | one of | An unused recovery code (alias: `recovery_code`) |

Response (200):

```json
{ "mfaEnabled": false }
```

Effects on success: `mfa_secret`, `mfa_recovery_hashes` and the
`mfa_enabled` flag are cleared; the used recovery code is consumed; an
`auth.mfa_disabled` audit event records the actor and the method
(`totp` or `recovery_code`); and every OTHER session of the user is revoked
immediately (per-session revocation, exactly like a password change — the
session that performed the disable stays signed in).

Errors: `400 VALIDATION_ERROR` when MFA is not enrolled or no second factor
was supplied, `401 UNAUTHORIZED` for a wrong password or wrong second
factor, `404 NOT_FOUND` for an unknown user, `429 RATE_LIMIT_EXCEEDED`
after 5 attempts per user per 15 minutes.

---

## List Sessions

```http
GET /v1/auth/sessions
Cookie: am_session=<session>
```

Returns the CALLER's active (unexpired) sessions, newest first — the same
records `POST /v1/auth/sessions/revoke` acts on. Other users' sessions are
never returned (the query is scoped to the authenticated user id).

Response (200):

```json
[
  {
    "id": "0e8c1f2a-…",
    "created_at": "2026-01-15T10:30:00+00:00",
    "ip_address": "203.0.113.9",
    "user_agent": "Mozilla/5.0 …",
    "expires_at": "2026-01-16T10:30:00+00:00",
    "current": true
  }
]
```

`current: true` marks the session the request itself authenticated with.
`ip_address` / `user_agent` are omitted when unknown. Revoke individual
sessions via `POST /v1/auth/sessions/revoke { "session_id": "<id>" }`.

---

## API Keys

> List/create/revoke require the `api-keys:read` / `api-keys:write` scopes.
> Those two are session-only — they cannot be minted onto another API key —
> so key management runs from a dashboard session or a `*` (wildcard) key.

### List API Keys

```http
GET /v1/auth/api-keys
X-API-Key: {{api_key}}
```

#### Response (200)

Returns a plain JSON array (see the [OpenAPI](../openapi.yaml) `ApiKeyInfo` schema):

```json
[
  {
    "id": "73f1ed44-b5a3-422b-b55b-a64f31d445fd",
    "name": "Production API Key",
    "key_prefix": "am_live_…a4f3",
    "scopes": ["messages:send", "messages:read", "analytics:read"],
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-04-15T10:30:00Z",
    "last_used_at": "2024-01-20T14:30:00Z"
  }
]
```

`key_prefix` is the display form `am_live_…abcd` (the shared 8-char key head,
an ellipsis, and the LAST 4 characters of the key) so keys are
distinguishable in the list. Keys minted before this convention keep the
bare `am_live_` prefix until they expire and are re-created.

### Create API Key

```http
POST /v1/auth/api-keys
X-API-Key: {{api_key}}
Content-Type: application/json
```

#### Request Body

```json
{
  "name": "Production API Key",
  "scopes": ["messages:send", "messages:read", "analytics:read"],
  "expires_in_days": 90
}
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Human-readable key name |
| `scopes` | string[] | ✓ | Access scopes (max 50) |
| `expires_in_days` | number | | Key expiry (1-365, default 90) |

#### Response (201)

```json
{
  "id": "73f1ed44-b5a3-422b-b55b-a64f31d445fd",
  "key": "am_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "key_prefix": "am_live_…xxxx",
  "name": "Production API Key",
  "scopes": ["messages:send", "messages:read", "analytics:read"],
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-04-15T10:30:00Z"
}
```

> **Important**: The full key value is only returned at creation time. Store it securely.

### Revoke API Key

```http
DELETE /v1/auth/api-keys/{id}
X-API-Key: {{api_key}}
```

#### Response (204)

`204 No Content` with an empty body — the key stops authenticating
immediately (in-flight cache entries are invalidated on revoke). Revoking a
non-existent id returns `404 NOT_FOUND`.
```

---

## Change Password

```http
POST /v1/auth/change-password
X-CSRF-Token: <token>
```

```json
{ "current_password": "...", "new_password": "..." }
```

Response `200`: `{ "changed": true }`.

The session that performed the change STAYS signed in; every other session of
the user is revoked immediately (per-session revocation — their JWTs and
refresh attempts fail with `401 session has been revoked`). The new password
takes effect on the next login.

---

## Revoke Sessions

```http
POST /v1/auth/sessions/revoke
X-CSRF-Token: <token>
```

Three shapes, one endpoint:

| Body | Effect | Current session |
|------|--------|-----------------|
| `{ "session_id": "<id>" }` | Revoke that one session (`404` if it does not exist or belongs to another user) | dies only if it IS the target |
| `{}` | Revoke all of the user's OTHER sessions | survives |
| `{ "revoke_all": true }` | Revoke every session of the user | dies |

Response `200`: `{ "revoked": <n> }` — the number of session records deleted.
Each revoked session is marked by its own `jti` in the revocation registry, so
the request-scoped session is never collateral damage of a targeted revoke.

---

## Available Scopes

| Scope | Description |
|-------|-------------|
| `*` | Full access (admin/owner only) |
| `messages:send` | Send email messages |
| `messages:read` | View message details and history |
| `analytics:read` | Access analytics dashboards and exports |
| `webhooks:read` | View webhook configurations |
| `webhooks:write` | Create and modify webhooks |
| `templates:read` | View email templates |
| `templates:write` | Create and modify templates |
| `domains:read` | View sending domains |
| `domains:write` | Add and verify domains |
| `campaigns:read` | View campaigns |
| `campaigns:write` | Create and modify campaigns |
| `contacts:read` | View contacts |
| `contacts:write` | Create and modify contacts |
| `suppressions:read` | View suppression lists |
| `suppressions:write` | Create and remove suppressions |
| `automations:read` | View automations |
| `automations:write` | Create and modify automations |
| `dedicated_ips:read` | View dedicated IPs |
| `dedicated_ips:write` | Allocate and manage dedicated IPs |
| `events:read` | View message events (delivered, bounced, opened, clicked) |
| `support:read` | View support tickets |
| `support:write` | Create and reply to support tickets |
| `billing:read` | View billing information |
| `billing:write` | Change plan, manage wallet (mintable but never role-granted — wildcard holders only) |
| `scim:read` | List SCIM users (mintable but never role-granted — wildcard holders only) |
| `scim:write` | Create/modify/delete SCIM users (mintable but never role-granted — wildcard holders only) |
| `ai:read` | AI chat and insights (mintable but never role-granted — wildcard holders only) |
| `api-keys:read` | List API keys (session-only — cannot be minted onto another key) |
| `api-keys:write` | Create/revoke API keys (session-only — cannot be minted onto another key) |
| `logs:read` | Access audit logs |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid email or password (identical for unknown email and wrong password — anti-enumeration) |
| `FORBIDDEN` | 403 | Account is not active, SSO required, or email not verified (disclosed only after the password verifies) |
| `VALIDATION_ERROR` | 400 | Malformed request body or invalid/expired token |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests (carries `Retry-After`) |
| `EMAIL_ALREADY_EXISTS` | — | Never returned: duplicate signups get the same generic `202` as fresh ones |
