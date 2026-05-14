# Authentication API

The Auth API handles user authentication, session management, API key management, and account registration.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/register` | Create a new account |
| POST | `/v1/auth/login` | Authenticate and receive session |
| POST | `/v1/auth/logout` | Invalidate current session |
| POST | `/v1/auth/refresh` | Refresh session token |
| POST | `/v1/auth/forgot-password` | Request password reset email |
| POST | `/v1/auth/reset-password` | Reset password with token |
| POST | `/v1/auth/verify-email` | Verify email address |
| GET | `/v1/auth/api-keys` | List API keys |
| POST | `/v1/auth/api-keys` | Create API key |
| DELETE | `/v1/auth/api-keys/:id` | Revoke API key |

---

## Register

Create a new ApexMail account.

### Request

```http
POST /v1/auth/register
Content-Type: application/json
```

### Request Body

```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!",
  "name": "John Doe",
  "acceptTerms": true
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | ✓ | Email address |
| `password` | string | ✓ | Password (min 12 characters, must include uppercase, lowercase, number, special char) |
| `name` | string | | Display name |
| `acceptTerms` | boolean | ✓ | Must accept terms of service |

### Response (201)

```json
{
  "user_id": "usr_abc123",
  "tenant_id": "ten_xyz789",
  "email": "user@example.com",
  "requires_email_verification": true
}
```

---

## Login

Authenticate with email and password.

### Request

```http
POST /v1/auth/login
Content-Type: application/json
```

### Request Body

```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!"
}
```

### Response (200)

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "owner",
    "tenant_id": "ten_xyz789"
  },
  "mfa_required": false
}
```

### Rate Limiting

Login attempts are rate-limited per IP (5 requests per 15 minutes) and per email (3 requests per 15 minutes). Excessive failures trigger escalating lockouts (15 min → 24 hours).

---

## Logout

Invalidate the current session.

### Request

```http
POST /v1/auth/logout
X-API-Key: {{api_key}}
```

### Response (200)

```json
{
  "success": true,
  "message": "Session invalidated"
}
```

---

## Refresh Session

Refresh an expiring session token.

### Request

```http
POST /v1/auth/refresh
Cookie: session=existing_session_token
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
  "success": true,
  "message": "If the email exists, a reset link has been sent"
}
```

Rate-limited per IP (5 requests per 15 min) and per email (3 requests per 15 min).

---

## Reset Password

Reset password using the token from the reset email.

### Request

```http
POST /v1/auth/reset-password
Content-Type: application/json
```

### Request Body

```json
{
  "token": "reset_token_from_email",
  "password": "NewSecureP@ssw0rd!"
}
```

### Response (200)

```json
{
  "success": true,
  "message": "Password has been reset"
}
```

---

## Verify Email

Verify email address using the verification token.

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
  "message": "Email verified successfully"
}
```

---

## API Keys

### List API Keys

```http
GET /v1/auth/api-keys
X-API-Key: {{api_key}}
```

#### Response

```json
{
  "data": [
    {
      "id": "ak_abc123",
      "name": "Production API Key",
      "prefix": "am_live_",
      "scopes": ["messages:send", "messages:read", "analytics:read"],
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-04-15T10:30:00Z",
      "last_used_at": "2024-01-20T14:30:00Z"
    }
  ]
}
```

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
| `scopes` | string[] | ✓ | Access scopes (max 10) |
| `expires_in_days` | number | | Key expiry (max 365, default 90) |

#### Response (201)

```json
{
  "id": "ak_abc123",
  "name": "Production API Key",
  "key": "am_live_xxxxxxxxxxxxxxxxxxxxxxxx",
  "scopes": ["messages:send", "messages:read", "analytics:read"],
  "expires_at": "2024-04-15T10:30:00Z"
}
```

> **Important**: The full key value is only returned at creation time. Store it securely.

### Revoke API Key

```http
DELETE /v1/auth/api-keys/ak_abc123
X-API-Key: {{api_key}}
```

#### Response (200)

```json
{
  "success": true,
  "message": "API key revoked"
}
```

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
| `billing:read` | View billing information |
| `logs:read` | Access audit logs |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `ACCOUNT_LOCKED` | 423 | Account temporarily locked due to too many attempts |
| `EMAIL_ALREADY_EXISTS` | 409 | Email already registered |
| `INVALID_TOKEN` | 400 | Reset/verification token expired or invalid |
| `WEAK_PASSWORD` | 422 | Password doesn't meet strength requirements |
| `MFA_REQUIRED` | 401 | Multi-factor authentication challenge required |
