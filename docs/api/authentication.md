# API Authentication

ApexMail supports multiple authentication methods for different use cases.

## Authentication Methods

| Method | Use Case | Security Level |
|--------|----------|----------------|
| API Keys | Server-to-server | Medium |
| JWT Tokens | User sessions | High |
| OAuth 2.0 | Third-party apps | High |

---

## API Keys

### Overview
API keys are long-lived credentials for server-to-server communication.

### Creating API Keys
```http
POST /v1/auth/api-keys
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "name": "Production Server",
  "scopes": ["messages:write", "templates:read"],
  "expiresAt": "2025-12-31T23:59:59Z",
  "allowedIps": ["10.0.0.0/8", "192.168.1.0/24"]
}
```

Response:
```json
{
  "apiKey": {
    "id": "key_abc123",
    "name": "Production Server",
    "prefix": "am_live_XXXXXX",
    "secretKey": "am_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "scopes": ["messages:write", "templates:read"],
    "expiresAt": "2025-12-31T23:59:59Z",
    "createdAt": "2024-01-15T10:30:00Z"
  },
  "warning": "Store the secret key securely. It will not be shown again."
}
```

> ⚠️ **Important**: The full API key is only shown once. Store it securely.

### Using API Keys
Include the API key in the `X-API-Key` header:

```http
POST /v1/messages
X-API-Key: am_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Content-Type: application/json

{
  "to": "user@example.com",
  "from": "hello@company.com",
  "subject": "Welcome!",
  "html": "<p>Hello World</p>"
}
```

### Key Prefixes
| Prefix | Environment | Purpose |
|--------|-------------|---------|
| `am_live_` | Production | Sending emails |
| `am_test_` | Sandbox | Testing (no delivery) |

### Scopes
| Scope | Description |
|-------|-------------|
| `messages:send` | Send transactional emails (basic send only) |
| `messages:write` | Send and manage transactional emails |
| `messages:read` | View message history |
| `templates:read` | Read templates |
| `templates:write` | Create/update templates |
| `webhooks:read` | View webhooks |
| `webhooks:write` | Create/update/delete webhooks |
| `domains:read` | View domains |
| `domains:write` | Manage domains |
| `suppressions:read` | View suppressions |
| `suppressions:write` | Manage suppressions |
| `analytics:read` | Access analytics |
| `events:read` | View events |
| `events:write` | Write custom events |
| `contacts:read` | View contacts |
| `contacts:write` | Manage contacts |
| `dedicated-ips:read` | View dedicated IPs |
| `dedicated-ips:write` | Manage dedicated IPs |
| `admin` | Full administrative access |

### Revoking Keys
```http
DELETE /v1/auth/api-keys/key_abc123
Authorization: Bearer {{jwt_token}}
```

---

## JWT Authentication

### Overview
JWT tokens are used for user authentication in the dashboard and API.

### Login Flow
```http
POST /v1/auth/login
Content-Type: application/json

{
  "email": "user@company.com",
  "password": "secure_password"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": "1h",
  "user": {
    "id": "usr_abc123",
    "email": "user@company.com",
    "name": "John Doe",
    "role": "admin",
    "tenantId": "ten_xyz"
  }
}
```

### Token Contents

Access tokens contain the following claims:

| Claim | Description |
|-------|-------------|
| User ID | Identifies the authenticated user (`sub`) |
| Tenant ID | The tenant the token is scoped to (`tid`) |
| Role | The user's role (owner, admin, editor, viewer) |
| Scopes | Granted permission scopes |
| Expiration | Access tokens expire based on server config (`exp`) |

Tokens are signed with **HS256**. Use `POST /v1/auth/refresh` with a valid token to obtain a new one before expiry.

### Using Access Tokens
```http
GET /v1/account
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token Refresh
```http
POST /v1/auth/refresh
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": "1h",
  "user": {
    "id": "usr_abc123",
    "email": "user@company.com",
    "name": "John Doe",
    "role": "admin",
    "tenantId": "ten_xyz"
  }
}
```

### Token Logout (Revocation)
```http
POST /v1/auth/logout
Authorization: Bearer {{access_token}}
```

Response:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### Security Features
- Access tokens are short-lived and refresh tokens are rotated on each use.
- Refresh token reuse is detected and results in immediate session revocation.

---

## OAuth 2.0

### Overview
OAuth 2.0 enables third-party applications to access ApexMail on behalf of users.

### Supported Flows
| Flow | Use Case |
|------|----------|
| Authorization Code + PKCE | Web/mobile apps |
| Client Credentials | Machine-to-machine |

### Authorization Code Flow (PKCE)

#### 1. Generate Code Verifier
```python
import base64
import hashlib
import secrets

code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()
```

#### 2. Authorization Request
```
GET /oauth/authorize?
  response_type=code&
  client_id=app_xyz789&
  redirect_uri=https://yourapp.com/callback&
  scope=messages:write%20analytics:read&
  state=random_state_value&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256
```

#### 3. User Authorization
User is redirected to ApexMail login, authorizes the application.

#### 4. Authorization Response
```
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?
  code=AUTH_CODE&
  state=random_state_value
```

#### 5. Token Exchange
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://yourapp.com/callback&
client_id=app_xyz789&
code_verifier=CODE_VERIFIER
```

Response:
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "messages:write analytics:read"
}
```

### Client Credentials Flow

For server-to-server integrations without user context:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=app_xyz789&
client_secret=SECRET&
scope=messages:write
```

### Registering OAuth Applications

```http
POST /v1/oauth/apps
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "name": "My Integration",
  "redirectUris": [
    "https://myapp.com/callback",
    "http://localhost:3000/callback"
  ],
  "scopes": ["messages:write", "analytics:read"],
}
```

Response:
```json
{
  "id": "app_xyz789",
  "name": "My Integration",
  "clientId": "app_xyz789",
  "clientSecret": "cs_XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "redirectUris": ["https://myapp.com/callback"],
  "scopes": ["messages:write", "analytics:read"],
  "createdAt": "2024-01-15T10:30:00Z"
}
```

---

## Multi-Factor Authentication

### Enabling MFA
```http
POST /v1/auth/mfa/enable
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "method": "totp"
}
```

Response:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCode": "data:image/png;base64,...",
  "backupCodes": [
    "abc123def456",
    "ghi789jkl012",
    "mno345pqr678",
    "stu901vwx234",
    "yza567bcd890"
  ]
}
```

### Verifying MFA Setup
```http
POST /v1/auth/mfa/verify
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "code": "123456"
}
```

### MFA Methods
| Method | Description |
|--------|-------------|
| `totp` | Time-based OTP (Google Authenticator) |
| `sms` | SMS verification code |
| `email` | Email verification code |
| `webauthn` | Hardware security keys |

---

## Security Best Practices

### API Key Security
1. **Never expose keys in client-side code**
2. **Use IP whitelisting** for production keys
3. **Rotate keys regularly** (recommended: 90 days)
4. **Use minimal scopes** for each integration
5. **Monitor key usage** via activity logs

### JWT Security
1. **Store tokens securely** (httpOnly cookies preferred)
2. **Implement proper logout** (revoke refresh tokens)
3. **Handle token expiration** gracefully
4. **Use short-lived access tokens** (1 hour max)

### OAuth Security
1. **Always use PKCE** for public clients
2. **Validate redirect URIs** exactly
3. **Use state parameter** to prevent CSRF
4. **Request minimal scopes**
5. **Implement token revocation** on app uninstall

---

## Error Responses

### Authentication Errors

| Code | Error | Description |
|------|-------|-------------|
| 401 | `INVALID_API_KEY` | API key invalid or expired |
| 401 | `INVALID_TOKEN` | Token expired or invalid |
| 401 | `TOKEN_REVOKED` | Token has been revoked |
| 401 | `AUTH_REQUIRED` | No authentication provided |
| 403 | `INSUFFICIENT_SCOPE` | Missing required scope |
| 403 | `INVALID_SCOPE` | API key contains unrecognised scopes |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |

### Example Error Response
```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "The access token has expired"
  }
}
```
