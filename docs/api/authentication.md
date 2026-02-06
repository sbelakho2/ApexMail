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
POST /api/v1/api-keys
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "name": "Production Server",
  "scopes": ["messages:send", "templates:read"],
  "expiresAt": "2025-12-31T23:59:59Z",
  "ipWhitelist": ["10.0.0.0/8", "192.168.1.0/24"]
}
```

Response:
```json
{
  "id": "key_abc123",
  "name": "Production Server",
  "key": "am_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "scopes": ["messages:send", "templates:read"],
  "expiresAt": "2025-12-31T23:59:59Z",
  "ipWhitelist": ["10.0.0.0/8", "192.168.1.0/24"],
  "createdAt": "2024-01-15T10:30:00Z"
}
```

> ⚠️ **Important**: The full API key is only shown once. Store it securely.

### Using API Keys
Include the API key in the `Authorization` header:

```http
POST /api/v1/messages
Authorization: Bearer am_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
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
| `messages:send` | Send transactional emails |
| `messages:read` | View message history |
| `templates:read` | Read templates |
| `templates:write` | Create/update templates |
| `campaigns:read` | View campaigns |
| `campaigns:write` | Create/manage campaigns |
| `analytics:read` | Access analytics |
| `contacts:read` | View contacts |
| `contacts:write` | Manage contacts |
| `webhooks:manage` | Configure webhooks |
| `account:read` | View account info |
| `account:write` | Modify account settings |

### Revoking Keys
```http
DELETE /api/v1/api-keys/key_abc123
Authorization: Bearer {{jwt_token}}
```

---

## JWT Authentication

### Overview
JWT tokens are used for user authentication in the dashboard and API.

### Login Flow
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@company.com",
  "password": "secure_password",
  "mfaCode": "123456"  // If MFA enabled
}
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600,
  "tokenType": "Bearer",
  "user": {
    "id": "usr_abc123",
    "email": "user@company.com",
    "name": "John Doe",
    "role": "admin"
  }
}
```

### Token Structure
```typescript
interface AccessTokenPayload {
  sub: string;           // User ID
  email: string;         // User email
  accountId: string;     // Account ID
  role: string;          // User role
  permissions: string[]; // Granted permissions
  iat: number;           // Issued at
  exp: number;           // Expiration (1 hour)
  jti: string;           // Token ID (for revocation)
}

interface RefreshTokenPayload {
  sub: string;           // User ID
  accountId: string;     // Account ID
  iat: number;           // Issued at
  exp: number;           // Expiration (30 days)
  jti: string;           // Token ID
  family: string;        // Token family (rotation)
}
```

### Using Access Tokens
```http
GET /api/v1/account
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token Refresh
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600
}
```

### Token Revocation
```http
POST /api/v1/auth/revoke
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Security Features
- **Algorithm**: ES256 (ECDSA with P-256 curve)
- **Access Token TTL**: 1 hour
- **Refresh Token TTL**: 30 days
- **Token Rotation**: Refresh tokens rotated on use
- **Family Tracking**: Detects refresh token reuse attacks

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
```javascript
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');
```

#### 2. Authorization Request
```
GET /oauth/authorize?
  response_type=code&
  client_id=app_xyz789&
  redirect_uri=https://yourapp.com/callback&
  scope=messages:send%20analytics:read&
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
  "scope": "messages:send analytics:read"
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
scope=messages:send
```

### Registering OAuth Applications

```http
POST /api/v1/oauth/apps
Authorization: Bearer {{jwt_token}}
Content-Type: application/json

{
  "name": "My Integration",
  "redirectUris": [
    "https://myapp.com/callback",
    "http://localhost:3000/callback"
  ],
  "scopes": ["messages:send", "analytics:read"],
  "grantTypes": ["authorization_code", "refresh_token"]
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
  "scopes": ["messages:send", "analytics:read"],
  "createdAt": "2024-01-15T10:30:00Z"
}
```

---

## Multi-Factor Authentication

### Enabling MFA
```http
POST /api/v1/auth/mfa/enable
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
POST /api/v1/auth/mfa/verify
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
| 401 | `invalid_token` | Token expired or invalid |
| 401 | `token_revoked` | Token has been revoked |
| 401 | `invalid_api_key` | API key invalid or expired |
| 403 | `insufficient_scope` | Missing required scope |
| 403 | `ip_not_allowed` | IP not in whitelist |
| 429 | `rate_limited` | Too many requests |

### Example Error Response
```json
{
  "error": {
    "code": "invalid_token",
    "message": "The access token has expired",
    "details": {
      "expiredAt": "2024-01-15T11:30:00Z"
    }
  }
}
```
