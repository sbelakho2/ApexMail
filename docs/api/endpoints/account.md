# Account API

The Account API allows users to view their profile and manage their account lifecycle.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/account/profile` | Get user profile |
| DELETE | `/v1/account` | Schedule account deletion |

---

## Get Profile

Retrieve the authenticated user's profile information.

### Request

```http
GET /v1/account/profile
X-API-Key: {{api_key}}
```

### Response

```json
{
  "user_id": "usr_abc123",
  "tenant_id": "ten_xyz789",
  "email": "user@example.com",
  "name": "John Doe",
  "role": "owner",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | string | Unique user identifier |
| `tenant_id` | string | Tenant (account) identifier |
| `email` | string | User's email address |
| `name` | string or null | User's display name |
| `role` | string | User role: `owner`, `admin`, `developer`, `viewer` |
| `created_at` | string | Account creation timestamp (ISO 8601) |

---

## Delete Account

Schedule account (tenant) deletion. Requires owner-level access (`*` scope).

### Request

```http
DELETE /v1/account
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "password": "CurrentPassword123!",
  "confirmation": "DELETE MY ACCOUNT",
  "reason": "Switching to another provider"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | string | ✓ | Current password for verification |
| `confirmation` | string | ✓ | Must be exactly `DELETE MY ACCOUNT` |
| `reason` | string | | Optional reason for leaving |

### Response (200)

```json
{
  "success": true,
  "message": "Account deletion scheduled. You have 30 days to cancel this request.",
  "deletion_scheduled_at": "2024-02-14T10:30:00Z"
}
```

> **Important**: Deletion is scheduled 30 days in the future. During this grace period, the account can be recovered by contacting support. All users in the tenant are disabled immediately upon scheduling deletion.

### Error Responses

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid password |
| `VALIDATION_ERROR` | 422 | Confirmation phrase doesn't match |
| `FORBIDDEN` | 403 | Non-owner users cannot delete account |
| `FORBIDDEN` | 403 | API keys without `*` scope cannot delete account |

---

## Role-Based Access

| Action | Required Scope |
|--------|----------------|
| View profile | Any authenticated user |
| Delete account | `*` (owner-level) |

### Role Hierarchy

| Role | Capabilities |
|------|-------------|
| `owner` | Full access, account deletion, billing management |
| `admin` | Full access except account deletion |
| `developer` | API access with configurable scopes |
| `viewer` | Read-only access |
