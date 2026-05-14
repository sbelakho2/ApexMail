# SCIM 2.0 Provisioning API

Enterprise SCIM (System for Cross-domain Identity Management) 2.0 provisioning endpoints for automating user and group management with identity providers (IdPs) such as Okta, Azure AD, OneLogin, and Google Workspace.

All endpoints require **admin scope** (`*`) and are only available on **Enterprise plans**.

## Base URL

All SCIM endpoints are mounted under `/v1/scim`:

```
https://api.apexmail.ee/v1/scim
```

## Endpoints

### Users

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/scim/Users` | List users |
| `POST` | `/v1/scim/Users` | Create a user |
| `GET` | `/v1/scim/Users/:id` | Get user details |
| `PUT` | `/v1/scim/Users/:id` | Update a user (full replace) |
| `DELETE` | `/v1/scim/Users/:id` | Delete a user |

### Groups

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/scim/Groups` | List groups |
| `POST` | `/v1/scim/Groups` | Create a group |
| `GET` | `/v1/scim/Groups/:id` | Get group details |
| `PUT` | `/v1/scim/Groups/:id` | Update a group (full replace) |
| `PATCH` | `/v1/scim/Groups/:id` | Partial group update (add/remove members) |
| `DELETE` | `/v1/scim/Groups/:id` | Delete a group |

**Scope required:** `*` (admin)

---

## List Users

```http
GET /v1/scim/Users?startIndex=1&count=20
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `startIndex` | `integer` | `1` | 1-based index of first result |
| `count` | `integer` | `20` | Maximum items per page (max 100) |
| `filter` | `string` | — | SCIM filter expression (e.g., `userName eq "jane@example.com"`) |

### Response — `200 OK`

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 150,
  "startIndex": 1,
  "itemsPerPage": 20,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "u_abc123",
      "userName": "jane@example.com",
      "name": {
        "givenName": "Jane",
        "familyName": "Doe"
      },
      "emails": [
        {
          "value": "jane@example.com",
          "primary": true
        }
      ],
      "active": true,
      "meta": {
        "resourceType": "User",
        "created": "2025-01-15T10:00:00Z",
        "lastModified": "2025-06-20T14:30:00Z"
      }
    }
  ]
}
```

---

## Create User

```http
POST /v1/scim/Users
Content-Type: application/scim+json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "jane@example.com",
  "name": {
    "givenName": "Jane",
    "familyName": "Doe"
  },
  "emails": [
    {
      "value": "jane@example.com",
      "primary": true
    }
  ],
  "active": true
}
```

### Response — `201 Created`

Returns the created user object with server-generated `id`.

---

## Get User

```http
GET /v1/scim/Users/u_abc123
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

Returns the full SCIM User resource.

---

## Update User (PUT)

```http
PUT /v1/scim/Users/u_abc123
Content-Type: application/scim+json
X-API-Key: am_live_xxxxxxxxxxxxx
```

Full replacement of the user resource. Requires all fields as in Create.

### Response — `200 OK`

Returns the updated user resource.

---

## Delete User

```http
DELETE /v1/scim/Users/u_abc123
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `204 No Content`

---

## List Groups

```http
GET /v1/scim/Groups?startIndex=1&count=20
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

Same as List Users: `startIndex`, `count`, `filter`.

### Response — `200 OK`

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 25,
  "startIndex": 1,
  "itemsPerPage": 20,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      "id": "g_def456",
      "displayName": "Engineering",
      "members": [
        {
          "value": "u_abc123",
          "display": "Jane Doe"
        }
      ],
      "meta": {
        "resourceType": "Group",
        "created": "2025-01-15T10:00:00Z",
        "lastModified": "2025-06-20T14:30:00Z"
      }
    }
  ]
}
```

---

## Create Group

```http
POST /v1/scim/Groups
Content-Type: application/scim+json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "Engineering",
  "members": [
    {
      "value": "u_abc123"
    }
  ]
}
```

### Response — `201 Created`

Returns the created group object with server-generated `id`.

---

## Get Group

```http
GET /v1/scim/Groups/g_def456
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

Returns the full SCIM Group resource.

---

## Update Group (PUT)

```http
PUT /v1/scim/Groups/g_def456
Content-Type: application/scim+json
X-API-Key: am_live_xxxxxxxxxxxxx
```

Full replacement of the group resource.

### Response — `200 OK`

---

## Patch Group (Partial Update)

```http
PATCH /v1/scim/Groups/g_def456
Content-Type: application/scim+json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [
        {
          "value": "u_xyz789"
        }
      ]
    },
    {
      "op": "remove",
      "path": "members",
      "value": [
        {
          "value": "u_old001"
        }
      ]
    }
  ]
}
```

### Supported Operations

| Op | Description |
|----|-------------|
| `add` | Add member(s) to the group |
| `remove` | Remove member(s) from the group |

### Response — `200 OK`

Returns the full updated group resource.

---

## Delete Group

```http
DELETE /v1/scim/Groups/g_def456
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `204 No Content`

---

## SCIM Schema Reference

### User Schema (`urn:ietf:params:scim:schemas:core:2.0:User`)

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `userName` | `string` | ✅ Yes | Unique email-based username |
| `name.givenName` | `string` | No | First name |
| `name.familyName` | `string` | No | Last name |
| `emails[].value` | `string` | ✅ Yes | Email address |
| `emails[].primary` | `boolean` | No | Whether this is the primary email |
| `active` | `boolean` | No | Whether the user account is active |

### Group Schema (`urn:ietf:params:scim:schemas:core:2.0:Group`)

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `displayName` | `string` | ✅ Yes | Group display name |
| `members[].value` | `string` | No | User ID of the member |
| `members[].display` | `string` | No | Display name of the member (read-only) |

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `invalid_scim_payload` | Malformed SCIM request body |
| `400` | `invalid_filter` | Unsupported or malformed SCIM filter expression |
| `409` | `duplicate_user` | Username already exists |
| `409` | `duplicate_group` | Group display name already exists |
| `429` | `rate_limit_exceeded` | Too many requests |
