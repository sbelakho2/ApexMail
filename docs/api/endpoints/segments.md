# Segments API

> **Base path:** `/v1/segments`
> **Required scopes:** `campaigns:read` (GET), `campaigns:write` (POST / PATCH / DELETE)
> **Content-Type:** `application/json`

Segments are **named saved audiences**: a reusable definition of `listIds`,
`excludeListIds` and tag/status match rules that campaigns target via
`segmentId`. A campaign's audience is the union of the campaign's own lists
and the segment's lists, filtered by the segment's match rules, minus the
union of both exclude sets. Segments are evaluated at send time — editing a
segment changes every future send that references it.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/segments` | Create a segment |
| GET | `/v1/segments` | List segments |
| GET | `/v1/segments/:id` | Get a segment |
| PATCH | `/v1/segments/:id` | Update a segment |
| DELETE | `/v1/segments/:id` | Delete a segment |

---

## Create Segment

```http
POST /v1/segments
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "name": "VIP customers",
  "description": "Tagged VIP and still active",
  "listIds": ["0b97a7f2-1111-4222-8333-444455556666"],
  "excludeListIds": ["7c31c9aa-2222-4333-9444-555566667777"],
  "match": {
    "tags_all": ["vip"],
    "tags_any": ["beta", "early-access"],
    "statuses": ["active", "subscribed"]
  }
}
```

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Segment name (unique per tenant, max 200 characters) |
| `description` | string | | Free-form description |
| `listIds` | string[] | | Lists whose subscribed members are in the segment (max 50) |
| `excludeListIds` | string[] | | Members of these lists are excluded (max 50) |
| `match` | object | | Match rules — see below |

### Match rules

| Field | Type | Description |
|-------|------|-------------|
| `tags_all` | string[] | Contact must carry ALL of these tags (max 50 tags, 1-64 chars each) |
| `tags_any` | string[] | Contact must carry AT LEAST ONE of these tags |
| `statuses` | string[] | Contact statuses to include (default `active`, `subscribed`; allowed: `active`, `subscribed`, `unsubscribed`, `bounced`, `complained`) |

A segment with no `listIds` and only tag rules targets every contact
matching the rules (subject to the campaign's own exclusions). A segment
with neither lists nor rules is an empty audience.

### Response

`201 Created`

```json
{
  "id": "8c42d0bb-3333-4444-8555-666677778888",
  "name": "VIP customers",
  "description": "Tagged VIP and still active",
  "list_ids": ["0b97a7f2-1111-4222-8333-444455556666"],
  "exclude_list_ids": ["7c31c9aa-2222-4333-9444-555566667777"],
  "match": { "tags_all": ["vip"], "tags_any": ["beta", "early-access"], "statuses": ["active", "subscribed"] },
  "created_at": "2026-10-05T10:00:00+00:00",
  "updated_at": "2026-10-05T10:00:00+00:00"
}
```

---

## List Segments

```http
GET /v1/segments
X-API-Key: {{api_key}}
```

`200 OK` — `{"data": [segment, ...], "error": null}`, newest first.

## Get / Update / Delete

- `GET /v1/segments/:id` — `200` or `404`.
- `PATCH /v1/segments/:id` — same body as create; replaces the definition.
  A duplicate name is `409`.
- `DELETE /v1/segments/:id` — `204`. Campaigns referencing the deleted
  segment keep their own lists and lose the segment-narrowed part
  (`campaigns.segment_id` is set to NULL).

## Error codes

| HTTP Status | Description |
|-------------|-------------|
| `400` | Malformed ids, unknown match-rule keys, invalid statuses, or oversized arrays |
| `401` | API key missing or invalid |
| `403` | API key lacks the required scope |
| `404` | Unknown or cross-tenant list/template/segment reference |
| `409` | Duplicate segment name |
