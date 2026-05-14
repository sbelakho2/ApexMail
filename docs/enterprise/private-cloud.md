# Private Cloud and BYOIP

ApexMail Enterprise includes a private deployment lifecycle for organizations that need dedicated tenancy, region scoping, dedicated IP management, or customer-owned IP range verification.

The implementation is backed by the Enterprise private deploy service and the `ent_private_deployments`, `ent_dedicated_ips`, `ip_pool_available`, and `ent_byoip_ranges` tables. Routes below are shown relative to the Enterprise API mount and require the same API key authentication (`X-API-Key` header) and tenant access checks as other Enterprise routes.

## Deployment Lifecycle

Supported deployment types:

| Type | Description |
|------|-------------|
| `dedicated` | Dedicated ApexMail-managed tenancy |
| `private_cloud` | Single-tenant private cloud deployment record |
| `hybrid` | Mixed managed and customer-operated deployment model |
| `on_premise` | Customer-operated deployment record |

Supported statuses are `pending`, `provisioning`, `active`, `maintenance`, `decommissioning`, and `failed`.

### Create Deployment

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/deployments \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "name": "EU private cloud",
    "deployment_type": "private_cloud",
    "region": "eu-central",
    "config": {
      "instance_count": 3,
      "storage_gb": 1024,
      "custom_domain": "mail-api.example.com",
      "operational_notes": "Dedicated tenancy with customer-selected region."
    }
  }'
```

Response body wraps a `PrivateDeployment` in the standard `ApiResult` envelope. The deployment includes its `id`, `tenant_id`, `name`, `deployment_type`, `status`, `region`, optional `config`, health fields, and timestamps.

### List and Inspect Deployments

```bash
curl https://api.apexmail.ee/enterprise/v1/deployments/tenant/$TENANT_ID \
  -H "X-API-Key: $API_KEY"

curl https://api.apexmail.ee/enterprise/v1/deployments/$DEPLOYMENT_ID \
  -H "X-API-Key: $API_KEY"
```

### Start Provisioning

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/deployments/$DEPLOYMENT_ID/provision \
  -H "X-API-Key: $API_KEY"
```

Provisioning moves a `pending` deployment to `provisioning`. If the deployment is missing or already outside `pending`, the service returns `INVALID_STATE`.

### Health Check

```bash
curl https://api.apexmail.ee/enterprise/v1/deployments/$DEPLOYMENT_ID/health \
  -H "X-API-Key: $API_KEY"
```

If the deployment record has a `health_check_url`, ApexMail probes it and stores `healthy`, `unhealthy`, or `unreachable`. Deployments without a health URL return `unknown`.

## Dedicated IP Lifecycle

Dedicated IP records track tenant ownership, optional deployment association, PTR, warmup state, reputation, counters, blocklist status, and creation time.

### Allocate a Dedicated IP

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/ips/allocate \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "deployment_id": "11111111-1111-1111-1111-111111111111",
    "ip_address": "203.0.113.10"
  }'
```

The Enterprise plan includes 10 dedicated IPs in the backend plan seed. Additional pool assignment can be operated from the `ip_pool_available` inventory table when regions and reputation preferences are managed internally.

### Read IP Records and Reputation

```bash
curl https://api.apexmail.ee/enterprise/v1/ips/$IP_ID \
  -H "X-API-Key: $API_KEY"

curl 'https://api.apexmail.ee/enterprise/v1/ips/tenant/'$TENANT_ID'?limit=50&offset=0' \
  -H "X-API-Key: $API_KEY"

curl https://api.apexmail.ee/enterprise/v1/ips/reputation/203.0.113.10 \
  -H "X-API-Key: $API_KEY"
```

Reputation is derived from stored reputation score, total sends, bounces, complaints, and blocklist state.

## BYOIP Verification

BYOIP registration stores a customer CIDR, marks it `pending_verification`, and returns a verification token. The customer must publish the token through the agreed verification channel before calling verify.

### Register a CIDR

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/ips/byoip \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "cidr_block": "198.51.100.0/24"
  }'
```

Example response payload:

```json
{
  "id": "22222222-2222-2222-2222-222222222222",
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "cidr_block": "198.51.100.0/24",
  "status": "pending_verification",
  "verification_token": "apexmail-byoip-...",
  "verification_method": "dns_txt",
  "verified_at": null,
  "created_at": "2026-05-07T00:00:00Z"
}
```

### Verify a CIDR

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/ips/byoip/$BYOIP_RANGE_ID/verify \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "verification_token": "apexmail-byoip-..."
  }'
```

Verification only succeeds for a matching token while the range is still `pending_verification`. On success the range moves to `verified` and `verified_at` is set.

## Pricing and Entitlements

Private deployment lifecycle and BYOIP verification are Enterprise-only entitlements. The canonical public pricing source is [../pricing.md](../pricing.md), and the backend plan seed enables both `private_cloud` and `byoip` for Enterprise.

## Operational Notes

- Tenant IDs for this service are UUIDs.
- Customer-specific network, residency, key-management, and operational requirements should be stored in the deployment `config` object and reflected in the signed Enterprise agreement.
- The deployment lifecycle tracks state and health. Infrastructure provisioning remains an operator-controlled workflow unless an environment adds provider-specific automation around these records.
- BYOIP verification confirms control of the CIDR before import or routing work begins.