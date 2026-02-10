# Private Cloud & Dedicated Infrastructure

ApexMail offers private cloud deployment for organisations that require dedicated resources, strict data residency, and maximum performance isolation.

## Overview

Private cloud deployment offers:

- **Dedicated Infrastructure** — Your own isolated compute and network resources
- **Geographic Control** — Deploy in specific EU data centres for data residency compliance
- **Custom Configurations** — Tailored resource allocation and scaling to match your workload
- **Enhanced Security** — Network isolation, dedicated IPs, encrypted VPN tunnels
- **Performance Guarantees** — Dedicated capacity with SLA guarantees

## Deployment Options

| Option | Description | Use Case |
|--------|-------------|----------|
| **Dedicated Tenant** | Isolated environment on managed infrastructure | Mid-size enterprises |
| **Private Cloud** | Fully dedicated servers and networking | Large enterprises |
| **On-Premises** | Deployed in your own data centre | Regulated industries |
| **Hybrid** | Mix of ApexMail-managed and on-premises | Complex requirements |

## Dedicated Tenant Deployment

### Request Dedicated Tenant

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/private-deploy/request \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "deploymentType": "dedicated_tenant",
    "region": "eu-fi",
    "requirements": {
      "estimatedMonthlyVolume": 10000000,
      "peakSendRate": 5000,
      "storageGB": 500,
      "retentionDays": 90
    },
    "networking": {
      "dedicatedIPs": true,
      "ipCount": 4,
      "vpnTunnel": false
    },
    "security": {
      "encryption": "customer_managed_keys",
      "keyId": "cmk-your-key-id"
    },
    "contact": {
      "name": "John Smith",
      "email": "john@enterprise.com",
      "phone": "+49-555-0123"
    }
  }'
```

### Response

```json
{
  "deployment": {
    "id": "deploy_abc123",
    "status": "pending_review",
    "type": "dedicated_tenant",
    "region": "eu-fi",
    "estimatedProvisioningTime": "3-5 business days",
    "pricing": {
      "baseMonthly": 2500.00,
      "perMillionEmails": 0.50,
      "additionalIPs": 50.00,
      "estimatedMonthly": 7500.00
    },
    "nextSteps": [
      "Our team will review your requirements",
      "You'll receive a detailed proposal within 24 hours",
      "Upon approval, provisioning will begin"
    ]
  }
}
```

## Available Regions

| Region Code | Location |
|-------------|----------|
| `eu-fi` | Helsinki, Finland |
| `eu-de-south` | Southern Germany |
| `eu-de-central` | Central Germany |

All regions are GDPR-compliant with data stored exclusively within the EU.

## Infrastructure Sizing

Private cloud deployments are sized to match your workload. During the provisioning process, our team will recommend a configuration based on your estimated monthly volume, peak send rate, and data retention requirements.

All components include automatic health monitoring and alerting.

## Dedicated IP Pools

### Configure Dedicated IPs

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/private-deploy/dedicated-ips \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "ipPools": [
      {
        "name": "transactional",
        "count": 2,
        "warmupDays": 30,
        "domains": ["notifications.yourcompany.com"]
      },
      {
        "name": "marketing",
        "count": 4,
        "warmupDays": 45,
        "domains": ["marketing.yourcompany.com"]
      }
    ]
  }'
```

### IP Pool Status

```json
{
  "ipPools": [
    {
      "name": "transactional",
      "ips": ["203.0.113.1", "203.0.113.2"],
      "reputation": {
        "score": 98,
        "trend": "stable"
      },
      "warmupProgress": 100,
      "dailyCapacity": 500000
    },
    {
      "name": "marketing",
      "ips": ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"],
      "reputation": {
        "score": 95,
        "trend": "improving"
      },
      "warmupProgress": 78,
      "dailyCapacity": 250000
    }
  ]
}
```

## Network Configuration

### VPN Tunnel

Connect your private network to your ApexMail deployment via an encrypted VPN tunnel:

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/private-deploy/vpn-tunnel \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "tunnelType": "wireguard",
    "peerPublicKey": "your-wireguard-public-key",
    "peerEndpoint": "vpn.yourcompany.com:51820",
    "peerCidrBlock": "10.0.0.0/16",
    "keepalive": 25
  }'
```

Response:
```json
{
  "vpnTunnel": {
    "id": "vpn-abc123",
    "status": "pending_peer_config",
    "apexMailPublicKey": "apexmail-wireguard-public-key",
    "apexMailEndpoint": "vpn-abc123.private.apexmail.ee:51820",
    "apexMailCidrBlock": "172.16.0.0/16",
    "instructions": [
      "Add ApexMail's public key and endpoint to your WireGuard config",
      "Configure allowed IPs for the ApexMail CIDR block",
      "Verify the tunnel is established with a ping test"
    ]
  }
}
```

Supported tunnel types:

| Type | Use Case |
|------|----------|
| **WireGuard** | Modern, high-performance VPN (recommended) |
| **IPsec IKEv2** | Compatibility with corporate firewalls and legacy VPN gateways |

### Custom DNS

```json
{
  "dns": {
    "customDomain": "mail-api.internal.yourcompany.com",
    "records": [
      {
        "type": "A",
        "name": "mail-api.internal.yourcompany.com",
        "value": "10.0.1.100"
      },
      {
        "type": "MX",
        "name": "smtp.internal.yourcompany.com",
        "value": "10 smtp-1.apexmail-private.ee"
      }
    ]
  }
}
```

## Security Configuration

### Customer-Managed Encryption Keys

ApexMail supports customer-managed encryption keys (CMEK). You provide the key endpoint, and ApexMail uses your key for data-at-rest encryption. Keys never leave your control.

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/private-deploy/encryption \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "encryption": {
      "type": "customer_managed",
      "keyProvider": "external",
      "keyEndpoint": "https://kms.yourcompany.com/keys/apexmail-dek",
      "keyId": "cmk-your-key-id",
      "rotationEnabled": true,
      "rotationDays": 365
    }
  }'
```

Supported key management providers:

| Provider | Integration |
|----------|-------------|
| **HashiCorp Vault** | REST API / Transit engine |
| **Custom KMS** | REST API endpoint |
| **PKCS#11 HSM** | On-premises HSM |

### Network Security

Private Cloud deployments include a pre-configured firewall, web application firewall (WAF), and DDoS protection. You can customize firewall rules via the API or dashboard to restrict access to your deployment.

## Monitoring & Observability

### Custom Metrics Endpoint

```bash
curl https://api.apexmail.ee/enterprise/v1/private-deploy/metrics \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -G -d "deploymentId=deploy_abc123"
```

Response:
```json
{
  "health": {
    "status": "healthy",
    "lastCheck": "2024-01-15T10:30:00Z"
  },
  "email": {
    "sent24h": 1250000,
    "delivered24h": 1243750,
    "bounced24h": 6250,
    "throughput": {
      "current": 145,
      "max": 5000
    }
  }
}
```

### Log Forwarding

Forward logs to your SIEM:

```json
{
  "logging": {
    "destination": "splunk",
    "endpoint": "https://splunk.yourcompany.com:8088",
    "token": "xxx",
    "logTypes": [
      "api_access",
      "smtp_transactions",
      "security_events",
      "infrastructure"
    ],
    "format": "json"
  }
}
```

## Disaster Recovery

### Backup Configuration

Automated backups are configured with cross-region replication and point-in-time recovery. Backup retention periods are configurable.

### Multi-Region Setup

Private Cloud supports multi-region deployments with automatic failover and near-zero data loss. Contact your account manager for available region options and failover configuration.

## Deployment Status

### Check Deployment Status

```bash
curl https://api.apexmail.ee/enterprise/v1/private-deploy/status/{deployment_id} \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response:
```json
{
  "deployment": {
    "id": "deploy_abc123",
    "status": "active",
    "type": "private_cloud",
    "region": "eu-fi",
    "provisionedAt": "2024-01-10T10:00:00Z",
    "endpoints": {
      "api": "https://api-abc123.private.apexmail.ee",
      "smtp": "smtp-abc123.private.apexmail.ee:587",
      "dashboard": "https://dashboard-abc123.private.apexmail.ee"
    },
    "health": {
      "status": "healthy",
      "lastCheck": "2024-01-15T10:30:00Z",
      "components": {
        "api": "healthy",
        "email_delivery": "healthy",
        "storage": "healthy"
      }
    },
    "maintenance": {
      "nextWindow": "2024-01-20T02:00:00Z",
      "duration": "2 hours",
      "type": "security_patches"
    }
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/private-deploy/request` | POST | Request deployment |
| `/private-deploy/status/{id}` | GET | Get deployment status |
| `/private-deploy/dedicated-ips` | POST | Configure dedicated IPs |
| `/private-deploy/vpn-tunnel` | POST | Setup VPN tunnel |
| `/private-deploy/encryption` | PUT | Configure encryption |
| `/private-deploy/metrics` | GET | Get infrastructure metrics |
| `/private-deploy/scaling` | PUT | Update scaling config |

## SLA Guarantees

Private Cloud offers enhanced SLA guarantees including higher uptime, faster API response times, dedicated throughput, and priority support. See your service agreement for details.

## Best Practices

1. **Start with Capacity Planning** — Accurately estimate volume and growth
2. **Warm Up IPs Gradually** — Follow IP warmup schedule for new pools
3. **Enable Cross-Region Replication** — Set up a standby in a second region for HA
4. **Configure Monitoring** — Set up alerts before going live
5. **Test Failover** — Regularly test disaster recovery procedures
6. **Review Security** — Audit security configurations quarterly
7. **Plan Maintenance Windows** — Coordinate with business requirements
