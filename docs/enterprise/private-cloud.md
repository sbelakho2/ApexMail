# Private Cloud & Dedicated Infrastructure

ApexMail's private cloud deployment options provide dedicated infrastructure for organizations requiring maximum control, security, and performance isolation.

## Overview

Private cloud deployment offers:

- **Dedicated Infrastructure** - Your own isolated compute and network resources
- **Geographic Control** - Deploy in specific regions for data residency
- **Custom Configurations** - Tailored resource allocation and scaling
- **Enhanced Security** - Network isolation, dedicated IPs, custom VPNs
- **Performance Guarantees** - Dedicated capacity with SLA guarantees

## Deployment Options

| Option | Infrastructure | Use Case |
|--------|---------------|----------|
| **Dedicated Tenant** | Isolated containers on shared infrastructure | Mid-size enterprises |
| **Private Cloud** | Dedicated VMs and networking | Large enterprises |
| **On-Premises** | Your own data center | Regulated industries |
| **Hybrid** | Mix of cloud and on-premises | Complex requirements |

## Dedicated Tenant Deployment

### Request Dedicated Tenant

```bash
curl -X POST https://api.apexmail.io/enterprise/v1/private-deploy/request \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "deploymentType": "dedicated_tenant",
    "region": "us-east-1",
    "requirements": {
      "estimatedMonthlyVolume": 10000000,
      "peakSendRate": 5000,
      "storageGB": 500,
      "retentionDays": 90
    },
    "networking": {
      "dedicatedIPs": true,
      "ipCount": 4,
      "vpcPeering": false
    },
    "security": {
      "encryption": "customer_managed_keys",
      "keyArn": "arn:aws:kms:us-east-1:123456789:key/xxx"
    },
    "contact": {
      "name": "John Smith",
      "email": "john@enterprise.com",
      "phone": "+1-555-0123"
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
    "region": "us-east-1",
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

## Private Cloud Configuration

### Infrastructure Sizing

```json
{
  "infrastructure": {
    "compute": {
      "apiServers": {
        "instanceType": "c6i.2xlarge",
        "count": 3,
        "autoScaling": {
          "min": 3,
          "max": 10,
          "targetCPU": 70
        }
      },
      "workers": {
        "instanceType": "c6i.xlarge",
        "count": 5,
        "autoScaling": {
          "min": 5,
          "max": 20,
          "targetCPU": 80
        }
      },
      "mtaServers": {
        "instanceType": "m6i.xlarge",
        "count": 4,
        "autoScaling": {
          "min": 4,
          "max": 12,
          "targetQueue": 10000
        }
      }
    },
    "database": {
      "type": "PostgreSQL",
      "instanceClass": "db.r6g.2xlarge",
      "storage": "1000GB",
      "multiAZ": true,
      "readReplicas": 2
    },
    "cache": {
      "type": "Redis",
      "nodeType": "cache.r6g.xlarge",
      "clusterMode": true,
      "nodes": 6
    },
    "storage": {
      "type": "S3",
      "bucket": "dedicated",
      "encryption": "AES-256"
    }
  }
}
```

## Dedicated IP Pools

### Configure Dedicated IPs

```bash
curl -X POST https://api.apexmail.io/enterprise/v1/private-deploy/dedicated-ips \
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

### VPC Peering

Connect ApexMail private cloud to your AWS VPC:

```bash
curl -X POST https://api.apexmail.io/enterprise/v1/private-deploy/vpc-peering \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "peerVpcId": "vpc-0123456789abcdef0",
    "peerOwnerId": "123456789012",
    "peerRegion": "us-east-1",
    "peerCidrBlock": "10.0.0.0/16"
  }'
```

Response:
```json
{
  "vpcPeering": {
    "id": "pcx-abc123",
    "status": "pending_acceptance",
    "apexMailVpcId": "vpc-apexmail-xxx",
    "apexMailCidrBlock": "172.16.0.0/16",
    "instructions": [
      "Accept the VPC peering request in your AWS console",
      "Add route to ApexMail CIDR in your route tables",
      "Update security groups to allow traffic from ApexMail"
    ]
  }
}
```

### Private Link / PrivateLink

```bash
curl -X POST https://api.apexmail.io/enterprise/v1/private-deploy/private-link \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "endpointType": "interface",
    "services": ["api", "smtp"]
  }'
```

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
        "value": "10 smtp-1.apexmail-private.io"
      }
    ]
  }
}
```

## Security Configuration

### Customer-Managed Keys

```bash
curl -X PUT https://api.apexmail.io/enterprise/v1/private-deploy/encryption \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "deploymentId": "deploy_abc123",
    "encryption": {
      "type": "customer_managed",
      "kmsKeyArn": "arn:aws:kms:us-east-1:123456789:key/mrk-xxx",
      "rotationEnabled": true,
      "rotationDays": 365
    }
  }'
```

### Network Security

```json
{
  "security": {
    "firewall": {
      "inbound": [
        {
          "port": 443,
          "protocol": "TCP",
          "source": "0.0.0.0/0",
          "description": "HTTPS API access"
        },
        {
          "port": 587,
          "protocol": "TCP",
          "source": "10.0.0.0/8",
          "description": "Internal SMTP submission"
        }
      ],
      "outbound": [
        {
          "port": 25,
          "protocol": "TCP",
          "destination": "0.0.0.0/0",
          "description": "SMTP delivery"
        }
      ]
    },
    "waf": {
      "enabled": true,
      "rules": ["OWASP", "IP_Rate_Limit", "Bot_Detection"]
    },
    "ddosProtection": {
      "enabled": true,
      "type": "advanced"
    }
  }
}
```

## Monitoring & Observability

### Custom Metrics Endpoint

```bash
curl https://api.apexmail.io/enterprise/v1/private-deploy/metrics \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -G -d "deploymentId=deploy_abc123"
```

Response:
```json
{
  "infrastructure": {
    "apiServers": {
      "healthy": 3,
      "total": 3,
      "avgCPU": 45,
      "avgMemory": 62
    },
    "workers": {
      "healthy": 5,
      "total": 5,
      "avgCPU": 72,
      "queueDepth": 1250
    },
    "database": {
      "connections": 85,
      "maxConnections": 500,
      "replicationLag": "0ms"
    },
    "cache": {
      "hitRate": 98.5,
      "memory": 4.2,
      "maxMemory": 16
    }
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

Forward infrastructure logs to your SIEM:

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

```json
{
  "backup": {
    "database": {
      "automated": true,
      "retentionDays": 35,
      "crossRegionCopy": "eu-west-1"
    },
    "configuration": {
      "automated": true,
      "retentionDays": 90
    },
    "pointInTimeRecovery": true
  }
}
```

### Multi-Region Setup

```json
{
  "multiRegion": {
    "primary": "us-east-1",
    "secondary": "us-west-2",
    "failover": {
      "automatic": true,
      "healthCheckInterval": 30,
      "failoverThreshold": 3
    },
    "replication": {
      "database": "async",
      "configuration": "sync",
      "maxLagSeconds": 60
    }
  }
}
```

## Deployment Status

### Check Deployment Status

```bash
curl https://api.apexmail.io/enterprise/v1/private-deploy/status/{deployment_id} \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response:
```json
{
  "deployment": {
    "id": "deploy_abc123",
    "status": "active",
    "type": "private_cloud",
    "region": "us-east-1",
    "provisionedAt": "2024-01-10T10:00:00Z",
    "endpoints": {
      "api": "https://api-abc123.private.apexmail.io",
      "smtp": "smtp-abc123.private.apexmail.io:587",
      "dashboard": "https://dashboard-abc123.private.apexmail.io"
    },
    "health": {
      "status": "healthy",
      "lastCheck": "2024-01-15T10:30:00Z",
      "components": {
        "api": "healthy",
        "workers": "healthy",
        "mta": "healthy",
        "database": "healthy",
        "cache": "healthy"
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
| `/private-deploy/vpc-peering` | POST | Setup VPC peering |
| `/private-deploy/private-link` | POST | Setup PrivateLink |
| `/private-deploy/encryption` | PUT | Configure encryption |
| `/private-deploy/metrics` | GET | Get infrastructure metrics |
| `/private-deploy/scaling` | PUT | Update scaling config |

## SLA Guarantees

| Metric | Standard | Private Cloud |
|--------|----------|---------------|
| Uptime | 99.9% | 99.99% |
| API Latency (p99) | 500ms | 100ms |
| Throughput | Shared | Dedicated |
| Support Response | 4 hours | 15 minutes |
| Incident RCA | 5 days | 24 hours |

## Best Practices

1. **Start with Capacity Planning** - Accurately estimate volume and growth
2. **Warm Up IPs Gradually** - Follow IP warmup schedule for new pools
3. **Enable Multi-AZ** - Ensure high availability within region
4. **Configure Monitoring** - Set up alerts before going live
5. **Test Failover** - Regularly test disaster recovery procedures
6. **Review Security** - Audit security configurations quarterly
7. **Plan Maintenance Windows** - Coordinate with business requirements
