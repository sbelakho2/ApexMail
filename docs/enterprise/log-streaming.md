# Log Streaming & Real-Time Analytics

ApexMail's log streaming service provides real-time access to email events, enabling integration with your existing analytics, monitoring, and data infrastructure.

## Overview

Log streaming enables:

- **Real-Time Event Delivery** - Stream events as they happen
- **Multiple Destinations** - Send to S3, BigQuery, Kafka, and more
- **Custom Filtering** - Stream only the events you need
- **Data Transformation** - Transform payloads before delivery
- **Reliability** - At-least-once delivery with retry logic

## Supported Destinations

| Destination | Use Case | Latency |
|-------------|----------|---------|
| Amazon S3 | Long-term storage, analytics | ~5 min batches |
| Google BigQuery | Real-time analytics | ~10 seconds |
| Snowflake | Data warehousing | ~5 min batches |
| Apache Kafka | Event streaming | Real-time |
| Amazon Kinesis | AWS streaming | Real-time |
| Elasticsearch | Search & visualization | ~30 seconds |
| Datadog | Monitoring | Real-time |
| Custom Webhook | Any HTTP endpoint | Real-time |

## Configuration

### Create Log Stream

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/log-streams \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "name": "Production Event Stream",
    "destination": {
      "type": "s3",
      "bucket": "apexmail-logs",
      "region": "eu-central-1",
      "prefix": "email-events/",
      "credentials": {
        "accessKeyId": "AKIA...",
        "secretAccessKey": "..."
      }
    },
    "events": [
      "email.sent",
      "email.delivered",
      "email.opened",
      "email.clicked",
      "email.bounced",
      "email.complained"
    ],
    "filters": {
      "tags": ["production"],
      "domains": ["yourcompany.com"]
    },
    "format": "json",
    "batchSize": 1000,
    "batchIntervalSeconds": 300
  }'
```

### Response

```json
{
  "stream": {
    "id": "stream_abc123",
    "name": "Production Event Stream",
    "status": "active",
    "destination": {
      "type": "s3",
      "bucket": "apexmail-logs"
    },
    "metrics": {
      "eventsStreamed": 0,
      "lastStreamedAt": null
    },
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

## Destination Configurations

### Amazon S3

```json
{
  "destination": {
    "type": "s3",
    "bucket": "your-bucket",
    "region": "eu-central-1",
    "prefix": "apexmail/events/",
    "credentials": {
      "accessKeyId": "AKIA...",
      "secretAccessKey": "..."
    },
    "compression": "gzip",
    "fileFormat": "json_lines",
    "partitioning": "date"
  }
}
```

S3 path structure:
```
s3://your-bucket/apexmail/events/2024/01/15/events_1705320000.json.gz
```

### Google BigQuery

```json
{
  "destination": {
    "type": "bigquery",
    "projectId": "your-project",
    "datasetId": "email_analytics",
    "tableId": "events",
    "credentials": {
      "type": "service_account",
      "projectId": "your-project",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n...",
      "clientEmail": "sa@your-project.iam.gserviceaccount.com"
    },
    "streaming": true
  }
}
```

BigQuery schema is automatically created with columns for event ID, event type, email ID, recipient, timestamp, metadata, and tags. The table is partitioned by date for efficient querying.

### Apache Kafka

```json
{
  "destination": {
    "type": "kafka",
    "brokers": ["kafka.yourcompany.com:9092", "kafka-2.yourcompany.com:9092"],
    "topic": "email-events",
    "authentication": {
      "mechanism": "SASL_SSL",
      "username": "...",
      "password": "..."
    },
    "compression": "snappy",
    "acks": "all"
  }
}
```

### Amazon Kinesis

```json
{
  "destination": {
    "type": "kinesis",
    "streamName": "email-events",
    "region": "eu-central-1",
    "credentials": {
      "accessKeyId": "AKIA...",
      "secretAccessKey": "..."
    },
    "partitionKey": "email_id"
  }
}
```

### Elasticsearch

```json
{
  "destination": {
    "type": "elasticsearch",
    "nodes": ["https://your-es-cluster.yourcompany.com:9200"],
    "index": "email-events",
    "authentication": {
      "username": "...",
      "password": "..."
    }
  }
}
```

### Datadog

```json
{
  "destination": {
    "type": "datadog",
    "apiKey": "dd_api_key",
    "site": "datadoghq.com",
    "service": "apexmail",
    "tags": ["env:production"]
  }
}
```

### Custom Webhook

```json
{
  "destination": {
    "type": "webhook",
    "url": "https://your-api.com/events",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer your-token",
      "Content-Type": "application/json"
    },
    "batchSize": 100
  }
}
```

## Event Types

### Available Events

| Event | Description | Payload |
|-------|-------------|---------|
| `email.sent` | Email accepted for delivery | Full email metadata |
| `email.delivered` | Email delivered to recipient | Delivery timestamp |
| `email.opened` | Email opened by recipient | Open location, device |
| `email.clicked` | Link clicked in email | Link URL, click data |
| `email.bounced` | Email bounced | Bounce type, reason |
| `email.complained` | Spam complaint received | Complaint details |
| `email.unsubscribed` | Recipient unsubscribed | Unsubscribe method |
| `email.deferred` | Delivery deferred | Retry schedule |

### Event Payload Structure

```json
{
  "eventId": "evt_abc123",
  "eventType": "email.opened",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "emailId": "msg_xyz789",
  "accountId": "acc_xxx",
  "recipient": "user@example.com",
  "subject": "Your order confirmation",
  "tags": ["transactional", "orders"],
  "metadata": {
    "orderId": "ORD-12345",
    "userId": "user_123"
  },
  "eventData": {
    "userAgent": "Mozilla/5.0...",
    "ipAddress": "203.0.113.1",
    "location": {
      "country": "US",
      "region": "CA",
      "city": "San Francisco"
    },
    "device": {
      "type": "desktop",
      "os": "macOS",
      "client": "Apple Mail"
    }
  }
}
```

## Filtering

### Filter by Event Type

```json
{
  "filters": {
    "events": ["email.bounced", "email.complained"]
  }
}
```

### Filter by Tags

```json
{
  "filters": {
    "tags": {
      "include": ["production", "marketing"],
      "exclude": ["test"]
    }
  }
}
```

### Filter by Domain

```json
{
  "filters": {
    "domains": ["yourcompany.com", "brand.yourcompany.com"]
  }
}
```

### Filter by Recipient Pattern

```json
{
  "filters": {
    "recipientPatterns": [
      "*@enterprise-client.com",
      "*@vip-customers.com"
    ]
  }
}
```

## Data Transformation

### Field Selection

Include only specific fields:

```json
{
  "transform": {
    "fields": [
      "eventId",
      "eventType",
      "timestamp",
      "emailId",
      "recipient",
      "eventData.location.country"
    ]
  }
}
```

### Field Mapping

Rename fields for your schema:

```json
{
  "transform": {
    "fieldMapping": {
      "eventId": "id",
      "eventType": "type",
      "timestamp": "occurred_at",
      "emailId": "message_id"
    }
  }
}
```

### PII Redaction

Automatically redact sensitive data:

```json
{
  "transform": {
    "redact": {
      "fields": ["recipient", "eventData.ipAddress"],
      "method": "hash_sha256"
    }
  }
}
```

## Monitoring & Health

### Check Stream Status

```bash
curl https://api.apexmail.ee/enterprise/v1/log-streams/{stream_id}/status \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response:
```json
{
  "streamId": "stream_abc123",
  "status": "healthy",
  "metrics": {
    "eventsStreamed24h": 1250000,
    "eventsPerSecond": 145,
    "lastStreamedAt": "2024-01-15T10:30:00Z",
    "errorRate": 0.001,
    "latencyP99Ms": 850
  },
  "destination": {
    "status": "connected",
    "lastSuccessfulWrite": "2024-01-15T10:29:55Z"
  }
}
```

### Stream Metrics

```bash
curl https://api.apexmail.ee/enterprise/v1/log-streams/{stream_id}/metrics \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -G -d "period=24h"
```

Response:
```json
{
  "period": "24h",
  "metrics": {
    "totalEvents": 1250000,
    "byEventType": {
      "email.sent": 450000,
      "email.delivered": 445000,
      "email.opened": 125000,
      "email.clicked": 32000,
      "email.bounced": 5000
    },
    "deliveryLatency": {
      "p50": 120,
      "p95": 450,
      "p99": 850
    },
    "errors": {
      "total": 125,
      "byType": {
        "connection_timeout": 80,
        "rate_limited": 45
      }
    }
  }
}
```

## Error Handling

### Retry Behavior

Failed log deliveries are automatically retried with exponential backoff. You can configure retry behavior in your stream settings.

### Failed Events

Events that fail delivery after all retries:

```json
{
  "failedEvents": {
    "enabled": true,
    "destination": {
      "type": "s3",
      "bucket": "your-company-failed-events",
      "prefix": "failed-events/"
    },
    "retentionDays": 30
  }
}
```

### Error Notifications

```json
{
  "alerting": {
    "errorThreshold": 100,
    "errorWindowMinutes": 5,
    "notify": {
      "email": ["ops@yourcompany.com"],
      "slack": "https://hooks.slack.com/...",
      "pagerduty": "your-integration-key"
    }
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/log-streams` | POST | Create stream |
| `/log-streams` | GET | List streams |
| `/log-streams/{id}` | GET | Get stream details |
| `/log-streams/{id}` | PUT | Update stream |
| `/log-streams/{id}` | DELETE | Delete stream |
| `/log-streams/{id}/status` | GET | Get stream status |
| `/log-streams/{id}/metrics` | GET | Get stream metrics |
| `/log-streams/{id}/pause` | POST | Pause stream |
| `/log-streams/{id}/resume` | POST | Resume stream |
| `/log-streams/{id}/test` | POST | Test destination |

## Best Practices

1. **Use Batching for S3/BigQuery** - Reduces costs and improves efficiency
2. **Enable Compression** - Reduce bandwidth and storage costs
3. **Filter at Source** - Only stream events you need
4. **Monitor Error Rates** - Set up alerts for delivery failures
5. **Enable Failed Event Storage** - Never lose events
6. **Partition by Date** - Easier querying and retention management
7. **Hash PII** - Comply with privacy regulations
