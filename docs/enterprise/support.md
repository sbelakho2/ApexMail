# Premium Support & Success Services

ApexMail offers comprehensive support tiers designed to meet the needs of organizations from startups to large enterprises.

## Support Tiers

| Feature | Standard | Premium | Enterprise |
|---------|----------|---------|------------|
| **Response Time** | 24 hours | 4 hours | 15 minutes |
| **Channels** | Email | Email, Chat | Email, Chat, Phone |
| **Hours** | Business hours | Extended hours | 24/7/365 |
| **Dedicated CSM** | ❌ | ✅ | ✅ |
| **Technical Account Manager** | ❌ | ❌ | ✅ |
| **Slack Channel** | ❌ | ❌ | ✅ |
| **Priority Escalation** | ❌ | ✅ | ✅ |
| **Quarterly Business Reviews** | ❌ | ❌ | ✅ |
| **Architecture Review** | ❌ | Annually | Quarterly |
| **Training Sessions** | Self-serve | 2/year | Unlimited |

## Creating Support Tickets

### Create Ticket

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/tickets \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "subject": "High bounce rate on marketing domain",
    "description": "We have observed a sudden increase in bounce rates from 2% to 15% starting yesterday. Affected domain: marketing.ourcompany.com. Volume: ~50,000 emails/day.",
    "priority": "high",
    "category": "deliverability",
    "affectedResources": [
      {"type": "domain", "id": "dom_marketing"},
      {"type": "ip_pool", "id": "pool_marketing"}
    ],
    "attachments": [],
    "contact": {
      "name": "John Smith",
      "email": "john@ourcompany.com",
      "phone": "+1-555-0123"
    }
  }'
```

### Response

```json
{
  "ticket": {
    "id": "ticket_abc123",
    "number": "APX-45678",
    "subject": "High bounce rate on marketing domain",
    "status": "open",
    "priority": "high",
    "category": "deliverability",
    "assignedTo": {
      "team": "deliverability",
      "agent": null
    },
    "sla": {
      "firstResponse": "2024-01-15T14:30:00Z",
      "resolution": "2024-01-17T10:30:00Z"
    },
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

### Priority Levels

| Priority | Description | First Response | Resolution Target |
|----------|-------------|----------------|-------------------|
| **Critical** | Service outage, security incident | 15 min | 4 hours |
| **High** | Major feature broken, significant impact | 1 hour | 8 hours |
| **Medium** | Feature degradation, workaround available | 4 hours | 24 hours |
| **Low** | General questions, feature requests | 24 hours | 5 days |

### Ticket Categories

- `deliverability` - Bounce rates, spam placement, reputation
- `technical` - API errors, integration issues
- `billing` - Invoices, pricing, plan changes
- `security` - Security concerns, access issues
- `feature_request` - Product enhancement suggestions
- `account` - Account management, user access
- `compliance` - GDPR, CCPA, regulatory questions

## Ticket Management

### Get Ticket Status

```bash
curl https://api.apexmail.ee/enterprise/v1/support/tickets/{ticket_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "ticket": {
    "id": "ticket_abc123",
    "number": "APX-45678",
    "subject": "High bounce rate on marketing domain",
    "status": "in_progress",
    "priority": "high",
    "assignedTo": {
      "team": "deliverability",
      "agent": {
        "name": "Your assigned specialist"
      }
    },
    "timeline": [
      {
        "timestamp": "2024-01-15T10:30:00Z",
        "action": "created",
        "actor": "customer"
      },
      {
        "timestamp": "2024-01-15T11:15:00Z",
        "action": "assigned",
        "actor": "system",
        "details": "Assigned to support agent"
      },
      {
        "timestamp": "2024-01-15T11:30:00Z",
        "action": "first_response",
        "actor": "agent",
        "message": "Hi John, I'm investigating your bounce rate increase..."
      }
    ],
    "sla": {
      "firstResponse": {
        "target": "2024-01-15T14:30:00Z",
        "actual": "2024-01-15T11:30:00Z",
        "met": true
      },
      "resolution": {
        "target": "2024-01-17T10:30:00Z",
        "actual": null,
        "met": null
      }
    }
  }
}
```

### Add Comment to Ticket

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/tickets/{ticket_id}/comments \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "message": "I have noticed this is affecting emails to Gmail specifically. Here are the bounce codes we are seeing...",
    "attachments": [
      {
        "filename": "bounce_report.csv",
        "content": "base64_encoded_content"
      }
    ]
  }'
```

### List Tickets

```bash
curl https://api.apexmail.ee/enterprise/v1/support/tickets \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "status=open" -d "priority=high"
```

## Escalation

### Escalate Ticket

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/tickets/{ticket_id}/escalate \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "reason": "Impact has expanded to transactional emails. Revenue impact estimated at $50K/day.",
    "requestedAction": "Engineering team involvement",
    "businessImpact": "critical"
  }'
```

Response:
```json
{
  "escalation": {
    "ticketId": "ticket_abc123",
    "escalationLevel": 2,
    "newAssignee": {
      "team": "engineering"
    },
    "escalatedAt": "2024-01-15T14:00:00Z"
  }
}
```

### Escalation Levels

| Level | Description | Criteria |
|-------|-------------|----------|
| 1 | Initial Support | Initial assignment |
| 2 | Senior Specialist | Complex technical issues |
| 3 | Engineering | Product bugs, infrastructure |
| 4 | Leadership | Critical business impact |

## Customer Success Management

### Schedule CSM Meeting

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/csm/meetings \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "type": "strategy_review",
    "preferredTimes": [
      "2024-01-20T14:00:00Z",
      "2024-01-21T10:00:00Z"
    ],
    "duration": 60,
    "agenda": [
      "Q4 performance review",
      "2024 email strategy",
      "New feature onboarding"
    ],
    "attendees": [
      {"name": "John Smith", "email": "john@company.com"},
      {"name": "Jane Doe", "email": "jane@company.com"}
    ]
  }'
```

### Quarterly Business Review (QBR)

Enterprise customers receive quarterly business reviews covering:

```json
{
  "qbrAgenda": {
    "accountHealth": {
      "deliverability": "Score trends, benchmark comparison",
      "usage": "Volume analysis, growth trajectory",
      "roi": "Cost per email, campaign performance"
    },
    "technicalReview": {
      "integration": "API usage patterns, error rates",
      "infrastructure": "Performance metrics, capacity planning",
      "security": "Compliance status, audit findings"
    },
    "strategicPlanning": {
      "roadmap": "Upcoming features relevant to your use case",
      "optimization": "Recommendations for improvement",
      "goals": "Q+1 objectives and success metrics"
    }
  }
}
```

### Request QBR

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/qbr/request \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "quarter": "2024-Q1",
    "format": "video_call",
    "additionalTopics": [
      "Expansion to European markets",
      "HIPAA compliance requirements"
    ]
  }'
```

## Training & Onboarding

### Schedule Training

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/training \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "topic": "advanced_deliverability",
    "format": "live_webinar",
    "attendees": 10,
    "preferredDate": "2024-02-01",
    "prerequisites": ["basic_api_training"],
    "notes": "Focus on Gmail and Microsoft deliverability best practices"
  }'
```

### Available Training Topics

| Topic | Duration | Level |
|-------|----------|-------|
| API Fundamentals | 2 hours | Beginner |
| Template Design | 3 hours | Beginner |
| Advanced Deliverability | 4 hours | Intermediate |
| Analytics & Reporting | 2 hours | Intermediate |
| Security Best Practices | 2 hours | Intermediate |
| Enterprise Integration | 4 hours | Advanced |
| Custom Development | 8 hours | Advanced |

## Technical Account Management

Enterprise customers with TAM receive:

### Proactive Monitoring

```json
{
  "tamServices": {
    "monitoring": {
      "deliverabilityAlerts": "Real-time reputation monitoring",
      "performanceReviews": "Weekly performance analysis",
      "capacityPlanning": "Monthly growth forecasting"
    },
    "optimization": {
      "configurationAudits": "Quarterly best practice reviews",
      "codeReviews": "Integration code analysis",
      "architectureGuidance": "Scaling recommendations"
    },
    "advocacy": {
      "featureRequests": "Direct product team escalation",
      "betaAccess": "Early access to new features",
      "roadmapInput": "Influence product direction"
    }
  }
}
```

### Request TAM Consultation

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/tam/consultation \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "topic": "architecture_review",
    "description": "Planning migration to event-driven architecture. Need guidance on webhook design and scaling.",
    "urgency": "medium",
    "documents": [
      {
        "name": "current_architecture.pdf",
        "url": "https://..."
      }
    ]
  }'
```

## Communication Channels

### Dedicated Slack Channel

Enterprise customers get a dedicated Slack channel:

```
#apexmail-yourcompany
├── @apexmail-support (Support team)
├── @apexmail-tam (Technical Account Manager)
├── @apexmail-csm (Customer Success Manager)
└── Your team members
```

### Emergency Contact

For critical issues outside business hours:

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/support/emergency \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "issue": "Complete service outage - no emails being delivered",
    "impact": "All transactional emails affected, estimated $10K/hour revenue loss",
    "contact": {
      "name": "John Smith",
      "phone": "+1-555-0123",
      "available": "immediately"
    }
  }'
```

## Support Metrics & SLA

### Check SLA Status

```bash
curl https://api.apexmail.ee/enterprise/v1/support/sla/status \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "period=2024-01"
```

Response:
```json
{
  "period": "2024-01",
  "slaMetrics": {
    "firstResponseSLA": {
      "target": "95%",
      "actual": "98.5%",
      "met": true
    },
    "resolutionSLA": {
      "target": "90%",
      "actual": "94.2%",
      "met": true
    },
    "uptime": {
      "target": "99.99%",
      "actual": "99.995%",
      "met": true
    }
  },
  "ticketStats": {
    "total": 12,
    "resolved": 11,
    "open": 1,
    "avgResolutionHours": 6.4,
    "customerSatisfaction": 4.8
  }
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/support/tickets` | POST | Create ticket |
| `/support/tickets` | GET | List tickets |
| `/support/tickets/{id}` | GET | Get ticket |
| `/support/tickets/{id}/comments` | POST | Add comment |
| `/support/tickets/{id}/escalate` | POST | Escalate ticket |
| `/support/csm/meetings` | POST | Schedule CSM meeting |
| `/support/qbr/request` | POST | Request QBR |
| `/support/training` | POST | Schedule training |
| `/support/tam/consultation` | POST | Request TAM consultation |
| `/support/emergency` | POST | Emergency contact |
| `/support/sla/status` | GET | Check SLA status |

## Best Practices

1. **Provide Complete Information** - Include all relevant details in initial ticket
2. **Use Correct Priority** - Reserve critical/high for genuine business impact
3. **Attach Evidence** - Include logs, screenshots, and examples
4. **Respond Promptly** - Keep communication flowing for faster resolution
5. **Track Trends** - Review ticket patterns to identify systemic issues
6. **Leverage TAM/CSM** - Use strategic resources for planning, not firefighting
7. **Attend QBRs** - Regular reviews prevent issues and optimize usage
