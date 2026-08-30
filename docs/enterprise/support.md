# Support & Success Services

ApexMail support is **async-first**. Most questions are answered by the docs and the in-app self-debug diagnostics (`GET /v1/domains/{id}/auth-status`, `GET /v1/domains/{id}/dns-records`). Human support exists for things automation can't solve — billing exceptions, security incidents, capacity planning, and architectural reviews.

We deliberately do **not** offer:

- 24/7 live chat
- Per-customer Discord servers
- White-glove real-time everything
- On-demand phone calls

We do offer scheduled async-first support with hard tier boundaries.

## Support Tiers (Hard Boundaries)

| Feature | Starter / Growth | Scale | Enterprise |
|---------|------------------|-------|------------|
| **Channel** | Email only | Priority email + shared Slack hub | Dedicated async channel |
| **First-response SLA** | 24–48h business hours | 8h business hours | 4h business hours, contractual |
| **Live calls** | None | Scheduled, monthly cap | Scheduled, weekly cap |
| **Hours** | Business hours (Europe/Tallinn) | Business hours | Business hours + on-call for P0 incidents |
| **Dedicated CSM** | | | |
| **Technical Account Manager** | | | (optional) |
| **Shared Slack hub** | | (one shared channel for all Scale tenants) | n/a (dedicated channel) |
| **Dedicated channel** | | | |
| **Priority Escalation** | | | |
| **Quarterly Business Reviews** | | | |
| **Architecture Review** | | Annually | Quarterly |
| **Training Sessions** | Self-serve only | 2/year async | Unlimited async + 4 live/year |

> **Why hard boundaries?** Real-time everything does not scale. We invest the saved hours in better docs, in-app diagnostics, and an AI support assistant trained on the system — so you usually do not need to contact us at all.

### Before opening a ticket

1. **Run self-debug.** Most domain/deliverability/auth issues are solved by `auth-status` + `dns-records` in under a minute.
2. **Email the support team** (support@apexmail.ee) — responses follow the tier SLAs below.
3. **Ask the in-app AI assistant.** It is trained on this exact system and answers most setup, API, billing-readonly, and troubleshooting questions instantly.
4. **Then open a ticket** if and only if the above three did not resolve it.

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

| Priority | Description | First Response (business hours) | Resolution Target |
|----------|-------------|--------------------------------|-------------------|
| **P0 / Critical** | Service outage, active security incident | 1h (Enterprise), 4h (Scale), 24h (Starter/Growth) | Best-effort, continuous async until resolved |
| **P1 / High** | Major feature broken, significant business impact | 4h (Enterprise), 8h (Scale), 24–48h (Starter/Growth) | 1 business day |
| **P2 / Medium** | Feature degradation, workaround available | 1 business day | 3 business days |
| **P3 / Low** | General questions, feature requests | 2 business days | Best-effort |

> **No 24/7 live chat.** P0 outage acknowledgement happens via the [status page](https://status.apexmail.ee) and email. Live calls are scheduled within the SLA window, not on demand.

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
      "target": "99.9%",
      "actual": "99.95%",
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
