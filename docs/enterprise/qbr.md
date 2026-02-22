# Quarterly Business Reviews (QBR)

ApexMail's Quarterly Business Review program provides enterprise customers with comprehensive performance analysis, strategic planning, and optimization recommendations.

## Overview

QBRs deliver:

- **Performance Analysis** - Deep dive into email metrics and trends
- **Benchmark Comparison** - How you compare to industry standards
- **Strategic Recommendations** - Data-driven optimization suggestions
- **Roadmap Alignment** - Product updates relevant to your needs
- **Success Planning** - Goals and KPIs for the next quarter

## QBR Structure

### Standard QBR Agenda (90 minutes)

| Section | Duration | Content |
|---------|----------|---------|
| Executive Summary | 10 min | High-level performance overview |
| Deliverability Deep Dive | 20 min | Reputation, placement, bounces |
| Engagement Analysis | 15 min | Opens, clicks, conversions |
| Technical Review | 15 min | API usage, integration health |
| Optimization Recommendations | 15 min | Actionable improvements |
| Product Roadmap | 10 min | Upcoming features |
| Q&A and Action Items | 5 min | Next steps |

## Requesting a QBR

### Schedule QBR

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/qbr/schedule \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "acc_xxx",
    "quarter": "2024-Q1",
    "format": "video_call",
    "preferredDates": [
      "2024-01-15",
      "2024-01-16",
      "2024-01-17"
    ],
    "preferredTime": "14:00",
    "timezone": "America/New_York",
    "attendees": [
      {
        "name": "John Smith",
        "email": "john@company.com",
        "role": "VP Marketing"
      },
      {
        "name": "Jane Doe",
        "email": "jane@company.com",
        "role": "Email Operations Manager"
      }
    ],
    "focusAreas": [
      "deliverability",
      "scaling",
      "compliance"
    ],
    "additionalContext": "Preparing for Black Friday campaign, expecting 5x volume increase"
  }'
```

### Response

```json
{
  "qbr": {
    "id": "qbr_2024q1_abc",
    "quarter": "2024-Q1",
    "status": "scheduled",
    "scheduledDate": "2024-01-15T14:00:00-05:00",
    "duration": 90,
    "format": "video_call",
    "meetingLink": "https://meet.apexmail.ee/qbr/abc123",
    "apexMailTeam": [
      {
        "role": "Customer Success Manager"
      },
      {
        "role": "Technical Account Manager"
      },
      {
        "role": "Deliverability Specialist"
      }
    ],
    "preparationDeadline": "2024-01-13T14:00:00-05:00"
  }
}
```

## QBR Report Sections

### Executive Summary

```json
{
  "executiveSummary": {
    "quarter": "2024-Q1",
    "overallHealth": "excellent",
    "healthScore": 94,
    "highlights": [
      "Deliverability improved from 97.2% to 99.1%",
      "Open rates up 12% quarter-over-quarter",
      "Successfully scaled to handle 10M emails/month"
    ],
    "attentionAreas": [
      "Gmail engagement metrics below benchmark",
      "Sunrise campaign had elevated bounce rate"
    ],
    "quarterlyGrowth": {
      "emailVolume": "+45%",
      "activeRecipients": "+23%",
      "engagementRate": "+8%"
    }
  }
}
```

### Deliverability Analysis

```json
{
  "deliverability": {
    "overview": {
      "deliveryRate": 99.1,
      "inboxPlacement": 95.2,
      "spamPlacement": 2.1,
      "bounceRate": 1.8,
      "complaintRate": 0.02
    },
    "byProvider": {
      "gmail": {
        "deliveryRate": 99.3,
        "inboxPlacement": 92.5,
        "trend": "improving"
      },
      "microsoft": {
        "deliveryRate": 99.5,
        "inboxPlacement": 97.8,
        "trend": "stable"
      },
      "yahoo": {
        "deliveryRate": 98.9,
        "inboxPlacement": 96.2,
        "trend": "stable"
      }
    },
    "reputationScores": {
      "senderScore": 96,
      "googlePostmaster": "High",
      "microsoftSNDS": "Green"
    },
    "benchmarkComparison": {
      "industryAvg": {
        "deliveryRate": 97.5,
        "inboxPlacement": 88.3
      },
      "yourPerformance": "Top 10%"
    }
  }
}
```

### Engagement Metrics

```json
{
  "engagement": {
    "overview": {
      "uniqueOpenRate": 28.5,
      "clickRate": 4.2,
      "clickToOpenRate": 14.7,
      "unsubscribeRate": 0.15,
      "conversionRate": 2.1
    },
    "trends": {
      "openRate": {
        "q4_2023": 25.3,
        "q1_2024": 28.5,
        "change": "+12.6%"
      },
      "clickRate": {
        "q4_2023": 3.8,
        "q1_2024": 4.2,
        "change": "+10.5%"
      }
    },
    "byCampaignType": {
      "promotional": {
        "openRate": 22.1,
        "clickRate": 3.5
      },
      "transactional": {
        "openRate": 65.2,
        "clickRate": 12.8
      },
      "newsletter": {
        "openRate": 31.4,
        "clickRate": 5.2
      }
    },
    "topPerformingCampaigns": [
      {
        "name": "Product Launch Announcement",
        "sent": 250000,
        "openRate": 42.5,
        "clickRate": 8.7
      }
    ]
  }
}
```

### Technical Health

```json
{
  "technical": {
    "apiHealth": {
      "availability": 99.99,
      "avgLatency": 45,
      "p99Latency": 120,
      "errorRate": 0.02
    },
    "integration": {
      "webhookDelivery": 99.8,
      "avgWebhookLatency": 85,
      "failedWebhooks": 234
    },
    "authentication": {
      "spfPassRate": 100,
      "dkimPassRate": 100,
      "dmarcCompliance": 99.8
    },
    "recommendations": [
      {
        "issue": "Webhook timeout on order confirmation endpoint",
        "impact": "234 missed delivery confirmations",
        "recommendation": "Increase endpoint timeout or implement async processing"
      }
    ]
  }
}
```

## Accessing QBR Reports

### Get QBR Report

```bash
curl https://api.apexmail.ee/enterprise/v1/qbr/reports/{qbr_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

### Download QBR Presentation

```bash
curl https://api.apexmail.ee/enterprise/v1/qbr/reports/{qbr_id}/download \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "format=pdf"
```

### List Historical QBRs

```bash
curl https://api.apexmail.ee/enterprise/v1/qbr/reports \
  -H "X-API-Key: YOUR_API_KEY"
```

Response:
```json
{
  "qbrs": [
    {
      "id": "qbr_2024q1_abc",
      "quarter": "2024-Q1",
      "date": "2024-01-15",
      "healthScore": 94,
      "status": "completed"
    },
    {
      "id": "qbr_2023q4_xyz",
      "quarter": "2023-Q4",
      "date": "2023-10-18",
      "healthScore": 89,
      "status": "completed"
    }
  ]
}
```

## Action Items & Follow-Up

### QBR Action Items

```json
{
  "actionItems": [
    {
      "id": "action_001",
      "title": "Implement engagement-based segmentation",
      "description": "Segment lists by engagement level to improve Gmail inbox placement",
      "owner": "Customer",
      "priority": "high",
      "dueDate": "2024-02-15",
      "status": "in_progress",
      "expectedImpact": "5-10% improvement in Gmail inbox placement"
    },
    {
      "id": "action_002",
      "title": "Webhook endpoint optimization",
      "description": "Review and optimize order confirmation webhook handler",
      "owner": "Customer",
      "priority": "medium",
      "dueDate": "2024-02-01",
      "status": "not_started",
      "expectedImpact": "Eliminate missed delivery confirmations"
    },
    {
      "id": "action_003",
      "title": "IP warmup for new pool",
      "description": "ApexMail to provision and warm up new dedicated IP pool for holiday volume",
      "owner": "ApexMail",
      "priority": "high",
      "dueDate": "2024-03-01",
      "status": "scheduled",
      "expectedImpact": "Handle 5x volume for Black Friday"
    }
  ]
}
```

### Track Action Item Progress

```bash
curl -X PUT https://api.apexmail.ee/enterprise/v1/qbr/actions/{action_id} \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "status": "completed",
    "completionNotes": "Implemented segmentation using engagement scores. Initial results show 7% improvement.",
    "completedAt": "2024-02-10"
  }'
```

## Custom QBR Components

### Request Custom Analysis

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/qbr/custom-analysis \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "qbrId": "qbr_2024q1_abc",
    "analysisType": "competitor_benchmark",
    "parameters": {
      "competitors": ["competitor_a", "competitor_b"],
      "metrics": ["deliverability", "engagement", "inbox_placement"],
      "period": "6_months"
    }
  }'
```

### Available Custom Analyses

| Analysis Type | Description |
|--------------|-------------|
| Competitor Benchmark | Compare against industry competitors |
| Campaign Deep Dive | Detailed analysis of specific campaigns |
| List Health Audit | Comprehensive list hygiene analysis |
| Deliverability Forensics | Root cause analysis for deliverability issues |
| ROI Analysis | Email marketing ROI calculation |
| Predictive Analytics | Forecasting for upcoming periods |

## QBR Preparation Checklist

### Pre-QBR Survey

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/qbr/survey \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "qbrId": "qbr_2024q1_abc",
    "responses": {
      "biggestChallenge": "Scaling for upcoming holiday season",
      "topPriorities": [
        "Improve Gmail deliverability",
        "Reduce bounce rates",
        "Better engagement tracking"
      ],
      "upcomingInitiatives": "International expansion to EU markets",
      "feedbackOnService": "Support team has been excellent",
      "additionalTopics": "GDPR compliance for EU expansion"
    }
  }'
```

## Success Metrics & Goals

### Set Quarterly Goals

```bash
curl -X POST https://api.apexmail.ee/enterprise/v1/qbr/goals \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "accountId": "acc_xxx",
    "quarter": "2024-Q2",
    "goals": [
      {
        "metric": "inbox_placement",
        "target": 97,
        "current": 95.2,
        "priority": "high"
      },
      {
        "metric": "engagement_rate",
        "target": 32,
        "current": 28.5,
        "priority": "medium"
      },
      {
        "metric": "monthly_volume",
        "target": 15000000,
        "current": 10000000,
        "priority": "high"
      }
    ]
  }'
```

### Track Goal Progress

```bash
curl https://api.apexmail.ee/enterprise/v1/qbr/goals/progress \
  -H "X-API-Key: YOUR_API_KEY" \
  -G -d "quarter=2024-Q2"
```

Response:
```json
{
  "goals": [
    {
      "metric": "inbox_placement",
      "target": 97,
      "current": 96.1,
      "progress": 50,
      "onTrack": true,
      "forecast": 97.5
    },
    {
      "metric": "engagement_rate",
      "target": 32,
      "current": 29.8,
      "progress": 37,
      "onTrack": true,
      "forecast": 31.5
    }
  ],
  "lastUpdated": "2024-05-15T10:00:00Z"
}
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/qbr/schedule` | POST | Schedule QBR |
| `/qbr/reports` | GET | List QBR reports |
| `/qbr/reports/{id}` | GET | Get QBR report |
| `/qbr/reports/{id}/download` | GET | Download QBR |
| `/qbr/actions` | GET | List action items |
| `/qbr/actions/{id}` | PUT | Update action item |
| `/qbr/survey` | POST | Submit pre-QBR survey |
| `/qbr/goals` | POST | Set quarterly goals |
| `/qbr/goals/progress` | GET | Track goal progress |
| `/qbr/custom-analysis` | POST | Request custom analysis |

## Best Practices

1. **Prepare in Advance** - Complete pre-QBR survey and gather questions
2. **Involve Stakeholders** - Include decision-makers in QBR meetings
3. **Review Previous QBR** - Track progress on previous action items
4. **Set Measurable Goals** - Define specific, achievable quarterly targets
5. **Follow Up** - Act on recommendations between QBRs
6. **Share Insights** - Distribute QBR findings with your team
7. **Provide Feedback** - Help us improve the QBR process
