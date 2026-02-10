# Advanced Analytics & Engagement Features

ApexMail includes cutting-edge analytics and engagement features that provide a competitive advantage in email deliverability and subscriber relationship management.

## Overview

| Feature | Purpose | Competitive Edge |
|---------|---------|-----------------|
| [Bot Click Detection](#bot-click-detection) | Filter bot/scanner clicks from metrics | Accurate engagement data |
| [Reply Rate Tracking](#reply-rate-tracking) | Track two-way communication | Microsoft recommends this |
| [Engagement Trust Score](#engagement-trust-score) | Measure subscriber trust | Beyond open/click metrics |
| [Gmail Annotations](#gmail-annotations) | Rich email previews | Stand out in Promotions tab |

---

## Bot Click Detection

Security scanners and email gateways automatically click links in emails to check for malware. This distorts your engagement metrics.

### The Problem

Bot clicks can account for a significant portion of total clicks in B2B email campaigns:

- Security scanners click links automatically
- Multiple links clicked simultaneously from the same source
- Corporate email gateways pre-fetch links

### How It Works

ApexMail automatically filters bot clicks from your engagement metrics. When a click event is received, it is analyzed using multiple detection signals before being counted in your analytics.

### Example: Checking Bot Status via API

```http
GET /api/v1/analytics/clicks?campaignId=camp_123&includeBot=true
Authorization: Bearer YOUR_API_KEY
```

Response includes a `botStatus` field for each click:

```json
{
  "clicks": [
    {
      "messageId": "msg_123",
      "recipientEmail": "user@company.com",
      "url": "https://example.com/promo",
      "timestamp": "2026-01-15T10:30:00Z",
      "isBot": true,
      "botType": "security_scanner",
      "confidence": 0.98
    }
  ]
}
```

### Detection

ApexMail uses multi-signal bot detection to separate genuine human engagement from automated link scanning. Signals include user-agent analysis, click timing patterns, IP reputation, click velocity, and header analysis. Adjusted metrics are shown alongside raw numbers in your analytics dashboard.

### Honeypot Links

ApexMail can automatically inject invisible honeypot links into your emails. Only bots click these links, providing a definitive signal for detection. Enable honeypot links in your sending domain settings or via the API:

```http
PUT /api/v1/domains/:id/settings
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "botDetection": {
    "honeypotEnabled": true
  }
}
```

### Adjusted Metrics

The analytics dashboard and API automatically show bot-adjusted metrics alongside raw numbers:

| Metric | Description |
|--------|-------------|
| Raw click rate | Total clicks / total delivered |
| Adjusted click rate | Human clicks only / total delivered |
| Bot percentage | Percentage of clicks identified as bot activity |

---

## Reply Rate Tracking

Microsoft now "strongly recommends" allowing two-way communication. Reply rates are emerging as a key engagement KPI.

### Why No More `no-reply@`

- **Microsoft signals**: Officially recommends reply-to addresses
- **Trust building**: Two-way communication builds relationships
- **Deliverability boost**: Replies signal engagement to ISPs
- **Valuable feedback**: Learn what subscribers actually think

### How It Works

When reply tracking is enabled, ApexMail monitors incoming replies to your campaigns and provides structured analytics:

```http
GET /api/v1/analytics/replies?campaignId=camp_123
Authorization: Bearer YOUR_API_KEY
```

```json
{
  "replies": [
    {
      "messageId": "msg_456",
      "from": "customer@example.com",
      "subject": "Re: Your order has shipped",
      "isAutoReply": false,
      "sentiment": "positive",
      "receivedAt": "2026-01-15T14:30:00Z"
    }
  ]
}
```

### Sentiment Detection

| Sentiment | Triggers |
|-----------|----------|
| `POSITIVE` | thank, great, awesome, appreciate |
| `NEGATIVE` | disappointed, frustrated, terrible, spam |
| `INQUIRY` | Question marks, "how do", "can you" |
| `UNSUBSCRIBE_REQUEST` | unsubscribe, stop sending, remove me |
| `OUT_OF_OFFICE` | vacation, away, leave |

### Auto-Reply Filtering

The service automatically detects and filters auto-replies via:

- Headers: `Auto-Submitted`, `X-Auto-Response-Suppress`, `Precedence`
- Content patterns: "Out of office", "Automatic reply"

### Recommended Reply-To Configuration

Configure your reply-to settings via the dashboard or API:

```http
PUT /api/v1/domains/:id/reply-tracking
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "replyToAddress": "support@acme.com",
  "autoResponderEnabled": true,
  "autoResponderMessage": "Thanks for your reply! The Acme Corp team will get back to you within 24 hours.",
  "webhookUrl": "https://api.acme.com/webhooks/replies"
}
```

### Reply Rate Benchmarks

| Email Type | Good | Excellent |
|------------|------|-----------|
| Transactional | 2% | 5% |
| Marketing | 0.5% | 2% |
| Sales Outreach | 5% | 15% |
| Customer Support | 10% | 25% |
| Newsletter | 0.1% | 0.5% |

---

## Engagement Trust Score

Moving beyond simple open/click metrics to measure true subscriber trust using the Trust Equation.

### The Trust Equation

```
Trust = (Credibility + Reliability + Intimacy) / Self-Orientation
```

- **Credibility**: Do they believe what you say?
- **Reliability**: Do they know what to expect?
- **Intimacy**: Do they feel safe with you?
- **Self-Orientation**: Are you focused on them or yourself? (lower is better)

### How It Works

ApexMail calculates a trust score (0–100) for each subscriber based on their engagement history. Access trust scores via the API or dashboard:

```http
GET /api/v1/contacts/:id/trust-score
Authorization: Bearer YOUR_API_KEY
```

```json
{
  "subscriberId": "sub_123",
  "overall": 78,
  "grade": "B",
  "riskLevel": "low",
  "components": {
    "credibility": 82,
    "reliability": 75,
    "intimacy": 71,
    "selfOrientation": 0.3
  },
  "trend": "improving"
}

### Component Scoring

| Component | Inputs |
|-----------|--------|
| Credibility | Opens, clicks, spam marks |
| Reliability | Tenure, preferences, recency |
| Intimacy | Replies, surveys, NPS |
| Self-Orientation | Frequency vs engagement (divisor — lower is better) |

### Trust Grades

| Grade | Score | Interpretation |
|-------|-------|----------------|
| A | 85-100 | High trust, engaged subscriber |
| B | 70-84 | Good trust, room to grow |
| C | 55-69 | Moderate, needs personalization |
| D | 40-54 | At risk, re-engage |
| F | 0-39 | Eroded trust, sunset flow |

### Campaign-Level Trust Metrics

```http
GET /api/v1/campaigns/:id/trust-metrics
Authorization: Bearer YOUR_API_KEY
```

```json
{
  "averageTrustScore": 72,
  "segments": {
    "highTrust": 450,
    "mediumTrust": 300,
    "lowTrust": 180,
    "atRisk": 70
  },
  "trend": "improving",
  "recommendations": [
    "Consider a re-engagement campaign for the 70 at-risk subscribers",
    "Your sending frequency may be too high for the low-trust segment"
  ]
}
```

---

## Gmail Annotations

Stand out in Gmail's Promotions tab with rich previews, deal badges, and product carousels.

### What Are Gmail Annotations?

Gmail Annotations allow promotional emails to display:

- **Featured images** in the preview
- **Deal badges** showing discounts
- **Product carousels** with up to 10 products
- **Expiration dates** for time-sensitive offers
- **Brand logos**

### How to Use Gmail Annotations

Add annotations to your campaigns via the API or dashboard:

```http
POST /api/v1/campaigns/:id/annotations
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "organization": {
    "name": "Acme Store",
    "url": "https://acme.com",
    "logoUrl": "https://acme.com/logo.png"
  },
  "featuredImageUrl": "https://acme.com/promo-banner.png",
  "deal": {
    "discountDescription": "25% off everything",
    "discountCode": "SAVE25",
    "availabilityEnds": "2025-02-28T00:00:00Z"
  },
  "goToAction": {
    "name": "Shop Now",
    "url": "https://acme.com/sale"
  },
  "products": [
    {
      "name": "Premium Widget",
      "imageUrl": "https://acme.com/widget.png",
      "price": 49.99,
      "currency": "USD",
      "url": "https://acme.com/widget"
    }
  ]
}
```

ApexMail generates the required JSON-LD markup and injects it into the email `<head>` automatically.

### Generated Schema

The service generates JSON-LD markup conforming to schema.org:

```json
{
  "@context": "https://schema.org",
  "@type": "DiscountOffer",
  "description": "25% off everything",
  "discountCode": "SAVE25",
  "availabilityEnds": "2025-02-28T00:00:00.000Z",
  "image": "https://acme.com/promo-banner.png"
}
```

### Image Requirements

| Image Type | Dimensions | Max Size |
|------------|------------|----------|
| Featured Image | 538 x 138 px | 50 KB |
| Product Image | 250 x 250 px | 30 KB |
| Logo | 200 x 200 px | 20 KB |

### Validation

Validate your annotation configuration before sending:

```http
POST /api/v1/campaigns/:id/annotations/validate
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{ ... same payload as above ... }
```

The response includes any errors or warnings about your annotation configuration.

---

## Best Practices

### 1. Filter Bot Traffic Before Analysis

Always run click events through bot detection before calculating engagement metrics.

### 2. Enable Two-Way Communication

- Replace `no-reply@` with monitored addresses
- Respond to replies within 24 hours
- Use webhook integration for real-time alerts

### 3. Monitor Trust Trends

- Calculate trust scores weekly
- Alert on declining trends
- Segment by trust level for targeted re-engagement

### 4. Use Gmail Annotations for Promotions

- Always include featured images
- Add deal badges for time-sensitive offers
- Test with Google's Email Markup Tester

---

## API Reference

See [API Documentation](../api/endpoints/analytics.md) for full endpoint reference.

## Related Documentation

- [Email Authentication](./email-authentication.md) - ARC, MTA-STS, BIMI
- [Inbox Placement Testing](../user-guide/inbox-placement-testing.md)
- [Deliverability Best Practices](../operations/deliverability.md)
