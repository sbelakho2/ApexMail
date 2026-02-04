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

Security scanners and email gateways (Barracuda, Mimecast, Proofpoint, etc.) click every link in emails to check for malware. This distorts your engagement metrics.

### The Problem

Research shows bot clicks can account for **20-60%** of total clicks in B2B email campaigns:

- Security scanners click all links instantly (< 1 second)
- Multiple links clicked simultaneously from same IP
- Known bot user-agents
- Corporate email gateways pre-fetch links

### Detection Methods

```typescript
import { BotDetectionService } from '@apexmail/analytics';

const botDetector = new BotDetectionService();

// Analyze a click event
const result = botDetector.analyzeClick({
  messageId: 'msg_123',
  recipientEmail: 'user@company.com',
  linkUrl: 'https://example.com/promo',
  timestamp: new Date(),
  userAgent: 'Mozilla/5.0 (compatible; Barracuda)',
  ipAddress: '64.235.100.50',
  headers: { 'x-scanner': 'true' }
}, messageOpenTime);

if (result.isBot) {
  console.log('Bot detected:', result.botType);
  console.log('Confidence:', result.confidence);
  console.log('Reasons:', result.reasons);
}
```

### Detection Signals

| Signal | Weight | Description |
|--------|--------|-------------|
| User-Agent | 40% | Known bot patterns (Barracuda, Mimecast, etc.) |
| Timing | 35% | Clicks within 1 second of open |
| IP Reputation | 30% | Known security gateway IP ranges |
| Click Velocity | 25% | Multiple clicks in < 5 seconds |
| Headers | Variable | Missing browser headers, prefetch flags |

### Honeypot Links

Generate invisible links that only bots will click:

```typescript
// Generate honeypot link
const honeypotUrl = botDetector.generateHoneypotLink(
  'msg_123',
  'https://track.example.com'
);

// Generate HTML to embed (invisible to humans)
const honeypotHtml = botDetector.generateHoneypotHtml(honeypotUrl);

// Check if a click is on honeypot
if (botDetector.isHoneypotClick(clickedUrl)) {
  // Definitely a bot
}
```

### Adjusted Metrics

```typescript
const metrics = botDetector.getAdjustedMetrics(
  totalClicks: 1000,
  botClicks: 350,
  totalOpens: 5000,
  botOpens: 200
);

console.log('Raw click rate:', metrics.rawClickRate);       // 20%
console.log('Adjusted click rate:', metrics.adjustedClickRate); // 13.5%
console.log('Bot percentage:', metrics.botClickPercentage);  // 35%
```

---

## Reply Rate Tracking

Microsoft now "strongly recommends" allowing two-way communication. Reply rates are emerging as a key engagement KPI.

### Why No More `no-reply@`

- **Microsoft signals**: Officially recommends reply-to addresses
- **Trust building**: Two-way communication builds relationships
- **Deliverability boost**: Replies signal engagement to ISPs
- **Valuable feedback**: Learn what subscribers actually think

### Implementation

```typescript
import { ReplyTrackingService } from '@apexmail/analytics';

const replyTracker = new ReplyTrackingService();

// Process an incoming reply
const reply = replyTracker.processReply({
  messageId: '<reply123@example.com>',
  inReplyTo: '<original456@yourcompany.com>',
  references: ['<original456@yourcompany.com>'],
  from: 'customer@example.com',
  subject: 'Re: Your order has shipped',
  body: 'Thanks for the quick delivery!',
  headers: {},
  receivedAt: new Date()
}, originalMessage);

if (reply) {
  console.log('Is auto-reply:', reply.isAutoReply);
  console.log('Sentiment:', reply.sentiment);
  console.log('Thread depth:', reply.threadDepth);
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

```typescript
const config = replyTracker.generateReplyToConfig({
  brandName: 'Acme Corp',
  domain: 'acme.com',
  supportEmail: 'support@acme.com',
  enableWebhook: true,
  webhookUrl: 'https://api.acme.com/webhooks/replies'
});

// Result:
// {
//   type: 'support-ticket',
//   address: 'support@acme.com',
//   autoResponderEnabled: true,
//   autoResponderMessage: 'Thanks for your reply! The Acme Corp team will get back to you within 24 hours.',
//   webhookUrl: 'https://api.acme.com/webhooks/replies'
// }
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

### Implementation

```typescript
import { EngagementTrustService } from '@apexmail/analytics';

const trustService = new EngagementTrustService();

const trustScore = trustService.calculateTrustScore({
  subscriberId: 'sub_123',
  email: 'subscriber@example.com',
  
  // Engagement metrics
  totalEmailsSent: 50,
  totalOpens: 35,
  totalClicks: 12,
  totalReplies: 2,
  totalConversions: 5,
  
  // Timing
  firstEmailDate: new Date('2024-01-01'),
  lastEngagementDate: new Date(),
  
  // Preferences
  hasSetPreferences: true,
  preferenceLastUpdated: new Date(),
  
  // Negative signals
  totalComplaints: 0,
  totalUnsubscribeClicks: 1,
  markedAsSpam: false,
  
  // Feedback
  surveyResponses: 1,
  npsScore: 9,
  feedbackSubmissions: 1
});

console.log('Trust Score:', trustScore.overall);  // 0-100
console.log('Grade:', trustScore.grade);          // A-F
console.log('Risk Level:', trustScore.riskLevel); // low/medium/high/critical
```

### Component Scoring

| Component | Inputs | Impact |
|-----------|--------|--------|
| Credibility | Opens, clicks, spam marks | 30% of trust |
| Reliability | Tenure, preferences, recency | 30% of trust |
| Intimacy | Replies, surveys, NPS | 25% of trust |
| Self-Orientation | Frequency vs engagement | 15% divisor |

### Trust Grades

| Grade | Score | Interpretation |
|-------|-------|----------------|
| A | 85-100 | High trust, engaged subscriber |
| B | 70-84 | Good trust, room to grow |
| C | 55-69 | Moderate, needs personalization |
| D | 40-54 | At risk, re-engage |
| F | 0-39 | Eroded trust, sunset flow |

### Campaign-Level Trust Metrics

```typescript
const campaignMetrics = trustService.calculateCampaignTrustMetrics(
  'campaign_123',
  subscribers,
  previousScoresMap
);

console.log('Average Trust:', campaignMetrics.averageTrustScore);
console.log('Segments:', campaignMetrics.subscriberSegments);
// { highTrust: 450, mediumTrust: 300, lowTrust: 180, atRisk: 70 }
console.log('Trend:', campaignMetrics.trustTrend); // improving/stable/declining
console.log('Top Recommendations:', campaignMetrics.topRecommendations);
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

### Implementation

```typescript
import { GmailAnnotationsService } from '@apexmail/mta';

const annotationService = new GmailAnnotationsService();

const result = annotationService.generateAnnotations({
  organization: {
    name: 'Acme Store',
    url: 'https://acme.com',
    logoUrl: 'https://acme.com/logo.png'
  },
  featuredImageUrl: 'https://acme.com/promo-banner.png',
  deal: {
    discountDescription: '25% off everything',
    discountCode: 'SAVE25',
    availabilityEnds: new Date('2025-02-28')
  },
  goToAction: {
    name: 'Shop Now',
    url: 'https://acme.com/sale'
  },
  products: [
    {
      name: 'Premium Widget',
      imageUrl: 'https://acme.com/widget.png',
      price: 49.99,
      currency: 'USD',
      url: 'https://acme.com/widget'
    }
  ]
});

// Add to email <head>
const emailHead = result.html;
```

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

```typescript
const validation = annotationService.validateConfig(config);

if (!validation.valid) {
  console.error('Errors:', validation.errors);
}
if (validation.warnings.length > 0) {
  console.warn('Warnings:', validation.warnings);
}
```

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
