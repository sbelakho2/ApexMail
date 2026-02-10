# Inbox Placement Testing

Monitor actual inbox vs spam folder placement rates using seed list testing.

## Overview

"Delivered" doesn't mean "inboxed". Inbox placement testing measures where your emails actually land:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Email Journey                                 │
│                                                                  │
│   Sent → Delivered → ?                                          │
│                      ├── 📥 Inbox (Primary)   ← TARGET          │
│                      ├── 📂 Promotions/Social                   │
│                      ├── 🗑️ Spam/Junk                           │
│                      └── ❌ Missing/Blocked                     │
└─────────────────────────────────────────────────────────────────┘
```

## Industry Benchmarks

| Email Type | Target Inbox Rate | Minimum Acceptable |
|------------|-------------------|-------------------|
| Transactional | 95-99% | 90% |
| Marketing | 85-95% | 80% |
| Cold Outreach | 70-85% | 60% |

**Below 80% requires immediate attention.**

## How It Works

1. **Seed Accounts**: Maintain test accounts across major ISPs
2. **Test Emails**: Send identical content to all seed accounts
3. **Mailbox Scanning**: Check where emails landed via IMAP
4. **Analysis**: Generate placement reports and recommendations

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Gmail Seed  │    │ Outlook Seed │    │  Yahoo Seed  │
│  Accounts    │    │   Accounts   │    │   Accounts   │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  Placement Test     │
                │  • Send test email  │
                │  • Wait 5-30 min    │
                │  • Check mailboxes  │
                │  • Analyze results  │
                └─────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   Placement Report     │
              │ • 92% Inbox (Gmail)    │
              │ • 88% Inbox (Outlook)  │
              │ • 78% Inbox (Yahoo)    │
              │ • Recommendations...   │
              └────────────────────────┘
```

## API Usage

### Run a Placement Test

```http
POST /api/v1/inbox-placement/tests
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "testName": "March Newsletter Test",
  "subject": "Your Weekly Update",
  "htmlBody": "<html>...</html>",
  "textBody": "Plain text version...",
  "fromAddress": "newsletter@yourdomain.com",
  "fromName": "Your Company"
}
```

### Response

```json
{
  "testId": "ipt_abc123",
  "status": "sending",
  "seedCount": 24,
  "estimatedCompletion": "2024-03-15T10:30:00Z",
  "message": "Test emails being sent. Results available in ~30 minutes."
}
```

### Check Test Results

```http
GET /api/v1/inbox-placement/tests/:testId
Authorization: Bearer {{token}}
```

### Response

```json
{
  "testId": "ipt_abc123",
  "testName": "March Newsletter Test",
  "status": "completed",
  "completedAt": "2024-03-15T10:28:00Z",
  "summary": {
    "totalSent": 24,
    "totalReceived": 23,
    "inboxCount": 20,
    "spamCount": 2,
    "promotionsCount": 1,
    "missingCount": 1,
    "inboxRate": 83.33,
    "deliveryRate": 95.83,
    "byProvider": {
      "gmail": {
        "sent": 8,
        "inbox": 6,
        "spam": 1,
        "other": 1,
        "missing": 0,
        "inboxRate": 75.0
      },
      "outlook": {
        "sent": 8,
        "inbox": 7,
        "spam": 1,
        "other": 0,
        "missing": 0,
        "inboxRate": 87.5
      },
      "yahoo": {
        "sent": 8,
        "inbox": 7,
        "spam": 0,
        "other": 0,
        "missing": 1,
        "inboxRate": 87.5
      }
    }
  },
  "recommendations": [
    "Gmail inbox rate (75%) is below target. Review Google Postmaster Tools.",
    "Consider segmenting inactive Gmail subscribers.",
    "Ensure proper List-Unsubscribe-Post header is present."
  ]
}
```

### Get Placement Trends

```http
GET /api/v1/inbox-placement/trends?startDate=2024-01-01&endDate=2024-03-15&granularity=week
Authorization: Bearer {{token}}
```

### Response

```json
{
  "periods": [
    { "period": "2024-W01", "inboxRate": 85.2, "spamRate": 8.1, "testCount": 4 },
    { "period": "2024-W02", "inboxRate": 84.8, "spamRate": 9.2, "testCount": 3 },
    { "period": "2024-W03", "inboxRate": 88.1, "spamRate": 6.5, "testCount": 5 },
    { "period": "2024-W04", "inboxRate": 91.3, "spamRate": 4.2, "testCount": 4 }
  ],
  "overallTrend": "improving",
  "recommendation": "Good: Inbox placement is healthy. Continue monitoring and optimizing."
}
```

### Provider-Specific Analysis

```http
GET /api/v1/inbox-placement/providers?days=30
Authorization: Bearer {{token}}
```

### Response

```json
{
  "gmail": {
    "avgInboxRate": 82.5,
    "avgSpamRate": 10.2,
    "testCount": 12,
    "trend": "stable",
    "tips": [
      "Gmail: Use Google Postmaster Tools to monitor reputation",
      "Gmail: Segment inactive subscribers to improve engagement",
      "Gmail: Ensure proper List-Unsubscribe-Post header (RFC 8058)"
    ]
  },
  "outlook": {
    "avgInboxRate": 91.3,
    "avgSpamRate": 5.1,
    "testCount": 12,
    "trend": "up",
    "tips": [
      "Placement looks good! Continue monitoring."
    ]
  },
  "yahoo": {
    "avgInboxRate": 78.5,
    "avgSpamRate": 12.8,
    "testCount": 12,
    "trend": "down",
    "tips": [
      "Yahoo: Ensure proper FBL registration",
      "Yahoo: Watch for rate limiting on new IPs",
      "Review content for spam trigger words"
    ]
  }
}
```

## Placement Categories

| Category | Description | Impact |
|----------|-------------|--------|
| **Inbox** | Primary inbox folder | ✅ Maximum visibility |
| **Promotions** | Gmail Promotions tab | ⚠️ Lower engagement |
| **Social** | Gmail Social tab | ⚠️ Lower engagement |
| **Spam** | Junk/Spam folder | ❌ Near-zero engagement |
| **Missing** | Not delivered or quarantined | ❌ Zero reach |

## Provider-Specific Tips

### Gmail

- Register with [Google Postmaster Tools](https://postmaster.google.com/)
- Segment inactive subscribers (no opens in 90+ days)
- Use engagement-based sending (prioritize active users)
- Implement one-click unsubscribe (RFC 8058)
- Monitor spam rate (keep under 0.1%)

### Microsoft (Outlook/Hotmail)

- Register for [SNDS](https://sendersupport.olc.protection.outlook.com/snds/)
- Apply for [JMRP](https://sendersupport.olc.protection.outlook.com/pm/)
- Use Outlook Sender Support if blocklisted
- Monitor feedback loop reports

### Yahoo/AOL

- Register for Yahoo FBL (Feedback Loop)
- Monitor complaint rates closely
- Use DKIM and proper alignment
- Maintain consistent sending patterns

### Apple iCloud

- Similar to other providers
- Focus on engagement signals
- BIMI support available

## Best Practices

### 1. Test Before Major Sends

```
Campaign Workflow:
1. Create campaign content
2. Run inbox placement test
3. If < 80% inbox rate:
   - Review content for spam triggers
   - Check authentication
   - Verify sender reputation
4. Send to full list
```

### 2. A/B Test Content

Test different versions to see which achieves better placement:

```json
{
  "testA": { "subject": "Limited Time Offer!", "inboxRate": 72 },
  "testB": { "subject": "Your Weekly Update", "inboxRate": 89 }
}
```

### 3. Monitor Trends

Weekly placement tests catch issues before they become critical:

```
Week 1: 92% ✅
Week 2: 88% ✅
Week 3: 78% ⚠️ <- Investigate!
Week 4: 65% ❌ <- Too late, damage done
```

### 4. Segment by Provider

If one provider shows poor placement:

```sql
-- Create segment for problematic provider
SELECT email FROM subscribers 
WHERE domain IN ('gmail.com', 'googlemail.com')
AND last_opened > NOW() - INTERVAL '90 days';
```

## Troubleshooting

### Low Gmail Inbox Rate

1. Check Google Postmaster Tools for reputation
2. Review recent spam complaint rate
3. Verify DMARC alignment
4. Segment to engaged users only
5. Reduce sending volume temporarily

### High Spam Rate

1. Remove spam trigger words from content
2. Balance text-to-image ratio
3. Verify all links are legitimate
4. Check for broken HTML
5. Ensure unsubscribe is prominent

### Missing Emails

1. Check if sending IP is blocklisted
2. Verify MX records for recipient domain
3. Review bounce messages
4. Check rate limiting thresholds

## Database Schema

The inbox placement service uses these tables:

```sql
Each inbox placement test tracks:

- **Test ID**: Unique identifier for the test run
- **Test name**: Your label for the test
- **Status**: pending, running, or completed
- **Results**: Per-provider inbox vs. spam placement
- **Summary**: Aggregate placement rates across all providers

## Related Documentation

- [Email Authentication](./email-authentication.md)
- [Deliverability Best Practices](./deliverability.md)
- [Analytics Module](../architecture/analytics-data-science.md)
