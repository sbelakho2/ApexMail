# Analytics & Data Science Module

## Overview

ApexMail includes advanced data science capabilities for optimizing email delivery, predicting customer behavior, and automating campaign decisions. This document describes the analytics modules implemented in `apps/analytics`.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ANALYTICS SERVICE                                    │
│                        (apps/analytics)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│   │ Send Time        │     │ Churn Prediction │     │ Subject Line     │   │
│   │ Optimizer (STO)  │     │ Engine           │     │ Analyzer (NLP)   │   │
│   │                  │     │                  │     │                  │   │
│   │ Bayesian         │     │ Engagement       │     │ Token Analysis   │   │
│   │ Optimization     │     │ Decay Analysis   │     │ Spam Detection   │   │
│   └──────────────────┘     └──────────────────┘     └──────────────────┘   │
│                                                                             │
│   ┌──────────────────┐     ┌──────────────────┐                            │
│   │ Campaign         │     │ Reply Handler    │                            │
│   │ Autopilot        │     │ (Worker)         │                            │
│   │                  │     │                  │                            │
│   │ Thompson         │     │ Intent           │                            │
│   │ Sampling         │     │ Classification   │                            │
│   └──────────────────┘     └──────────────────┘                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Modules

### 1. Send Time Optimizer (STO)

**Purpose:** Determine the optimal time to send emails to maximize engagement.

**Algorithm:** Bayesian optimization with Beta distribution priors

**Location:** `apps/analytics/src/send-time-optimizer.ts`

#### How It Works

1. **Profile Building**: Analyzes recipient's historical engagement patterns
2. **Hourly Distribution**: Computes engagement probability per hour (0-23)
3. **Daily Distribution**: Computes engagement probability per day (Mon-Sun)
4. **Bayesian Smoothing**: Uses industry priors for cold-start (no history)
5. **Confidence Scoring**: Returns confidence based on sample size

#### API

```typescript
import { SendTimeOptimizer } from '@apexmail/analytics';

const sto = new SendTimeOptimizer({ db, redis, logger });

// Single recipient
const { suggestedTime, confidence, profile } = await sto.getOptimalSendTime(
  'user@example.com',
  'tenant_123'  // optional
);

// Bulk optimization
const results = await sto.optimizeBatch([
  { email: 'user1@example.com' },
  { email: 'user2@example.com' },
], 'tenant_123');
```

#### Industry Priors (Cold Start)

| Hour | Prior | Hour | Prior |
|------|-------|------|-------|
| 9 AM | 0.10 | 3 PM | 0.06 |
| 10 AM | 0.11 | 4 PM | 0.05 |
| 11 AM | 0.10 | 5 PM | 0.04 |

### 2. Churn Prediction Engine

**Purpose:** Predict tenant and recipient churn risk to enable proactive retention.

**Algorithm:** Feature-based scoring with engagement decay analysis

**Location:** `apps/analytics/src/churn-prediction.ts`

#### Risk Signals

| Signal | Weight | Critical Threshold |
|--------|--------|-------------------|
| Complaint Rate | High | > 0.3% |
| Bounce Rate | Medium | > 10% |
| Days Inactive | High | > 60 days |
| Engagement Decay | High | > 50% drop |
| Send Volume Drop | Medium | > 75% decline |

#### Risk Tiers

- **Critical**: Score > 0.8 - Immediate intervention required
- **High**: Score 0.6-0.8 - Schedule retention call
- **Medium**: Score 0.4-0.6 - Send win-back campaign
- **Low**: Score 0.2-0.4 - Monitor closely
- **Healthy**: Score < 0.2 - No action needed

#### API

```typescript
import { ChurnPredictionEngine } from '@apexmail/analytics';

const churn = new ChurnPredictionEngine({ db, redis, logger });

// Single tenant
const metrics = await churn.predictTenantChurn('tenant_123');
// Returns: { tenantId, name, churnPrediction: { riskScore, riskTier, signals, recommendations } }

// All at-risk tenants
const atRisk = await churn.getAtRiskTenants('medium');  // min risk tier
```

### 3. Subject Line Analyzer (NLP)

**Purpose:** Score subject lines for engagement potential and suggest A/B variations.

**Algorithm:** Token analysis, sentiment detection, spam pattern matching

**Location:** `apps/analytics/src/subject-line-analyzer.ts`

#### Scoring Factors

| Factor | Weight | Optimal |
|--------|--------|---------|
| Length | 15% | 30-60 chars |
| Urgency Words | 10% | 1-2 tokens |
| Personalization | 15% | Has merge tags |
| Clarity | 20% | Clear action |
| Spam Risk | 20% | < 0.2 score |
| Sentiment | 10% | Positive |
| Power Words | 10% | Industry-aligned |

#### Token Categories

- **Urgency**: now, today, limited, last chance, expires
- **Exclusivity**: exclusive, only, invitation, members
- **Benefit**: free, save, new, improve, discover
- **Curiosity**: secret, reveal, surprising, unexpected
- **Social Proof**: popular, trending, everyone, thousands

#### API

```typescript
import { SubjectLineAnalyzer } from '@apexmail/analytics';

const analyzer = new SubjectLineAnalyzer({ db, redis, logger });

// Score a subject line
const score = await analyzer.scoreSubjectLine(
  '🚀 Limited Time: Save 50% on Your First Order',
  'tenant_123'  // optional, for personalized insights
);

// Generate A/B variations
const variations = await analyzer.suggestVariations(
  'Check out our new product',
  'tenant_123'
);
```

### 4. Campaign Autopilot (Multi-Armed Bandit)

**Purpose:** Automatically optimize email template selection using exploration/exploitation.

**Algorithm:** Thompson Sampling with Beta-Bernoulli model

**Location:** `apps/analytics/src/campaign-autopilot.ts`

#### How Thompson Sampling Works

1. **Prior**: Each template starts with Beta(1, 1) - uniform prior
2. **Sampling**: Sample from each template's Beta distribution
3. **Selection**: Choose template with highest sampled value
4. **Update**: Record outcome (open/click) to update posterior

#### Convergence

- After ~100 sends, the bandit typically converges to best template
- Maintains 5-10% exploration to detect changing preferences
- Auto-detects significant performance changes

#### API

```typescript
import { CampaignAutopilot } from '@apexmail/analytics';

const autopilot = new CampaignAutopilot({ db, redis, logger });

// Select best template (with exploration)
const { templateId, explorationMode } = await autopilot.selectTemplate(
  'campaign_123',
  ['template_A', 'template_B', 'template_C']
);

// Record outcome
await autopilot.recordOutcome('campaign_123', 'template_A', 'open');
await autopilot.recordOutcome('campaign_123', 'template_A', 'click');

// Get optimization report
const report = await autopilot.getOptimizationReport('campaign_123');
```

### 5. Reply Handler (AI Classification)

**Purpose:** Automatically classify inbound email replies and suggest actions.

**Algorithm:** Pattern matching + optional LLM integration

**Location:** `apps/worker/src/processors/reply-handler.ts`

#### Classification Categories

| Category | Example | Suggested Action |
|----------|---------|-----------------|
| `out_of_office` | "I'm away until..." | Reschedule send |
| `not_interested` | "Please remove me" | Unsubscribe |
| `interested` | "Tell me more" | Escalate to sales |
| `meeting_request` | "Let's schedule a call" | Create calendar invite |
| `question` | "What pricing plans..." | Route to support |
| `complaint` | "Stop spamming me" | Flag for review |
| `wrong_person` | "I'm not the right contact" | Update CRM |
| `bounce` | "User not found" | Mark undeliverable |

#### API

```typescript
import { ReplyHandler } from '@apexmail/worker';

const handler = new ReplyHandler({
  db,
  redis,
  logger,
  llmEnabled: true,  // Enable LLM for ambiguous cases
  llmEndpoint: 'https://api.openai.com/v1/chat/completions',
  llmApiKey: process.env.OPENAI_API_KEY,
});

// Classify a reply
const result = await handler.classifyReply(
  'Re: Your product demo',
  'Thanks for reaching out! I would love to schedule a call next week.',
  'prospect@company.com',
  { 'auto-submitted': undefined }
);

// Process from queue
await handler.processInboundMessage('message_id_123');
```

## Database Schema

### Engagement Events

```sql
-- Used by STO for time optimization
SELECT 
  EXTRACT(HOUR FROM opened_at) as hour,
  COUNT(*) as opens
FROM events
WHERE event_type = 'open'
  AND recipient_email_hash = $1
GROUP BY hour;
```

### Churn Metrics

```sql
-- Tenant health metrics
SELECT
  t.id,
  COUNT(DISTINCT m.id) as total_sends,
  SUM(CASE WHEN e.event_type = 'complaint' THEN 1 ELSE 0 END) as complaints,
  MAX(m.created_at) as last_send
FROM tenants t
LEFT JOIN messages m ON m.tenant_id = t.id
LEFT JOIN events e ON e.message_id = m.id
GROUP BY t.id;
```

### Bandit State

```sql
-- Thompson Sampling state per campaign/template
CREATE TABLE campaign_template_stats (
  campaign_id TEXT NOT NULL,
  template_id TEXT NOT NULL,
  alpha NUMERIC DEFAULT 1,  -- Beta prior successes
  beta NUMERIC DEFAULT 1,   -- Beta prior failures
  sends INTEGER DEFAULT 0,
  opens INTEGER DEFAULT 0,
  clicks INTEGER DEFAULT 0,
  PRIMARY KEY (campaign_id, template_id)
);
```

## Performance Considerations

### Caching Strategy

All modules use Redis caching:

- **STO profiles**: 24-hour TTL
- **Churn predictions**: 6-hour TTL
- **Subject line scores**: 24-hour TTL (keyed by hash)
- **Bandit state**: 1-hour TTL

### Batch Processing

For high-volume operations:

```typescript
// STO batch (processes 50 recipients in parallel)
const results = await sto.optimizeBatch(recipients);

// Churn batch
const atRisk = await churn.getAtRiskTenants('low', 100);  // limit

// Subject variations (async generation)
const suggestions = await analyzer.suggestVariations(subject);
```

## Integration with Control Plane

The Control Plane dashboard (`apps/control-plane`) displays real-time analytics:

```typescript
// Dashboard API endpoint
GET /api/dashboard/stats

// Returns aggregated metrics from all analytics modules
{
  "sales": { "activeLeads": 234, "conversionRate": 0.12 },
  "compliance": { "riskAlerts": 5, "gdprPending": 12 },
  "platform": { "activeHosts": 47, "deliveryRate": 0.94 }
}
```

## Related Documentation

- [Control Plane Architecture](./control-plane-isolation.md)
- [Data Flow](./data-flow.md)
- [ADR 0001: Database Choice](../adr/0001-database-choice.md)
