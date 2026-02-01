# ADR 0003: Sales Autopilot CRM

## Status
Accepted

## Date
2024-01-20

## Context
ApexMail's control plane needs a CRM to manage:
- Lead generation from website visitors
- Sales pipeline and deal management
- Customer relationship tracking
- Integration with billing (Stripe-only)

We wanted to avoid external CRM SaaS dependencies while providing full functionality.

## Decision
We built **Sales Autopilot** as an internal CRM module with the following components:

### Architecture
```
apps/sales-autopilot/
├── src/
│   ├── ads/           # Ad platform integration
│   ├── calendar/      # Meeting scheduling
│   ├── campaigns/     # Drip campaigns, sequences
│   ├── crm/           # Core CRM functionality
│   ├── enrichment/    # Lead enrichment
│   ├── inbox/         # Unified inbox
│   └── scrapers/      # Ethical web scraping
```

### Core Components

#### CRM Engine
- **Contacts**: Full lifecycle management with custom fields
- **Companies**: Organization hierarchy and relationship mapping
- **Deals**: Pipeline stages with probability scoring
- **Activities**: Timeline tracking (calls, emails, meetings)

#### Lead Generation
- Website visitor tracking (privacy-compliant)
- Form capture and progressive profiling
- Intent signal scoring

#### Enrichment
- DNS/WHOIS lookups for domain data
- Social profile discovery
- Technographic detection (built with scrapers)

#### Campaigns
- Drip sequences with branching logic
- Multi-channel (email, in-app notifications)
- A/B testing with statistical significance

### Data Model
```typescript
interface Contact {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  company?: Company;
  score: number;          // Lead score 0-100
  lifecycle: LeadStatus;  // subscriber → lead → mql → sql → customer
  customFields: Record<string, unknown>;
  activities: Activity[];
}

interface Deal {
  id: string;
  name: string;
  amount: number;
  probability: number;
  stage: PipelineStage;
  contacts: Contact[];
  expectedCloseDate: Date;
}
```

## Consequences

### Positive
- Zero external CRM costs
- Tight integration with email platform
- Full data ownership
- Customizable to exact needs

### Negative
- Development and maintenance overhead
- No ecosystem of CRM integrations
- Feature parity with mature CRMs takes time

### Risks Mitigated
- Data silos: Single database with email platform
- Vendor lock-in: Full data portability
- Privacy: All data processing in-house

## Related ADRs
- ADR 0001: Database Choice (shared PostgreSQL)
- ADR 0004: AI Local Inference (lead scoring models)
