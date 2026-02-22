# Hetzner Simulation Infrastructure Checklist

This is the simulation/staging deployment runbook for ApexMail on Hetzner infrastructure. It documents the shadow-production environment for realistic load testing, chaos engineering, and continuous verification.

> **Infrastructure Overview:**  
> - **API Server:** `apex-sim-api` (API + dashboard + Stripe webhook handler)  
> - **Worker Server:** `apex-sim-worker` (queue workers + sender + webhook dispatcher)  
> - **Data Server:** `apex-sim-data` (PostgreSQL + Redis)  
> - **SSH Access:** `ssh -i ~/.ssh/apex-sim-key root@<SERVER_IP>`  
> - **Purpose:** Shadow production for invariant testing + chaos engineering

---

## Table of Contents

1. [Design Goals](#design-goals)
2. [Infrastructure Architecture](#1-infrastructure-architecture)
3. [Server Setup](#2-server-setup)
4. [SSH Access](#3-ssh-access)
5. [Assertion Daemon & Invariants](#4-assertion-daemon--invariants)
6. [CLI Automation](#5-cli-automation)
7. [Provisioning](#6-provisioning)
8. [AWS SES Plumbing](#7-aws-ses-plumbing)
9. [Stripe Billing Simulation](#8-stripe-billing-simulation)
10. [Deployment](#9-deployment)
11. [Load Testing](#10-load-testing)
12. [Chaos Engineering](#11-chaos-engineering)
13. [Reports & Verification](#12-reports--verification)
14. [Pass/Fail Criteria](#13-passfail-criteria)

---

## Design Goals

**One command should:**

1. Provision infrastructure (Hetzner + AWS SES plumbing)
2. Deploy the stack
3. Run realistic load + billing churn + chaos
4. Continuously verify correctness
5. Abort immediately on any invariant breach
6. Export a complete report bundle

```bash
# Single command execution
./ops/sim/apexsim all --env staging-sim --tenants 2000 --duration 6h --load-profile realistic --chaos-profile medium --fail-fast
```

---

## 1. Infrastructure Architecture

### 1.1 Three-Server Setup (Shadow Production)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  INTERNET                                        │
└──────────────────────────────────────────────────────────────────────────────────┘
                     │                    │                    │
                     ▼                    ▼                    ▼
┌────────────────────────────┐  ┌────────────────────────────┐  ┌────────────────────────────┐
│     API SERVER             │  │    WORKER SERVER           │  │      DATA SERVER           │
│     apex-sim-api           │  │    apex-sim-worker         │  │      apex-sim-data         │
│     cpx31 (4 vCPU, 8GB)    │  │    cpx31 (4 vCPU, 8GB)     │  │      cpx31 (4 vCPU, 8GB)   │
│                            │  │                            │  │                            │
│  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │
│  │  API Server :3000    │  │  │  │  Queue Workers       │  │  │  │  PostgreSQL 16       │  │
│  │  - REST API          │  │  │  │  - BullMQ processors │  │  │  │  - apexmail database │  │
│  │  - GraphQL           │  │  │  │  - Email sender      │  │  │  │  - Message ledger    │  │
│  │  - Rate limiting     │  │  │  │  - Event processor   │  │  │  │  - Billing ledger    │  │
│  └──────────────────────┘  │  │  └──────────────────────┘  │  │  └──────────────────────┘  │
│                            │  │                            │  │                            │
│  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │
│  │  Dashboard :4000     │  │  │  │  Email Sender        │  │  │  │  Redis 7             │  │
│  │  - Next.js web app   │  │  │  │  - SES integration   │  │  │  │  - Job queues        │  │
│  │  - Auth flows        │  │  │  │  - Throttle handling │  │  │  │  - Rate limit state  │  │
│  └──────────────────────┘  │  │  └──────────────────────┘  │  │  │  - Session cache     │  │
│                            │  │                            │  │  └──────────────────────┘  │
│  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │  │                            │
│  │  Stripe Webhooks     │  │  │  │  Webhook Dispatcher  │  │  │  ┌──────────────────────┐  │
│  │  :3000/webhooks      │  │  │  │  - Outbound webhooks │  │  │  │  Toxiproxy           │  │
│  │  - Subscription mgmt │  │  │  │  - Retry logic       │  │  │  │  - Network chaos     │  │
│  │  - Entitlement sync  │  │  │  │  - DLQ handling      │  │  │  │  - Latency injection │  │
│  └──────────────────────┘  │  │  └──────────────────────┘  │  │  └──────────────────────┘  │
│                            │  │                            │  │                            │
│  ┌──────────────────────┐  │  │  ┌──────────────────────┐  │  └────────────────────────────┘
│  │  Assertion Daemon    │  │  │  │  SES Event Consumer  │  │
│  │  - Invariant checker │  │  │  │  - SQS polling       │  │
│  │  - Ledger validator  │  │  │  │  - Event processing  │  │
│  └──────────────────────┘  │  │  └──────────────────────┘  │
└────────────────────────────┘  └────────────────────────────┘
        │                               │                               │
        └───────────────────────────────┼───────────────────────────────┘
                                        │
                               Private Network
                              (10.0.0.0/24)
```

### 1.2 Network Topology

| Server | Private IP | Public IP | Purpose |
|--------|------------|-----------|---------|
| apex-sim-api | 10.0.0.1 | (assigned) | API + Dashboard + Webhooks |
| apex-sim-worker | 10.0.0.2 | (assigned) | Workers + Sender + Dispatcher |
| apex-sim-data | 10.0.0.3 | (assigned) | PostgreSQL + Redis |

### 1.3 Port Allocation

| Port | Server | Service | Access |
|------|--------|---------|--------|
| 22 | All | SSH | Public (key-only) |
| 3000 | API | API Server | Public |
| 4000 | API | Dashboard | Public |
| 5432 | Data | PostgreSQL | Private (10.0.0.0/24) |
| 6379 | Data | Redis | Private (10.0.0.0/24) |
| 8474 | Data | Toxiproxy API | Private |
| 9090 | API | Prometheus | Private |
| 9100 | All | Node Exporter | Private |

### 1.4 Firewall Rules

```bash
# API Server
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow from 10.0.0.0/24 to any port 9090 comment 'Prometheus'
ufw allow from 10.0.0.0/24 to any port 9100 comment 'Node Exporter'

# Worker Server
ufw allow 22/tcp comment 'SSH'
ufw allow from 10.0.0.0/24 comment 'Private network'

# Data Server
ufw allow 22/tcp comment 'SSH'
ufw allow from 10.0.0.0/24 to any port 5432 comment 'PostgreSQL'
ufw allow from 10.0.0.0/24 to any port 6379 comment 'Redis'
ufw allow from 10.0.0.0/24 to any port 8474 comment 'Toxiproxy'
```

---

## 2. Server Setup

### 2.1 API Server (apex-sim-api)

**Prerequisites:**
- [x] Ubuntu 22.04 LTS
- [x] Docker & Docker Compose installed
- [x] Node.js 20+ installed
- [x] SSH key access configured

**Services running:**
- [x] API Server (Node.js on port 3000)
- [x] Dashboard (Next.js on port 4000)
- [x] Stripe webhook handler
- [x] Assertion daemon
- [x] Prometheus (port 9090)
- [x] Stripe CLI (webhook forwarding)

**Environment:**
```bash
# /opt/apexmail/.env
NODE_ENV=staging
DATABASE_URL=postgresql://apexmail:${DB_PASSWORD}@10.0.0.3:5432/apexmail
REDIS_URL=redis://:${REDIS_PASSWORD}@10.0.0.3:6379/0
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
SES_REGION=eu-west-1
SES_CONFIGURATION_SET=apexmail-staging-sim
RECIPIENT_ALLOWLIST=@example.com,@test.apexmail.dev
```

### 2.2 Worker Server (apex-sim-worker)

**Prerequisites:**
- [x] Ubuntu 22.04 LTS
- [x] Docker & Docker Compose installed
- [x] Node.js 20+ installed
- [x] AWS CLI configured
- [x] SSH key access configured

**Services running:**
- [x] Queue workers (BullMQ processors)
- [x] Email sender service
- [x] SES event consumer (SQS polling)
- [x] Webhook dispatcher
- [x] Node Exporter (port 9100)

**Environment:**
```bash
# /opt/apexmail/.env
NODE_ENV=staging
DATABASE_URL=postgresql://apexmail:${DB_PASSWORD}@10.0.0.3:5432/apexmail
REDIS_URL=redis://:${REDIS_PASSWORD}@10.0.0.3:6379/0
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=eu-west-1
SES_CONFIGURATION_SET=apexmail-staging-sim
SQS_EVENTS_QUEUE_URL=https://sqs.eu-west-1.amazonaws.com/ACCOUNT/apexmail-staging-sim-events
RECIPIENT_ALLOWLIST=@example.com,@test.apexmail.dev
```

### 2.3 Data Server (apex-sim-data)

**Prerequisites:**
- [x] Ubuntu 22.04 LTS
- [x] Docker & Docker Compose installed
- [x] SSH key access configured

**Services running:**
- [x] PostgreSQL 16 (port 5432)
- [x] Redis 7 (port 6379)
- [x] Toxiproxy (port 8474)
- [x] Node Exporter (port 9100)

**PostgreSQL Configuration:**
```bash
# /etc/postgresql/16/main/postgresql.conf
max_connections = 200
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 32MB
maintenance_work_mem = 512MB
wal_level = replica
max_wal_senders = 3
```

---

## 3. SSH Access

### 3.1 SSH Configuration

```bash
# ~/.ssh/config
Host apex-sim-api
    HostName <API_SERVER_IP>
    User root
    IdentityFile ~/.ssh/apex-sim-key

Host apex-sim-worker
    HostName <WORKER_SERVER_IP>
    User root
    IdentityFile ~/.ssh/apex-sim-key

Host apex-sim-data
    HostName <DATA_SERVER_IP>
    User root
    IdentityFile ~/.ssh/apex-sim-key
```

### 3.2 Helper Script

```bash
# Usage
./ops/sim/hetzner/ssh.sh api          # SSH to API server
./ops/sim/hetzner/ssh.sh worker       # SSH to Worker server
./ops/sim/hetzner/ssh.sh data         # SSH to Data server
./ops/sim/hetzner/ssh.sh api -- "docker ps"  # Run command
```

---

## 4. Assertion Daemon & Invariants

### 4.1 Design: "No Silent Failures" Enforcement

The assertion daemon runs continuously during test runs and **fails the run immediately** if any invariant is breached.

### 4.2 Message Correctness Invariants (A)

| Invariant | Detection | Severity |
|-----------|-----------|----------|
| **A1:** Duplicate send for same `(tenant_id, idempotency_key)` | Query message ledger for duplicates | CRITICAL |
| **A2:** Message stuck non-terminal > X minutes | Query pending messages older than threshold | CRITICAL |
| **A3:** Event applied to wrong tenant/message | Cross-reference events with message ownership | CRITICAL |
| **A4:** Missing terminal outcome after X minutes for accepted sends | Query accepted messages without terminal state | CRITICAL |
| **A5:** Suppressed recipient still sent | Check suppression list against sent messages | CRITICAL |

```sql
-- A1: Detect duplicate sends
SELECT tenant_id, idempotency_key, COUNT(*) as count
FROM messages
WHERE idempotency_key IS NOT NULL
GROUP BY tenant_id, idempotency_key
HAVING COUNT(*) > 1;

-- A2: Stuck non-terminal messages
SELECT id, tenant_id, status, created_at
FROM messages
WHERE status NOT IN ('delivered', 'bounced', 'failed', 'rejected')
  AND created_at < NOW() - INTERVAL '15 minutes';

-- A4: Missing terminal outcome
SELECT id, tenant_id, status, created_at
FROM messages
WHERE status = 'accepted'
  AND created_at < NOW() - INTERVAL '30 minutes';
```

### 4.3 Billing/Entitlement Invariants (B)

| Invariant | Detection | Severity |
|-----------|-----------|----------|
| **B1:** Tenant sends while not entitled (plan canceled/past due/no subscription) | Cross-reference sends with entitlement state at send time | CRITICAL |
| **B2:** Tenant blocked while entitled (paid but rejected) | Check rejected sends against active subscriptions | CRITICAL |
| **B3:** Overage meter ≠ usage ledger (drift) | Compare Stripe meter aggregates with internal usage | HIGH |
| **B4:** Stripe event replay causes duplicate entitlement transitions | Check for duplicate subscription state changes | CRITICAL |

```sql
-- B1: Sends without entitlement
SELECT m.id, m.tenant_id, m.created_at, t.subscription_status
FROM messages m
JOIN tenants t ON m.tenant_id = t.id
WHERE m.created_at > NOW() - INTERVAL '1 hour'
  AND t.subscription_status NOT IN ('active', 'trialing');

-- B3: Usage drift detection
SELECT 
  t.id as tenant_id,
  t.stripe_customer_id,
  COUNT(m.id) as internal_count,
  t.stripe_usage_reported as stripe_count,
  ABS(COUNT(m.id) - COALESCE(t.stripe_usage_reported, 0)) as drift
FROM tenants t
LEFT JOIN messages m ON m.tenant_id = t.id 
  AND m.created_at > DATE_TRUNC('month', NOW())
GROUP BY t.id
HAVING ABS(COUNT(m.id) - COALESCE(t.stripe_usage_reported, 0)) > 0;
```

### 4.4 Systems Invariants (C)

| Invariant | Detection | Severity |
|-----------|-----------|----------|
| **C1:** Queue age exceeds threshold (backlog runaway) | Monitor oldest job age in BullMQ | HIGH |
| **C2:** Worker crash loop | Monitor process restarts/uptime | CRITICAL |
| **C3:** DB pool exhaustion | Monitor active connections vs max | HIGH |
| **C4:** SES throttling not backing off (retry storm) | Monitor retry rate vs throttle events | HIGH |
| **C5:** Webhook delivery retry storm (unbounded) | Monitor webhook retry queue depth | HIGH |

### 4.5 Assertion Daemon Output

On invariant breach:
1. Print exact failing keys (`tenant_id`, `message_id`, `event_id`, `stripe_event_id`)
2. Snapshot relevant rows to report bundle
3. Dump service logs
4. Exit with nonzero status code

```bash
# Run assertion daemon
./ops/sim/apexsim assert --strict --abort-on-first

# Example output on failure:
# ❌ INVARIANT BREACH: A1 - Duplicate send detected
#    tenant_id: ten_abc123
#    idempotency_key: msg_xyz789
#    count: 2
#    messages: [msg_001, msg_002]
# 
# Snapshotting evidence to reports/2026-02-22T14:30:00Z/
# Dumping service logs...
# EXIT CODE: 1
```

---

## 5. CLI Automation

### 5.1 Directory Structure

```
ops/sim/
├── apexsim                    # Main CLI entrypoint
├── env/
│   └── staging.env            # Non-secret environment config
├── secrets/                   # Git-ignored secrets
│   └── .gitkeep
├── aws/                       # SES/SNS/SQS scripts
│   ├── setup-ses.sh
│   ├── setup-sns-sqs.sh
│   └── verify-plumbing.sh
├── hetzner/                   # Hetzner provisioning scripts
│   ├── provision.sh
│   ├── teardown.sh
│   └── ssh.sh
├── stripe/                    # Stripe CLI scripts
│   ├── setup-webhooks.sh
│   ├── trigger-scenarios.sh
│   └── create-test-customers.sh
├── load/                      # k6 load test scenarios
│   ├── realistic.js
│   ├── burst.js
│   └── billing-churn.js
├── chaos/                     # Chaos engineering scripts
│   ├── toxiproxy-setup.sh
│   ├── network-chaos.sh
│   ├── process-chaos.sh
│   └── profiles/
│       ├── mild.yaml
│       ├── medium.yaml
│       └── harsh.yaml
├── assert/                    # Assertion daemon
│   ├── daemon.ts
│   ├── invariants/
│   │   ├── message.ts
│   │   ├── billing.ts
│   │   └── systems.ts
│   └── reporters/
│       └── snapshot.ts
└── reports/                   # Output bundles
    └── .gitkeep
```

### 5.2 CLI Commands

```bash
# Full pipeline (one-shot)
./ops/sim/apexsim all --env staging-sim \
  --tenants 2000 \
  --duration 6h \
  --load-profile "realistic" \
  --chaos-profile "medium" \
  --fail-fast

# Phased execution
./ops/sim/apexsim bootstrap   # hcloud + aws + stripe prep
./ops/sim/apexsim deploy      # Deploy stack
./ops/sim/apexsim smoke       # 5–10 min, strict invariants
./ops/sim/apexsim load        # 60–180 min load test
./ops/sim/apexsim chaos       # Inject failures during load
./ops/sim/apexsim verify      # Ledger + billing reconciliation
./ops/sim/apexsim report      # Zip logs + metrics + diffs
./ops/sim/apexsim teardown    # Clean up infrastructure
```

---

## 6. Provisioning

### 6.1 Hetzner Provisioning (hcloud CLI)

```bash
# Set up hcloud context
export HCLOUD_TOKEN="..."
hcloud context create apexmail-sim --token "$HCLOUD_TOKEN"
hcloud context use apexmail-sim

# Create SSH key
hcloud ssh-key create --name apex-sim-key --public-key-from-file ~/.ssh/apex-sim-key.pub

# Create private network
hcloud network create --name apex-sim-net --ip-range 10.0.0.0/16
hcloud network add-subnet apex-sim-net --network-zone eu-central --type cloud --ip-range 10.0.0.0/24

# Create servers
hcloud server create \
  --name apex-sim-api \
  --type cpx31 \
  --image ubuntu-22.04 \
  --ssh-key apex-sim-key \
  --network apex-sim-net \
  --location fsn1

hcloud server create \
  --name apex-sim-worker \
  --type cpx31 \
  --image ubuntu-22.04 \
  --ssh-key apex-sim-key \
  --network apex-sim-net \
  --location fsn1

hcloud server create \
  --name apex-sim-data \
  --type cpx31 \
  --image ubuntu-22.04 \
  --ssh-key apex-sim-key \
  --network apex-sim-net \
  --location fsn1

# Note: Use EX44 types for closer CPU characteristics to production
# cpx31 is sufficient for simulation logic correctness testing
```

### 6.2 Server Type Reference

| Type | vCPU | RAM | Disk | Use Case |
|------|------|-----|------|----------|
| cpx31 | 4 | 8 GB | 160 GB | Standard simulation |
| cpx41 | 8 | 16 GB | 240 GB | Heavy load testing |
| EX44 | 8 | 64 GB | 2x 512 GB | Production-like |

---

## 7. AWS SES Plumbing

### 7.1 Create Configuration Set

```bash
aws sesv2 create-configuration-set \
  --configuration-set-name apexmail-staging-sim \
  --delivery-options TlsPolicy=REQUIRE \
  --reputation-options ReputationMetricsEnabled=true \
  --sending-options SendingEnabled=true
```

### 7.2 Create SNS Topic + SQS Queue

```bash
# Create SNS topic
TOPIC_ARN=$(aws sns create-topic --name apexmail-staging-sim-events --query 'TopicArn' --output text)

# Create SQS queue
QUEUE_URL=$(aws sqs create-queue --queue-name apexmail-staging-sim-events --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)

# Subscribe SQS to SNS
aws sns subscribe \
  --topic-arn "$TOPIC_ARN" \
  --protocol sqs \
  --notification-endpoint "$QUEUE_ARN"

# Set SQS policy to allow SNS
aws sqs set-queue-attributes \
  --queue-url "$QUEUE_URL" \
  --attributes '{
    "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"sqs:SendMessage\",\"Resource\":\"'$QUEUE_ARN'\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"'$TOPIC_ARN'\"}}}]}"
  }'
```

### 7.3 Create Event Destination

```bash
aws sesv2 create-configuration-set-event-destination \
  --configuration-set-name apexmail-staging-sim \
  --event-destination-name sns-events \
  --event-destination '{
    "Enabled": true,
    "MatchingEventTypes": ["SEND","DELIVERY","BOUNCE","COMPLAINT","REJECT","FAILURE"],
    "SnsDestination": {"TopicArn": "'$TOPIC_ARN'"}
  }'
```

### 7.4 Hard Safety Rail: Recipient Allowlist

> **⚠️ CRITICAL:** In staging-sim, enforce a recipient allowlist in code. If recipient domain is not allowlisted, **reject before SES**. This guarantees no accidental real-world sends.

```typescript
// In worker/src/sender.ts
const RECIPIENT_ALLOWLIST = process.env.RECIPIENT_ALLOWLIST?.split(',') ?? [];

function isAllowedRecipient(email: string): boolean {
  if (RECIPIENT_ALLOWLIST.length === 0) {
    throw new Error('RECIPIENT_ALLOWLIST not configured - refusing to send');
  }
  return RECIPIENT_ALLOWLIST.some(pattern => email.endsWith(pattern));
}

// Before sending
if (!isAllowedRecipient(message.to)) {
  throw new RecipientNotAllowedError(`Recipient ${message.to} not in allowlist`);
}
```

---

## 8. Stripe Billing Simulation

### 8.1 Stripe Webhook Feed (CLI)

Run on API server to forward Stripe events to webhook handler:

```bash
# Start webhook forwarding
stripe listen --forward-to http://127.0.0.1:3000/webhooks/stripe

# The webhook handler MUST verify the signing secret emitted by stripe listen
# STRIPE_WEBHOOK_SECRET will be printed when stripe listen starts
```

### 8.2 Trigger Realistic Billing Events

```bash
# Standard lifecycle events
stripe trigger customer.subscription.created
stripe trigger invoice.payment_succeeded
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.deleted

# Trial-to-active conversion
stripe trigger customer.subscription.trial_will_end
stripe trigger invoice.paid

# Upgrade/downgrade scenarios (via API)
stripe subscriptions update sub_xxx --price price_premium
stripe subscriptions update sub_xxx --price price_basic

# Past due + recovery
stripe trigger invoice.payment_failed
stripe trigger invoice.payment_action_required
stripe trigger invoice.paid

# Dispute scenario
stripe trigger charge.dispute.created
```

### 8.3 Automated Billing Churn Script

```bash
# Run billing churn simulation
./ops/sim/stripe/trigger-scenarios.sh --scenario full-lifecycle --tenants 100

# Scenarios:
# - trial-to-active: Trial → Active subscription
# - upgrade-downgrade: Plan changes
# - payment-failure: Payment failures + recovery
# - cancellation: Subscription cancellation
# - full-lifecycle: All of the above
```

---

## 9. Deployment

### 9.1 Deployment Script

`./ops/sim/apexsim deploy` performs:

1. rsync/scp compose files to all servers
2. Start services
3. Run migrations
4. Health-check every service before proceeding

```bash
# Deploy to all servers
ssh apex-sim-data "docker compose up -d && docker compose exec postgres pg_isready"
ssh apex-sim-api "docker compose up -d && ./bin/migrate && ./bin/healthcheck"
ssh apex-sim-worker "docker compose up -d && ./bin/healthcheck"
```

### 9.2 Health Check Requirements

**Hard rule:** If any healthcheck fails → abort deployment.

```bash
# Health check endpoints
curl -sf http://apex-sim-api:3000/health || exit 1
curl -sf http://apex-sim-api:4000/health || exit 1
curl -sf http://apex-sim-worker:8080/health || exit 1

# Database connectivity
PGPASSWORD=$DB_PASSWORD psql -h apex-sim-data -U apexmail -d apexmail -c "SELECT 1" || exit 1

# Redis connectivity
redis-cli -h apex-sim-data -a "$REDIS_PASSWORD" ping || exit 1

# Queue health
curl -sf http://apex-sim-worker:8080/queues/health || exit 1
```

---

## 10. Load Testing

### 10.1 k6 Load Scenarios

The workload generator simulates:

- Multi-tenant distribution (many small tenants + few heavy)
- Bursts and retry storms
- Mixed endpoints: send, batch, scheduled, templates, contacts
- Webhook registration and failures
- Plan limit crossings (emails & API calls)

### 10.2 Tenant Distribution

```javascript
// load/realistic.js
const TENANT_DISTRIBUTION = {
  heavy: { count: 10, sendRate: 1000 },      // 10 heavy tenants
  medium: { count: 100, sendRate: 100 },     // 100 medium tenants
  light: { count: 1890, sendRate: 10 },      // 1890 light tenants
};
```

### 10.3 SES Reality Simulation

Simulate:
- **Throttles:** Exceed send rate briefly → ensure backoff
- **Delayed events:** Hold SQS visibility / delay processing
- **Duplicates/out-of-order events:** Inject synthetically

```bash
# Run load test
./ops/sim/apexsim load --duration 60m --profile realistic

# With SES chaos
./ops/sim/apexsim load --duration 60m --profile realistic --ses-chaos
```

---

## 11. Chaos Engineering

### 11.1 Toxiproxy Setup

```bash
# On data server
docker run -d --name toxiproxy \
  -p 8474:8474 \
  -p 5433:5433 \
  -p 6380:6380 \
  ghcr.io/shopify/toxiproxy

# Create proxies
toxiproxy-cli create postgres -l 0.0.0.0:5433 -u localhost:5432
toxiproxy-cli create redis -l 0.0.0.0:6380 -u localhost:6379
```

### 11.2 Network Chaos

```bash
# Cut outbound to SES for 5 minutes (worker node)
ssh apex-sim-worker "iptables -A OUTPUT -d email.eu-west-1.amazonaws.com -j DROP"
sleep 300
ssh apex-sim-worker "iptables -D OUTPUT -d email.eu-west-1.amazonaws.com -j DROP"

# Add latency to webhook dispatcher
toxiproxy-cli toxic add -t latency -a latency=500 -a jitter=200 postgres

# Drop DB connections intermittently
toxiproxy-cli toxic add -t reset_peer -a timeout=5000 postgres
```

### 11.3 Process Chaos

```bash
# Kill worker mid-flight
ssh apex-sim-worker "docker kill apexmail-worker"

# Restart postgres
ssh apex-sim-data "systemctl restart postgresql"

# Restart redis
ssh apex-sim-data "systemctl restart redis"

# Rolling deployment during load
./ops/sim/apexsim deploy --rolling
```

### 11.4 Chaos Profiles

```yaml
# chaos/profiles/medium.yaml
seed: 12345
experiments:
  - name: database-latency
    target: postgres
    toxic: latency
    params:
      latency: 100
      jitter: 50
    duration: 5m
    
  - name: ses-outage
    target: ses
    action: block
    duration: 2m
    
  - name: worker-crash
    target: worker
    action: kill
    recovery: auto
    
  - name: redis-reset
    target: redis
    toxic: reset_peer
    params:
      timeout: 1000
    probability: 0.01
```

### 11.5 Reproducible Chaos

```bash
# Run seeded chaos for reproducibility
./ops/sim/apexsim chaos --seed 123 --profile harsh

# Same seed = same sequence of failures
```

---

## 12. Reports & Verification

### 12.1 Report Bundle Contents

```
reports/2026-02-22T14:30:00Z/
├── summary.json              # Pass/fail + key metrics
├── invariant-checks.json     # All invariant check results
├── ledger-snapshot/
│   ├── messages.csv          # Message ledger snapshot
│   ├── events.csv            # Event log snapshot
│   └── billing.csv           # Billing ledger snapshot
├── metrics/
│   ├── prometheus-dump.tar   # Prometheus TSDB snapshot
│   └── latency-histograms/   # p50/p95/p99 distributions
├── logs/
│   ├── api.log
│   ├── worker.log
│   └── assertion-daemon.log
├── chaos/
│   ├── timeline.json         # What chaos was injected when
│   └── recovery-times.json   # Time to recover from each failure
└── stripe/
    ├── events-received.json  # All Stripe events received
    └── reconciliation.json   # Internal vs Stripe state diff
```

### 12.2 Verification Queries

```sql
-- Ledger reconciliation
SELECT 
  'messages' as table_name,
  COUNT(*) as total,
  COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
  COUNT(*) FILTER (WHERE status = 'bounced') as bounced,
  COUNT(*) FILTER (WHERE status = 'failed') as failed,
  COUNT(*) FILTER (WHERE status NOT IN ('delivered', 'bounced', 'failed', 'rejected')) as pending
FROM messages
WHERE created_at > NOW() - INTERVAL '24 hours';

-- Billing reconciliation
SELECT 
  t.id as tenant_id,
  t.stripe_customer_id,
  t.subscription_status,
  COUNT(m.id) as internal_sends,
  t.stripe_usage_reported as stripe_usage,
  t.plan_limit,
  CASE 
    WHEN COUNT(m.id) > t.plan_limit THEN 'OVERAGE'
    ELSE 'OK'
  END as limit_status
FROM tenants t
LEFT JOIN messages m ON m.tenant_id = t.id
  AND m.created_at > DATE_TRUNC('month', NOW())
GROUP BY t.id;
```

---

## 13. Pass/Fail Criteria

### 13.1 Production Ready Checklist

A run is **PASS** only if ALL of the following are true:

| Criterion | Threshold | Check |
|-----------|-----------|-------|
| **Ledger violations** | 0 | No message, event, or billing ledger inconsistencies |
| **Backlog growth** | Bounded | Queue depth never exceeds 2x normal |
| **P95 latency** | < target | Under SLO during target load |
| **Chaos recovery** | Automatic | No manual intervention required |
| **Stripe webhook replay** | Idempotent | No duplicate entitlement transitions |
| **SES throttle handling** | Backoff | No retry storms (retry rate < 10% of sends) |
| **Retention/cleanup jobs** | Stable | No impact on system stability |

### 13.2 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | PASS - All criteria met |
| 1 | FAIL - Invariant breach |
| 2 | FAIL - Backlog runaway |
| 3 | FAIL - Latency SLO breach |
| 4 | FAIL - Chaos recovery failure |
| 5 | FAIL - Billing reconciliation error |
| 10 | ERROR - Infrastructure failure |
| 11 | ERROR - Configuration error |

### 13.3 Example Run Output

```
================================================================================
APEXMAIL SIMULATION RUN COMPLETE
================================================================================

Duration: 6h 0m 23s
Tenants: 2000
Messages Sent: 1,247,832
Load Profile: realistic
Chaos Profile: medium

INVARIANT CHECKS:
  ✓ A1: No duplicate sends
  ✓ A2: No stuck messages
  ✓ A3: No cross-tenant events
  ✓ A4: All accepted → terminal
  ✓ A5: No suppression bypass
  ✓ B1: No unauthorized sends
  ✓ B2: No false rejections
  ✓ B3: Usage drift < 0.01%
  ✓ B4: Stripe replay idempotent
  ✓ C1: Queue age < threshold
  ✓ C2: No worker crash loops
  ✓ C3: DB pool healthy
  ✓ C4: SES backoff working
  ✓ C5: Webhook retries bounded

PERFORMANCE:
  P50 latency: 45ms
  P95 latency: 120ms
  P99 latency: 280ms
  Max queue depth: 1,247
  Delivered rate: 99.7%

CHAOS RECOVERY:
  ✓ SES outage (2m): recovered in 47s
  ✓ Worker crash: recovered in 12s
  ✓ DB latency spike: no impact
  ✓ Redis reset: recovered in 3s

BILLING:
  ✓ Usage aligned: 0 drift
  ✓ Overage metered: 47 tenants
  ✓ Entitlements: 2000/2000 consistent

RESULT: ✅ PASS

Report bundle: reports/2026-02-22T14:30:00Z/
================================================================================
```

---

## Related Documentation

- [Quick Start Guide](quickstart.md)
- [Docker Configuration](docker.md)
- [Disaster Recovery](../operations/disaster-recovery.md)
- [SLO Management](../operations/slo-management.md)
- [Monitoring Setup](../operations/monitoring.md)
