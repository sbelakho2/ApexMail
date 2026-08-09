+++
title = "High-Volume Sending Solution"
description = "Millions of transactional emails per month. Managed dedicated IPs, automated warm-up, queue prioritization, batch APIs, and contractual SLAs."
template = "prose.html"
+++

## High-Volume Sending

Send millions of transactional emails per month with predictable throughput, dedicated IP reputation, automated warm-up, and contractual availability guarantees.

## Audience

Large SaaS platforms sending >1M emails/month. E-commerce platforms sending order confirmations at scale. Social networks sending notification digests. IoT platforms sending device alerts. Any organization where email throughput directly affects customer experience and revenue.

## Business Context

At high volume, small deliverability changes have large revenue impact. A 1% delivery degradation on 10M emails/month means 100,000 missed messages. Queue backpressure during recipient-provider throttling must not cascade into application latency. IP reputation management becomes a full-time concern without automation.

## Core Problem

- Shared IP pools accumulate reputation risk from other senders.
- Queue backpressure during provider throttling affects all streams if not isolated.
- Manual IP warm-up is error-prone and slow.
- Rate limits on standard plans cap throughput below business requirements.
- Without dedicated infrastructure, peak traffic competes with other customers.

## ApexMail Solution

- **Dedicated IPs** — 1 managed dedicated IP on Growth, 1 on Business, up to 3 on Enterprise, 2 on Dedicated Tenant. IP eligibility review for all plans.
- **Automated Warm-Up** — Gradual volume ramp following provider-specific schedules. Monitored for reputation signals. Manual override available.
- **Queue Prioritization** — Per-stream priority configuration. Transactional streams processed ahead of broadcast. Time-to-inbox targets monitored.
- **Batch API** (`POST /v1/emails/batch`) — Submit up to 1,000 emails per request. Lower per-message overhead than individual API calls.
- **Rate Limits** — Up to 10,000 req/min on Enterprise. Dedicated and BYOC plans support negotiated limits.
- **Contractual SLA** — 99.9% API availability on Enterprise. Enhanced SLA on Dedicated Tenant and BYOC.

## Technical Implementation

1. Request dedicated IP eligibility review from support or sales.
2. Once approved, dedicated IPs are provisioned and assigned to your account.
3. Automated warm-up begins. Monitor warm-up progress in dashboard.
4. Assign dedicated IPs to transactional streams for reputation isolation.
5. Configure per-stream queue priority and concurrency limits.
6. Use batch API for high-throughput sending scenarios.
7. Monitor delivery latency, queue depth, and provider-specific acceptance rates.

## Relevant API Endpoints

| Endpoint | Description |
|---|---|
| `POST /v1/emails` | Send individual email |
| `POST /v1/emails/batch` | Send up to 1,000 emails in one request |
| `GET /v1/dedicated-ips` | List dedicated IPs and warm-up status |
| `GET /v1/streams/:id/stats` | Per-stream throughput and latency metrics |
| `GET /v1/analytics/delivery` | Aggregate delivery metrics by provider |

## Required Plan

| Plan | Monthly Volume | Dedicated IPs | Rate Limit | Support |
|---|---|---|---|---|
| Growth | 500,000 emails | 1 (review) | 3,000 req/min | 8 business hours |
| Business | 2,000,000 emails | 1 (review) | 3,000 req/min | 4 business hours |
| Enterprise | 5,000,000+ emails | Up to 3 | 10,000 req/min | Negotiated |
| Dedicated Tenant | 5,000,000+ baseline | 2 included | Negotiated | Enhanced SLA |
| BYOC | Negotiated | Customer-managed | Negotiated | Operational support |

## Security Considerations

- Dedicated IP reputation is managed exclusively for your account. Changes require account owner approval.
- Batch API requests are atomic: all messages in a batch succeed or fail together (no partial completion).
- Queue depth and processing latency are visible in real time via dashboard and API.
- Rate limit headers returned on every response. Monitor `X-RateLimit-Remaining` to avoid throttling.

## Known Limitations

- Dedicated IP eligibility requires a sending history review. New accounts start on shared IPs.
- IP warm-up typically takes 2-4 weeks depending on target volume and provider policies.
- Maximum batch size is 1,000 emails per request. Larger volumes require multiple batch calls.
- Throughput during provider outages depends on queue retry configuration and provider recovery time.

## Recommended Next Action

[Contact sales](/contact/sales/) for a volume assessment, dedicated IP evaluation, and dedicated tenancy pricing.
