+++
title = "Operational Reliability"
description = "How ApexMail monitors the platform, measures availability, classifies incidents, and communicates maintenance and postmortems."
template = "prose.html"
weight = 5
+++

This page describes how the ApexMail platform is monitored and how we communicate about reliability. It deliberately does not publish internal alert rules or remediation runbooks — those live in the internal operations repository.

## Monitoring approach

- **Synthetic probes** hit the public API, SMTP, dashboard, and webhook pipeline from external regions every 60 seconds.
- **Server-side metrics** (request latency, queue depth, delivery latency, webhook delivery health) are collected per service and drive internal alerting.
- **Real-traffic signals** — error rates, bounce storms, deferral spikes — are monitored alongside synthetic checks so a passing probe never masks a customer-visible problem.

Live status: [status.apexmail.ee](https://status.apexmail.ee).

## Status methodology

- Each component (API, SMTP, webhooks, dashboard) reports Operational / Degraded / Outage based on probe success and latency thresholds.
- Availability percentages are calculated per calendar month from probe data and published on the status page history.
- Incident states are updated manually by the on-call operator; automated probe data alone never silently resolves an incident.

## Incident severity

| Severity | Definition | Communication |
|----------|------------|---------------|
| SEV-1 | Platform-wide outage or data-integrity risk | Status page incident + email to affected tenants |
| SEV-2 | Degraded service for a component or a tenant subset | Status page incident |
| SEV-3 | Minor degradation, workaround exists | Status page note |

## Maintenance policy

- Maintenance windows are announced on the status page at least 48 hours in advance.
- Zero-downtime deploys (rolling container replacement) are the default; customer-visible maintenance is exceptional.
- Emergency security fixes may bypass the announcement window and are documented post-hoc.

## Postmortem policy

Every SEV-1 incident receives a written postmortem within five business days: timeline, root cause, blast radius, and preventive actions. Postmortems are available to affected tenants on request.

## External monitoring regions

Probes run from at least two independent regions outside the primary data center so that a local network event cannot mask a real outage.
