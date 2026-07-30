# Private Cloud Engagement Process

> Last updated: 2026-07-29

## Overview

The Private Cloud engagement process takes a prospective customer from initial interest to a fully operational dedicated or BYOC deployment. Each stage has defined owners, inputs, deliverables, and exit criteria.

---

## Stage 1: Qualification

| Attribute | Detail |
|-----------|--------|
| Owner | Sales |
| Customer inputs | Monthly volume, peak volume, compliance requirements, deployment preference, timeline |
| ApexMail deliverables | Qualification assessment, preliminary fit evaluation |
| Dependencies | None |
| Estimated duration | 1–3 business days |
| Approval required | Internal sales review |
| Exit criteria | Customer meets Private Cloud eligibility criteria; mutual interest confirmed |

---

## Stage 2: Requirements Collection

| Attribute | Detail |
|-----------|--------|
| Owner | Solutions Engineering |
| Customer inputs | Technical requirements document, security policy, compliance framework, data residency requirements, integration points, volume projections |
| ApexMail deliverables | Requirements summary, gap analysis |
| Dependencies | Stage 1 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Customer sign-off on requirements document |
| Exit criteria | All technical, security, and compliance requirements documented |

---

## Stage 3: Security Workshop

| Attribute | Detail |
|-----------|--------|
| Owner | Security Engineering |
| Customer inputs | Security questionnaire, penetration test requirements, access control policy, encryption requirements |
| ApexMail deliverables | Security architecture overview, shared responsibility model, security controls documentation |
| Dependencies | Stage 2 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Customer security team sign-off |
| Exit criteria | Security requirements aligned; residual risks documented |

---

## Stage 4: Architecture Design

| Attribute | Detail |
|-----------|--------|
| Owner | Solutions Engineering |
| Customer inputs | Cloud provider preference, networking requirements, scaling projections, monitoring requirements, backup policy |
| ApexMail deliverables | Reference architecture diagram, deployment topology, network design, data flow diagram |
| Dependencies | Stage 3 complete |
| Estimated duration | 2–4 weeks |
| Approval required | Customer architecture review board sign-off |
| Exit criteria | Architecture design approved; deployment topology finalized |

---

## Stage 5: Data Residency Review

| Attribute | Detail |
|-----------|--------|
| Owner | Compliance |
| Customer inputs | Data classification policy, residency requirements, cross-border transfer restrictions, retention policy |
| ApexMail deliverables | Data flow documentation, data residency confirmation, DPA terms |
| Dependencies | Stage 4 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Customer DPO or legal sign-off |
| Exit criteria | Data residency requirements confirmed; DPA ready for execution |

---

## Stage 6: Commercial Proposal

| Attribute | Detail |
|-----------|--------|
| Owner | Sales |
| Customer inputs | Budget approval, procurement timeline |
| ApexMail deliverables | Commercial proposal: pricing, SLA, support terms, contract terms |
| Dependencies | Stages 3–5 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Customer procurement |
| Exit criteria | Proposal accepted; ready for contract |

---

## Stage 7: Contract and DPA

| Attribute | Detail |
|-----------|--------|
| Owner | Legal |
| Customer inputs | Legal review, redlines, procurement process |
| ApexMail deliverables | Master Services Agreement, DPA, SLA, Support Policy, Subprocessor List |
| Dependencies | Stage 6 complete |
| Estimated duration | 2–6 weeks |
| Approval required | Both parties' legal sign-off |
| Exit criteria | Contract executed; DPA signed |

---

## Stage 8: Environment Provisioning

| Attribute | Detail |
|-----------|--------|
| Owner | Infrastructure Engineering |
| Customer inputs | Cloud account setup (BYOC), network configuration, access credentials |
| ApexMail deliverables | Provisioned environment, connectivity confirmed, initial configuration |
| Dependencies | Stage 7 complete |
| Estimated duration | 1–4 weeks (varies by deployment model) |
| Approval required | Technical acceptance by customer |
| Exit criteria | Environment accessible; health checks passing |

---

## Stage 9: Deployment

| Attribute | Detail |
|-----------|--------|
| Owner | Infrastructure Engineering |
| Customer inputs | DNS records, sending domain configuration |
| ApexMail deliverables | Deployed application, configured services, verified connectivity |
| Dependencies | Stage 8 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Deployment verification |
| Exit criteria | All services running; smoke tests passing |

---

## Stage 10: Integration

| Attribute | Detail |
|-----------|--------|
| Owner | Solutions Engineering |
| Customer inputs | Integration code, API credentials, webhook endpoints |
| ApexMail deliverables | Integration guidance, SDK setup, test send verification |
| Dependencies | Stage 9 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Customer development team sign-off |
| Exit criteria | Test sends successful; webhooks receiving events |

---

## Stage 11: Security Validation

| Attribute | Detail |
|-----------|--------|
| Owner | Security Engineering |
| Customer inputs | Penetration test authorization, security scan scope |
| ApexMail deliverables | Security validation report, penetration test coordination |
| Dependencies | Stage 10 complete |
| Estimated duration | 2–4 weeks |
| Approval required | Security sign-off from both parties |
| Exit criteria | Security validation complete; findings addressed |

---

## Stage 12: Performance Testing

| Attribute | Detail |
|-----------|--------|
| Owner | Infrastructure Engineering |
| Customer inputs | Expected peak volumes, throughput requirements |
| ApexMail deliverables | Performance test report, capacity confirmation |
| Dependencies | Stage 11 complete |
| Estimated duration | 1–2 weeks |
| Approval required | Performance acceptance |
| Exit criteria | Performance meets or exceeds requirements |

---

## Stage 13: Migration

| Attribute | Detail |
|-----------|--------|
| Owner | Solutions Engineering |
| Customer inputs | Migration plan, existing provider credentials, domain/IP transition schedule |
| ApexMail deliverables | Migration support, IP warmup, deliverability monitoring |
| Dependencies | Stage 12 complete |
| Estimated duration | 2–8 weeks (varies by volume and complexity) |
| Approval required | Migration cutover sign-off |
| Exit criteria | All sending migrated; legacy provider decommissioned |

---

## Stage 14: Go-Live

| Attribute | Detail |
|-----------|--------|
| Owner | Customer with ApexMail support |
| Customer inputs | Go-live authorization, monitoring escalation contacts |
| ApexMail deliverables | Go-live support, enhanced monitoring, escalation readiness |
| Dependencies | Stage 13 complete |
| Estimated duration | 1 day (event); 1 week (hypercare) |
| Approval required | Go-live sign-off |
| Exit criteria | Production traffic flowing; no critical issues |

---

## Stage 15: Stabilization

| Attribute | Detail |
|-----------|--------|
| Owner | Support Engineering |
| Customer inputs | Performance feedback, issue reports |
| ApexMail deliverables | Issue resolution, configuration tuning, performance optimization |
| Dependencies | Stage 14 complete |
| Estimated duration | 2–4 weeks |
| Approval required | Stabilization review |
| Exit criteria | System stable; performance within SLA; no open critical issues |

---

## Stage 16: Ongoing Operations

| Attribute | Detail |
|-----------|--------|
| Owner | Customer with ApexMail operations support |
| Customer inputs | Usage monitoring, capacity planning, change requests |
| ApexMail deliverables | Monitoring, upgrades, patching, support, periodic reviews |
| Dependencies | Stage 15 complete |
| Estimated duration | Ongoing |
| Approval required | Periodic service reviews |
| Exit criteria | Renewal or termination per contract terms |
