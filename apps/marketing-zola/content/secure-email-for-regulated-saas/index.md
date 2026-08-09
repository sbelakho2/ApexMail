+++
title = "Secure Email for Regulated SaaS"
template = "prose.html"
description = "ApexMail combines email delivery with SOC 2 control evidence, HIPAA BAA lifecycle tooling, Trust Portal workflows, and automated SIG, CAIQ, and HECVAT answer packs for regulated SaaS teams."

[extra]
og_image = "/images/og-image.svg"
+++

## The Email Stack Built for Your Security Review

Regulated SaaS buyers need more than a fast send API. They need audit logs,
data subject workflows, clear access controls, and a vendor team that can answer
security questionnaires without hand-waving.

ApexMail now generates security-review evidence directly from the platform:
SOC 2 control mappings, HIPAA BAA state, GDPR workflows, Trust Portal artifacts,
subprocessor records, incident history, and SIG, CAIQ, and HECVAT answer packs.

<div class="grid grid-cols-1 md:grid-cols-3 gap-6 my-12">
  <div class="bg-surface-900 border border-surface-800 rounded-sm p-6">
    <h3 class="text-xl font-semibold mb-3">SOC 2 Evidence — In Product</h3>
    <p>Control catalog and evidence workflows for access reviews, change logs, audit events, privacy controls, availability, confidentiality, and operational review.</p>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-sm p-6">
    <h3 class="text-xl font-semibold mb-3">HIPAA BAA Lifecycle</h3>
    <p>Enterprise BAA request, signing, countersigning, activation, termination, and hash-chained audit events are modeled as first-class workflows for regulated implementation review.</p>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-sm p-6">
    <h3 class="text-xl font-semibold mb-3">Questionnaire Automation</h3>
    <p>Authenticated Trust Portal routes generate SIG, CAIQ, and HECVAT answer packs plus a one-click security-review report with stable SHA-256 hashes and evidence manifests.</p>
  </div>
</div>

## What "Compliance-Native" Actually Means

ApexMail is the email platform and the compliance evidence engine around that
platform. The questionnaire generator pulls from live product sources instead of
static sales copy: SOC 2 controls, Trust Portal documents, subprocessors,
incident records, HIPAA BAA state, GDPR DSR workflows, and consent records.

| Capability                         | Generic ESP        | ApexMail                    |
|------------------------------------|--------------------|-----------------------------|
| SIG answer pack                    | Manual spreadsheet | Generated from controls     |
| CAIQ answer pack                   | Manual spreadsheet | Generated from controls     |
| HECVAT answer pack                 | Manual spreadsheet | Generated from controls     |
| SOC 2 evidence support             | Static documents   | Control/evidence workflow   |
| HIPAA BAA lifecycle                | Email thread       | Signed workflow + audit log |
| Customer security report           | Sales request      | One-click hashed report     |
| Trust Portal evidence              | Status page only   | Docs, incidents, processors |

## Built for the Security Questionnaire

The compliance service exposes authenticated admin routes for security review
automation:

- `GET /v1/admin/trust/questionnaires/frameworks`
- `POST /v1/admin/trust/questionnaires/sig/generate`
- `POST /v1/admin/trust/questionnaires/caiq/generate`
- `POST /v1/admin/trust/questionnaires/hecvat/generate`
- `POST /v1/admin/trust/security-review-report`

Each generated pack includes normalized questions, answers, answer status,
confidence, owner, SOC 2 control mappings, Trust Portal evidence references,
and a stable hash for audit trails.

- **Encryption:** TLS in transit and encrypted storage controls
- **Access control:** SSO/SAML, SCIM, API keys, IP allowlisting, and RBAC on higher tiers
- **Audit logs:** API, configuration, and admin events with export workflows
- **Data rights:** DSR lifecycle for access, erasure, portability, restriction, and objection
- **Security questionnaires:** SIG, CAIQ, and HECVAT packs generated from live evidence sources
- **Regulated launch:** Enterprise implementation review for HIPAA, residency, and custom deployment needs

## Talk to Us

If your sales cycle ends with a security review, ApexMail can give your team a
complete evidence story around email delivery. [Request a Trust Portal preview](/contact/).
