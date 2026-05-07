# Security Questionnaire Automation

ApexMail Enterprise can generate security-review answer packs for common buyer workflows without copying proprietary questionnaire text. The compliance service maps ApexMail-owned normalized questions to SIG, CAIQ, and HECVAT domains, then fills answers from live platform evidence.

## Evidence Sources

Generated packs are composed from:

- SOC 2 control catalog and evidence records
- Trust Portal documents, subprocessors, incidents, and access-request workflows
- HIPAA BAA tenant state and BAA lifecycle events
- GDPR DSR and consent workflows
- Audit logging and operational control mappings

## Admin Endpoints

All endpoints are authenticated with the compliance service Bearer token.

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/admin/trust/questionnaires/frameworks` | List supported frameworks and output formats |
| `POST /v1/admin/trust/questionnaires/sig/generate` | Generate a SIG-mapped answer pack |
| `POST /v1/admin/trust/questionnaires/caiq/generate` | Generate a CAIQ-mapped answer pack |
| `POST /v1/admin/trust/questionnaires/hecvat/generate` | Generate a HECVAT-mapped answer pack |
| `POST /v1/admin/trust/security-review-report` | Generate a combined security-review report across SIG, CAIQ, and HECVAT |

## Request Shape

```json
{
  "tenant_id": "tenant_123",
  "requester_company": "Example Customer",
  "include_private_documents": true,
  "include_markdown_report": true
}
```

`tenant_id` is optional, but tenant-specific HIPAA answers require it. If no active BAA exists for the tenant, HIPAA answers are marked `needs_review` instead of being presented as active.

## Output Contract

Each generated questionnaire includes:

- `questionnaire_hash`: SHA-256 hash of the generated pack
- `completion`: automated, review-required, and source-count summary
- `answers`: normalized questions, generated answers, owner, confidence, status, mapped SOC 2 controls, and evidence references
- `evidence_manifest`: deduplicated Trust Portal and SOC 2 evidence references
- `report_md`: markdown report for customer or auditor review when requested

The combined security-review report returns all three framework packs and a report-level SHA-256 hash.