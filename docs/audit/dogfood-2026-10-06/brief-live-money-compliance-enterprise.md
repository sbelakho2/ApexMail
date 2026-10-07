# LIVE dogfood — money, compliance, enterprise (RUN the product)

You are dogfooding the RUNNING ApexMail stack, adversarially. Working dir:
/Users/sabelakhoua/IdeaProjects/ApexMail. Stack is up. Surfaces: 127.0.0.1:8080 with a Host header
(app.apexmail.ee customer console, admin.apexmail.ee control plane, apexmail.ee marketing) plus
separate services: billing-service, compliance (container apexmail-compliance-1), enterprise
(apexmail-enterprise-1, host port 3002), Mailpit at :8025, Postgres 127.0.0.1:5432
(apexmail/apexmail/bebc8cefdc096e5247f8864e5c0edf78099df23058133321), Redis 6379 (password in .env).

## Your job: exercise the money/compliance/enterprise planes end to end
1. **Billing**: read the canonical plans (crates/platform-catalog) and then prove the LIVE stack
   agrees: GET the public plans/limits endpoints, the tenant's plan/usage/entitlements, POST a usage
   event, hit a quota boundary (Free 3,000/mo) and show the honest refusal + the metering rows.
   Invoices/credit notes: create and fetch one through the API or the service; check the ledger rows
   the code claims (accounting-postings / ledger tables) exist and balance.
2. **PAYG + overage**: push usage past an included volume and verify the overage/PAYG math matches
   the catalog values (80/60/35 millicents; PAYG tiers 0.0010/0.0008/0.0005/0.0003) — quote the
   rows you read.
3. **Compliance**: run a GDPR/DSR flow end to end (export + erasure) for a throwaway tenant, and
   verify the retention sweep and the ledger/audit rows the docs promise.
4. **Suppressions**: create a suppression, prove the send gate refuses that recipient, prove
   complaint/unsubscribe suppressions CANNOT be deleted (403) but a manual/temporary one can.
5. **Enterprise SSO**: walk the OIDC/SAML surfaces the container exposes (3002): configuration
   validation, a login initiation with an unreachable IdP (must fail honestly), and the
   SSO-must-not-bypass-MFA gate.
6. **VAT/accounting**: exercise whatever the running compliance container exposes that corresponds
   to `vat_recognition` / `accounting-export` (a CLI/endpoint/one-shot run); if it is not reachable
   in this stack, say BLOCKED with the exact reason instead of guessing.

## Rules
- RUN things; capture exact commands + observed output. Adversarially: cross-tenant probes against
  billing/usage ids, negative amounts, absurd quantities, replay of an idempotency key, quota
  boundaries (exactly at the limit, one over), and a foreign tenant's invoice id.
- Do NOT edit code. Report.
- Findings → docs/audit/dogfood-2026-10-06/dogfood-money-compliance.md with:
  ### <P0|P1|P2|P3> <file or endpoint> — <title>
  Ran: … Observed: … Expected: … Why it is a defect: … Suggested fix: …
- Ledger → docs/audit/dogfood-2026-10-06/ledger-money-compliance.md (RUN/PASS/FAIL/BLOCKED per flow).
