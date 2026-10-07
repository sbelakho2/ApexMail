# Fix Report — docs, protocol, root data, legal templates

> Executor: FIX agent (docs slice)
> Date: 2026-10-07
> Brief: `docs/audit/dogfood-2026-10-06/brief-fix-docs.md`
> Review: `docs/audit/dogfood-2026-10-06/review-docs-protocol-data.md`
> Contract: every claim in the touched artifacts was checked against the
> shipped code/config at working-tree state 2026-10-07.

## Verdict summary

P1: 9/9 resolved (one with a documented deletion decision instead of a content
reconciliation). P2/P3: 21 items fixed in owned paths; 2 items are outside the
owned paths (root `README.md`, `apps/ai/**`) and are named below for their
owners. P0: investigate-only table with implementation order delivered (no
service edits, no change to `docs/pricing.md:44-46`).

## P1-1 — Stale price ladder in the Stripe contract and the billing-lifecycle doc

FIXED.

- `docs/tool-contracts/stripe.md`: the price table now carries the canonical
  ladder with plan IDs (Free / Developer `starter` €29 / Pro €89 / Growth €229
  / Business `scale` €699 / Enterprise Cloud €1,750; annual 10×; Free launch
  allowance noted). The Checkout paragraph now names the real self-service IDs
  (`starter`, `pro`, `growth`, `scale`).
- `docs/architecture/billing-lifecycle.md`: the plan table now names
  `platform-catalog` as the fact source and carries the canonical cents
  (2,900 / 8,900 / 22,900 / 69,900 / 175,000; Free 3,000 + one-time 30,000
  launch allowance) plus canonical display names.
- Pinned: `tools/check_knowledge_consistency.py` grew
  `parse_stripe_contract_plans()`, `parse_billing_lifecycle_plans()` and
  `check_doc_plan_tables_match_catalog()`; both docs are now in the gate's
  source set and its `--self-test` (two new mutation cases, both PASS).
- Evidence: `python3 tools/check_knowledge_consistency.py` →
  `PASS knowledge-consistency`; `--self-test` → all PASS.

## P1-2 — Pricing reference dedicated-IP counts and price

FIXED.

- Runtime truth found at `api-server/src/routes/explorer.rs` (
  `4_900 + (n-1) * 6_900`, i.e. €49 first / €69 each additional).
- `docs/pricing.md`: Business row is `1 included`, Enterprise Cloud row
  `3 included`; the dedicated-IP section now quotes “€49/month (first) and
  €69/month (each additional) on Pro and above”; the self-service path names
  Developer/Business.
- `docs/marketing/pricing.md`: dedicated-IP table corrected to the same
  ladder (`Scale`/`Enterprise` rows renamed to Business/Enterprise Cloud).
- `docs/tool-contracts/ses.md`: plan allocation table corrected to Business 1 /
  Enterprise Cloud up to 3, and the `$30/mo` USD price replaced with the EUR
  ladder (also fixes the USD-in-EUR-doc finding).
- Pinned: `tools/validate_pricing_drift.py` now derives the add-on pair from
  `routes/explorer.rs` (`extract_dedicated_ip_addon`) and requires the same
  sentence in `docs/pricing.md` and the calculator; it also checks the
  dedicated-IP cell of every `docs/pricing.md` catalog row
  (`dedicated_ip_cell`). The contradictory `pricing.json ip_cost == 30`
  assertion is dropped (see residual below); `pricing drift validation passed`.
- Residual (not owned): `apps/marketing-zola/data/pricing.json` still carries
  the dead `"ip_cost": 30` field. No template reads it; it is now unpinned.
  The marketing owner should delete the field or set it to 49.

## P1-3 — Billing lifecycle plan catalog

FIXED — see P1-1 (same file + gate).

## P1-4 — SLA credit caps contradict the runtime

FIXED, with the decision stated.

- Runtime enforcer: `billing-service/src/maintenance.rs`
  (`sla_credit_percentage_for_breach` ladder, then
  `credit_amount.min(percent_of_cents_half_up(invoice, cap_percent))` where
  `cap_percent` comes from the plan features). Seed values:
  `plans.rs` Business (`scale`) 30, Enterprise Cloud (`enterprise`) 25.
- Decision: the docs/legal text is aligned to the **shipped 30%** for
  Business, because that is the cap the sweep enforces; the ladder in
  `templates/legal/sla.md`/`docs/sla.md` remains, capped per plan.
- `docs/sla.md`: §3.1 and §3.4 now say Business capped at 30%, Enterprise
  Cloud 25%; §2.3 and exclusion 6 use canonical names; throughput line uses
  Developer/Business/Enterprise Cloud.
- `templates/legal/sla.md`: applicability table, plan headings, credit caps
  and support table use Business/Enterprise Cloud; caps 30%/25%.
- Pinned: `tools/validate_pricing_drift.py`
  (`validate_sla_credit_docs`) parses `sla_credit_percentage` per seed and
  fails when either doc drifts or the retired 10% cap returns. Validator
  passes.

## P1-5 — Rebuilt `docs/deployment/configuration.md` from the real env contract

FIXED.

- The doc is regenerated from `.env.example` (170 vars), the compose
  `${VAR}`/`${VAR:?}` surface, and the guard list. Every `PROD_*_FILE` mount
  and every required variable is listed. Verified mechanically: 52 guard vars,
  0 missing from the doc; 337 documented variable names, all present in the
  contract (the only non-contract names are in an explicit “Removed variables”
  paragraph that states they are not read).
- The 49 phantom variables (incl. `OPENAI_API_KEY`, `SENTRY_DSN`,
  `ENCRYPTION_KEY`, `DATABASE_POOL_MAX`, `FEATURE_*`, `SLO_*`, `QUEUE_*`,
  `GDPR_ENABLED`, `CORS_ENABLED`) are gone; the doc now points at the real
  AI surface (`AI_MODEL_*`, `AI_ADMIN_TOKEN`, …) and the real K8s-free
  deployment model.
- Compose-only runtime variables read by the services are documented; the
  third-party stack variables are listed with the compose file as the source.

## P1-6 — Root `data/**` scratch corpus

Done with a documented decision (deletion), because faithful reconciliation
was not possible without shipping wrong arithmetic.

- Consumer trace (finished): `apps/ai/training/pipeline.sh:18`
  (`DATA_PATH="$PROJECT_ROOT/data/train.jsonl"`),
  `apps/ai/training/common_paths.py:25` (`DATA_DIR` defaults to repo-root
  `data/`), `tools/common_paths.py:5` (`DATA_DIR = PROJECT_ROOT / "data"`),
  and the tools that import it (`tools/fix_all_errors.py`,
  `tools/fix_all_training_limits.py`, `tools/fix_payg_calculations.py`,
  `tools/definitive_audit.py`).
- Reconciliation attempt: the pipeline's own canonicalizer
  (`apps/ai/training/validate_pricing.canonize_text`) was run over all 18
  JSONL files (dry-run then applied). It removed most retired-ladder tokens but
  left computed examples internally inconsistent (e.g. “Overage: 30,000 ÷
  1,000 × €0.40 = €12.00 … Total: €150 + €12 = €162.00”) because the totals and
  arithmetic embed the old ladder. Shipping that would violate the honesty
  contract more than removing untracked scratch data.
- Decision: the 18 JSONL files and the scratch `normalize_format.py` were
  removed. The directory’s own README declared this exact state (“the prior
  JSONL corpus … were removed”), the tree is gitignored (`.gitignore:168
  /data/`), and the apps/ai tooling already excludes root `data/` as “a retired,
  gitignored scratch directory … not swept”.
- Kept and repaired: `data/system_prompts.json` (the shared prompt catalog the
  tracked corpus references by `system_prompt_id`) — canonicalized against the
  platform catalog (1,349 replacements) and its digests regenerated. Its
  remaining stale numbers (Free 30k/300k, dedicated-IP counts, €30 add-on,
  SLA 10%) were reconciled to the shipped catalog (461 targeted replacements).
- `data/README.md` now describes the directory accurately (what remains, where
  the live corpus is), and `data/manifest.json` is updated (`updatedAt
  2026-10-07`, datasets empty by design).
- Acceptance: `grep -rn "€25\b\|€65\b\|€150\b\|€350\b\|€3,000\b" data/` → 0 hits.
- Follow-up for the apps/ai and tools owners: point the consumer paths above at
  `apps/ai/training/data/` (the single tracked, validated corpus).

## P1-7 — `data/system_prompts.json` digests and checksum

FIXED (content wins over the manifest).

- The content canonicalization in P1-6 ran first; every per-prompt `sha256`
  was then regenerated from the (new) content: 112/120 were recomputed on the
  first pass, and 0 mismatches remain after the second targeted pass.
- `data/system_prompts.json.sha256` was rewritten with a real newline
  (the writer bug in `apps/ai/training/sweep_currency_to_eur.py:214` remains
  for the apps/ai owner).
- Verification one-liner:

```bash
cd data && python3 -c "import hashlib,json;from pathlib import Path;d=json.loads(Path('system_prompts.json').read_text());print('mismatches',sum(1 for v in d['prompts'].values() if v['sha256']!=hashlib.sha256(v['content'].encode()).hexdigest()))" && shasum -a 256 -c system_prompts.json.sha256
# mismatches 0 / system_prompts.json: OK
```

## P1-8 — Emergency key-revocation runbook used a nonexistent endpoint

FIXED; capability gaps documented in place.

- Real surfaces (verified in routes):
  - Tenant API key: `DELETE /v1/auth/api-keys/:id` — `api-keys:write` scope,
    tenant-scoped delete + Redis cache invalidation, `204`/`404`
    (`api-server/src/routes/auth.rs`).
  - Enterprise sub-account key:
    `POST /api/enterprise/sub-accounts/:id/api-keys/:key_id/revoke` with parent
    tenant access (`enterprise/src/routes.rs`).
  - Sessions: `POST /v1/auth/sessions/revoke` (`{session_id}` /
    `{revoke_all}`).
  - Platform-wide: rotate `API_KEY_HASH_SECRET` (invalidates every stored
    hash), JWT/PEM overlap, DKIM re-issue, webhook secret (secret-rotation
    runbook).
- `docs/operations/emergency-key-revocation.md` rewritten to these surfaces,
  including the direct-DB fallback (`DELETE FROM api_keys … RETURNING
  key_hash` + cache DEL) and an explicit “Known gaps” section: no admin bulk
  revoke/unrevoke endpoint, no `key_kid`/`encryption_keys` bookkeeping, no
  `X-2FA-Code` header anywhere, no tenant notification behaviour.
- `docs/operations/admin-2fa-enforcement.md`: the false `X-2FA-Code` claim is
  replaced with the shipped behaviour (role MFA policy at login; control-plane
  sessions carry `mfa_enabled`; no per-request 2FA header).
- `docs/operations/runbooks/crypto-incidents.md`: both the fictional revoke
  curl and the fictional `/v1/admin/audit-logs` query were replaced with the
  real endpoints (`DELETE /v1/auth/api-keys/:id`,
  `POST …/sub-accounts/…/revoke`, `GET /v1/admin/audit` with the system-tenant
  requirement).

## P1-9 — VDP `security.txt` and PGP artifacts

Two outcomes, both stated.

- `security.txt`: **shipped in-repo** at
  `apps/marketing-zola/static/.well-known/security.txt` (Zola copies `static/`
  into the served `public/` root; the `apexmail.ee` vhost proxies to the
  marketing origin). RFC 9116 fields: `Contact`, `Expires` (2027-10-06),
  `Preferred-Languages: en, et`, `Canonical`, `Policy`, `Encryption`. The
  compliance template `templates/compliance/security.txt` now carries the same
  real values plus the exact clear-sign operator command (the private key is
  held by the security team, never in-repo).
- PGP key: the repository already ships a **real, valid** public key at
  `apps/marketing-zola/static/pgp-key.asc` (`gpg --show-keys`: `rsa4096
  2026-07-29`, fingerprint `B30B 9531 6B44 4E38 2803  19A5 5183 FF3B C9A6
  9386`, uid `ApexMail Security <security@apexmail.ee>`). The invalid
  `docs/security/pgp-public-key.asc` was replaced with that key, and
  `docs/security/pgp-key-distribution.md` was rewritten to the real key facts
  (algorithm, dates, fingerprint, served path) with the generation and
  revocation operator commands; invented keyserver/WKD/Keybase publication
  claims were removed.
- `docs/security/vulnerability-disclosure-program.md`: PGP line points at the
  served `.asc` + fingerprint, the checklist distinguishes in-repo shipping
  from post-deploy liveness, and `status.apexmail.io` became
  `status.apexmail.ee`.
- Residual: `api.apexmail.ee/.well-known/security.txt` is not served
  (the api vhost proxies to api-server, which has no such route; adding one is
  a `services/**` change and `deploy/**` is out of scope here).

## P2/P3 items

Fixed in owned paths:

- P2-2: `docs/api/rate-limits.md` usage example now `GET /v1/billing/usage`
  (billing:read, real payload shape).
- P2-3/P2-4: `docs/api/endpoints/suppressions.md` rewritten to the five
  mounted routes (single check stays `GET /check/:email`; bulk add documented
  with its real body/response); fabricated `POST /check`, `GET /:id`,
  `GET /stats`, `DELETE /bulk`, `POST /import`, `GET /export` removed.
  `docs/api/changelog.md` endpoint tables cleaned of the same fabrications.
  `docs/user-guide/contacts.md` suppression block now uses
  `GET /check/:email`, `DELETE /:id` and states there is no CSV pipeline; the
  GDPR export row now cites the shipped CSV/analytics exports and the
  not-implemented DSAR state.
- P2-5: `stripe-integration.ts`/`autoProvisionDedicatedIps()` replaced with
  `billing-service/src/stripe_webhooks.rs::auto_provision_dedicated_ips_background`
  in `docs/architecture/hybrid-email-infrastructure.md` and
  `docs/deployment/PRODUCTION_SETUP.md`; `ses_monitoring.rs` →
  `routes/ses_notifications.rs`; the SES DKIM bullet corrected to
  customer-managed keys (Easy DKIM is not used); the `$30` add-on corrected.
- P2-6: `status.apexmail.io` → `status.apexmail.ee` in
  `docs/operations/incident-communication.md`,
  `docs/operations/performance-methodology.md`,
  `docs/security/vulnerability-disclosure-program.md`.
- P2-7: `docs/operations/cache-warming.md`: the session-cache entry now
  describes the real Redis caches (no 50k moka session cache, no
  `api-server/src/auth.rs`), the Kubernetes init-container section is marked
  roadmap-only with the Compose deployment stated, the cold-start table uses
  Compose/host language, and §7 states that
  `deploy/config/top-email-domains.txt` is not shipped and the script falls
  back to its inline list.
- P2-9: KiwiCaptcha difficulty default corrected to 20 in both places.
- P2-10: `docs/pricing-authority.md` link points at the crate copy of
  `legal_entity.rs`; both it and `docs/pricing.md` now name
  `platform-catalog` as the canonical plan-fact source and `plans.rs` as the
  runtime seed.
- P2-11: `docs/development/application-route-inventory.md` cites
  `axum_router.rs` and its April validation block is marked historical/stale.
- P3-1…P3-13: HSTS citation (`HDR_HSTS` static), RBAC citation
  (`scopes_for_role`), sales-autopilot paths (`integration-tests`, module
  directories, worker-processors link), overview monorepo diagram rows,
  contributing recognition/standards links, ADR numbering (0001–0011, 0015),
  inline-script labeling in `crypto-incidents.md`/`secret-rotation.md`,
  GDPR wording alignment in `docs/README.md`, roadmap marking for read
  replicas/Redis cluster, and the analytics planned-endpoint cache rows moved
  under a planned note. `templates/compliance/security.txt` fixed under
  P1-9.

Not fixed (outside owned paths) / follow-ups:

- P2-1 root `README.md` analytics/webhook tables and `message.sent`
  (root file not in the owned path list).
- P2-8 the duplicate tracked corpus under `apps/ai/training/data` and the
  consumer defaults (apps/ai owner).
- P3-12 was recorded by the review as a no-finding.

## P0 (investigate-only) — seven capabilities sold in `docs/pricing.md:44-46`

`docs/pricing.md:44-46` was intentionally **not** edited: the brief assigns the
claim rewrite to the follow-up wave. Ground truth:

| Capability (claim) | Classification (`billing-entitlements/src/classify.rs`) | Shipped implementation | Entitlement path behaviour | Follow-up |
|---|---|---|---|---|
| A/B testing (`ab_testing`, “Growth and above”) | NotYetImplemented | None. Campaigns accept/store an inert `ab_test` JSON field (`api-server/src/routes/campaigns.rs:256,299,324`), but no experiment-creation handler, no arm split or winner selection in the send path. `ai-service/src/content.rs:319` has a deterministic winner helper not wired to sends. | Never grantable: `require_feature` returns `NotRuntimeEnforced`, `has_feature` false; not seeded; a runtime gate on it would 500 (tests `entitlements.rs:222`, `snapshot.rs:353`). | Needs experiment execution in the send pipeline. |
| Audit logs (`audit_logs`, “Growth and above”) | NotYetImplemented | Audit rows + hash chain are written; the only read surface is operator-only `GET /v1/admin/audit` (wildcard scope + system tenant). No customer read/export route. | Same: not grantable, not seeded. | Add customer read/export route + gate; data already exists. |
| Time-travel debugging (`time_travel_debugging`, “Growth and above”) | NotYetImplemented | None beyond the flag and tests. | Not grantable, not seeded. | Largest item: historical message-state replay infra. |
| Custom retention (`custom_retention`, “Growth and above”) | NotYetImplemented | No retention-editing handler; `max_retention_days` ceilings exist only as displayed plan values (also classified NotYetImplemented for editing). | Not grantable, not seeded. | Add retention-editing API + enforcement in sweeps. |
| Custom tracking domain (`custom_tracking_domain`, “Pro and above”) | NotYetImplemented | Only the `PlanFeatures` field and the billing payload echo; no setup/verification route (tracking service has no tenant custom-domain lifecycle). | Not grantable, not seeded. | Needs tracking-domain lifecycle (DNS record + tracking-service routing). |
| Template approval workflow (`template_approval_workflow`, “Business and Enterprise Cloud”) | NotYetImplemented as a plan flag | An enterprise-service surface **does** exist: `enterprise/src/routes.rs:849-853` (`/templates/submit`, `/:id/approve`, `/:id/reject`, stats) backed by `TemplateApprovalService`. | Not grantable, not seeded; the enterprise surface is not gated by the billing flag. | Wire the entitlement + expose to Business. |
| Subaccounts (`subaccounts`, “Business and Enterprise Cloud”) | NotYetImplemented | An enterprise-service surface exists: sub-account CRUD + per-key revoke (`enterprise/src/routes.rs:817-833`), tenant-access checked but not plan-gated; `plans.rs` seeds `subaccounts: false`, `max_subaccounts: 0`. | Not grantable, not seeded. | Wire the entitlement + `max_subaccounts` capacity. |

Proposed implementation order (lowest cost, highest claim integrity first):

1. `audit_logs` — data and chain already shipped; add the customer read/export
   route and the gate.
2. `template_approval_workflow` — enterprise service already implements the
   maker/checker flow; wire the entitlement and expose it to Business.
3. `subaccounts` — enterprise CRUD exists; wire the entitlement and the
   `max_subaccounts` capacity so the seeded 0/50 limits mean something.
4. `custom_tracking_domain` — build the domain lifecycle and tracking-service
   routing, then seed the flag.
5. `ab_testing` — add experiment execution (arm assignment, holdout, winner
   selection) to the send path.
6. `custom_retention` — add the retention-editing surface and enforce it.
7. `time_travel_debugging` — historical-state replay; treat as a project, not
   a flag flip.

Until each lands, the entitlement path correctly refuses the flag; the pricing
page claims remain the one open honesty gap of this slice.

## Gates run (after edits)

| Gate | Result |
|---|---|
| `python3 tools/check_knowledge_consistency.py` | PASS (incl. new stripe/lifecycle doc pinning) |
| `python3 tools/check_knowledge_consistency.py --self-test` | PASS (all cases, incl. 2 new) |
| `python3 tools/validate_pricing_drift.py` | PASS (incl. new dedicated-IP and SLA-cap pins) |
| `python3 docs/marketing/check_pricing_parity.py` | PASS — 6 plans, exit 0 |
| `python3 tools/i18n-audit.py` | PASS — 0 findings |
| `bash tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` | all files touched by this fix are within baseline; total 2792 vs baseline 2827. Three rows unrelated to this work remain over: `docs/user-guide/glossary.md` (34/32), `docs/deployment/migration-rollback.md` (12/10), `docs/user-guide/inbox-placement-testing.md` (14/13). glossary and inbox-placement are byte-identical to HEAD, so the committed baseline is already red for them; migration-rollback is a concurrent agent edit. |
| `python3 tools/check_capability_claims.py`, `check_feature_entitlements.py`, `check_docs_architecture_truth.py`, `check_claim_expiry.py`, `check_security_posture.py` | all PASS |

## Cross-owner follow-ups (named, not done here)

1. apps/ai: redirect `pipeline.sh:18`, `apps/ai/training/common_paths.py:25`
   to `apps/ai/training/data/`; fix the `\\n` writer bug at
   `sweep_currency_to_eur.py:214`; the canonical table still lists the
   dedicated-IP add-on as `€30/mo` (`validate_pricing.py` `addons`), stale
   against the runtime €49/€69.
2. tools owner: `tools/common_paths.py:5` `DATA_DIR` still points at root
   `data/` (its consumer scripts now find no JSONL corpus there).
3. marketing owner: delete or correct the dead `ip_cost: 30` in
   `apps/marketing-zola/data/pricing.json`.
4. docs-follow-up wave: rewrite `docs/pricing.md:44-46` only together with
   the capability implementations above (owner directive: true claim backed by
   code, not a deleted claim).
5. deploy/services owner: an `api.apexmail.ee/.well-known/security.txt` needs
   an api-server route or an nginx static location (deploy/** not owned here).
