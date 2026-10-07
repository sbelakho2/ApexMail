# FIX FLEET — docs, protocol, root data, legal templates (from review-docs-protocol-data.md)

You are a FIX agent with a rigorous mandate. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail. READ
docs/audit/dogfood-2026-10-06/review-docs-protocol-data.md in full first —
it carries file:line evidence per item.

The honesty contract: every factual claim must match the SHIPPED code/config.
House directives (owner): claims must match the shipped code — when a claim
names a capability, the end state is a TRUE claim backed by code, not a
deleted claim; operator-only steps (secrets, deploys) may be stated as such
when the artifact itself cannot be produced in-repo.

Own these paths ONLY: `docs/**`, `data/**`, `templates/legal/**`,
`templates/compliance/**`, `protocol/**`, `apps/marketing-zola/data/canonical.json`
(only if a claim there is proven stale), `packages/README.md` (no — owned by
another agent; skip it). Do NOT touch `services/mail-server/**`, `apps/ai/**`,
`packages/**`, `ci/**`, `deploy/**`, `scripts/**`.

## Items

P1 (fix all):
1. Stale price ladder: `docs/tool-contracts/stripe.md:16-24` and
   `docs/architecture/billing-lifecycle.md:20-28` — align to the canonical
   catalog (services/mail-server/crates/platform-catalog/src/lib.rs +
   billing plans.rs seeds). These are the same numbers the knowledge gate
   pins; after your edit run `python3 tools/check_knowledge_consistency.py`
   (it does not cover these two docs — ALSO add them to the gate's docs
   coverage if that is the honest way to keep them pinned; coordinate:
   tools/check_knowledge_consistency.py is not owned by another agent).
2. `docs/pricing.md` dedicated-IP counts/price: Scale 3 vs runtime 1,
   Enterprise 10 vs 3; €30 vs calculator €49/€69 — resolve against runtime
   (billing seeds/calculator) and make doc + calculator agreement pinned by
   the drift validator if it doesn't already.
3. SLA credit cap contradiction: `docs/sla.md` + `templates/legal/sla.md`
   (10%) vs runtime 30%. Find the runtime enforcer, align the legal/doc text
   to the shipped number (that is the promise the system keeps), and note the
   decision in your report.
4. `docs/marketing/check_pricing_parity.py` exits 1 after the platform-catalog
   refactor — fix its parser the same way tools/validate_pricing_drift.py was
   fixed (support the catalog delegation shape; cite that file's approach).
5. `docs/deployment/configuration.md` documents 49 env vars that exist
   nowhere (incl. OPENAI_API_KEY, SENTRY_DSN): rebuild the doc from the real
   env contract (.env.example + docker-compose*.yml `${VAR}` usages + the
   `${VAR:?}` guard list). Every row must exist; every required var must be
   listed.
6. Root scratch corpus `data/**` with the retired price ladder while
   data/README.md (or docs) says it was removed: trace consumers (the review
   began this — finish it). No consumers → remove the drifted duplicates per
   the README's own stated state; consumers → reconcile content. Either way
   run the pricing grep (€25/€65/€150/€350/€3,000) over data/** and leave zero
   live hits.
7. `data/system_prompts.json` 111/120 broken digests + malformed `.sha256`:
   recompute the digests from the actual content and fix the checksum file
   (verify with a one-liner in your report). If a digest-mismatch means the
   content changed after the manifest was written, the CONTENT wins and the
   manifest is regenerated (say so).
8. Emergency key-revocation runbook documents a nonexistent
   `POST /v1/admin/keys/revoke`: find the real revocation surface in
   api-server routes (grep api-keys routes) and rewrite the runbook to the
   real path/method/body/permissions. If no revocation surface exists, that
   is a capability gap — document it precisely in your report as such for the
   follow-up wave (do NOT edit services/**).
9. VDP security.txt/PGP placeholders: produce a real
   `.well-known/security.txt` artifact in-repo (contact security@apexmail.ee,
   canonical URL, expiry, languages — per RFC 9116) at the location the
   deployment serves from; for the PGP key, if generating one requires a
   private key only the owner may hold, ship the exact generation command in
   the VDP doc as a one-line operator step and keep the placeholder file
   clearly labeled as not-yet-generated. State both outcomes in the report.

P2/P3: fix the mounted-route doc gaps against the real api-server routes
(`/v1/account/usage`, `POST /v1/suppressions/check`, contacts/suppressions
exports), the removed-system references (`stripe-integration.ts`,
`ses_monitoring.rs`), `status.apexmail.io` drift, the cache-warming K8s
self-contradiction, and the stale line/path citations the review lists.

INVESTIGATE-ONLY (no edits to services/**; produce a ground-truth table in
your report): the P0 — `docs/pricing.md:44-46` selling seven capabilities
(A/B testing, audit logs, time-travel debugging, custom retention, custom
tracking domain, template approval, subaccounts) that
`billing-service/src/types.rs` classifies `NotYetImplemented`. For EACH
capability: does shipped code implement it (grep for the feature flag's
consumers, the target feature's routes/tables)? what does the entitlement
path do with the NotYetImplemented classification? This table drives the
follow-up implementation wave (billing-service is owned by a running agent
right now).

## Rules
- No deploy. No edits outside your owned paths.
- Run the repo's doc gates after editing: `bash tools/docs-lint.sh` (if it has
  a baseline mode, use it), `python3 tools/check_knowledge_consistency.py`,
  `python3 tools/validate_pricing_drift.py`, `python3 tools/i18n-audit.py`.
- Report per item: FIXED (evidence) or a named blocker. For the
  investigate-only P0: the table + a proposed implementation order.
- Report file: docs/audit/dogfood-2026-10-06/fix-report-docs.md.
