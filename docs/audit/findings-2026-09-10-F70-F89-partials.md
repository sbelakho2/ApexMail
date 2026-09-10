49 open findings: 31 P1 and 18 P2. Of the original F01–F69 register, 40 are closed and 29 are partially repaired or incomplete. This pass adds F70–F89 (20 findings). Closed means the original reported defect is repaired by the stated evidence; it does not certify every behavior in that file.

Reviewed revision: 1b18516935e008c2c57bbff31d54f0168dddcd5e. Compared with 0c27984d1d551a245d86869525dbe418ba6de62a: 70 commits, 598 changed files. A final branch check found 29 additional commits after the initially inspected 0c0111e; those changes were incorporated and the available checks repeated. References below are pinned to the final reviewed revision.

The strongest release concerns are consent/tenant enforcement (F18/F55), caller-controlled SES attribution (F74), non-authoritative Stripe settlement and collection (F33/F34/F72/F73), broken contact persistence (F07/F70), and idempotency under replay/cancellation (F19/F20/F21). Fixing the reported SQL line alone is insufficient where the failure spans an operation, ledger or transport contract.

P1 means a significant security, billing, data-integrity, common-flow or required-gate defect. P2 means a narrower feature/operational defect, including explicitly conditional components. No P0 or observed production compromise is asserted. F49/F50 were already closed in the preceding final review; do not count them as new repairs. F43 retains the pagination identity in the archived final F01–F69 report, correcting the older JSON title.

Evidence and limits

Check

Result

Practical limit

Tracked-file inventory

3,573 files; 2,972 text files; 8,721,629 text lines

Hashes and coverage are in ApexMail-File-Index.csv; this is not a claim of manual semantic review of every line.

Rust AST parsing

752 files; no syntax errors

Does not check type correctness, features, ownership, linking or runtime behavior.

Other syntax

68 TOML, 77 Python, 100 JSON, 86 shell, 42 JavaScript; no failures

Only the parsers/check modes stated in the scripts were used.

Canonical migration SQL

152 files applied to a fresh PostgreSQL 18.3/PGlite database

Production SQLx execution, migration checksums and all populated upgrade lineages not validated.

Extracted SQL

2,401 literals; 2,094 prepared; 307 rejected, of which 209 are outside test modules

Rejected literals include templates/fragments, runtime initializers and inference limits; see the triage file, not a 307-bug claim.

Targeted database checks

15 defect reproductions plus one existing wallet guard verified

Statement-level fixtures; no full Rust service or real external provider calls.

Contrast classifier

Known 1:1 gradient was downgraded to nonblocking pixel-suspect

Actual classifier executed with known inputs; screenshot acquisition was not run.

Repository checks

All 11 invoked checks passed

Zola, security flags, audit ledger, outbound contract, claim expiry, pricing, legal identity, i18n, tag balance, Kiwi isolation, Python SDK.

HTML structure / Python SDK

300/300 pages balanced; 59 Python tests passed

No browser visual signoff; no clean wheel or other SDK runtime suite.

This is a systematic source, schema and bounded reproduction audit, not proof that every defect has been found.

All 3,573 tracked files were inventoried and hashed. The 8,721,629 text lines were not all manually reviewed for semantics; large generated/vendored assets dominate that count.

Rust was parsed for syntax, not compiled or executed: cargo/rustc and a live full-stack runtime were unavailable. No Rust unit/integration/Clippy run is claimed here.

Canonical SQL migrations were applied on PostgreSQL 18.3 in PGlite 0.5.8, not through the production SQLx runner or production database. This validates the tested schema/query cases, not every live upgrade lineage, extension, lock schedule or driver result type.

No live SMTP/SES send, Stripe charge/refund, SCIM IdP exchange, production database write, load/chaos exercise or deployment was performed.

Python SDK tests ran using available dependencies and source paths; clean wheel installation and Go/Java/PHP/Ruby runtime suites were not executed.

Zola and structural checks ran. Current screenshots/committed UI reports and the repository’s stated CI/deployment success are not an independently repeated visual/production signoff. Browser layout, contrast and accessibility were not re-executed here; the contrast classifier was separately exercised with a controlled input.

Optional/standalone findings explicitly identify unproven production reachability. Missing runtime-initialized stores and ambiguous SQL parameter inference were not automatically counted as bugs.

No application source was edited or pushed by this audit. Existing working copies and their modified screenshots were left intact.

The file inventory records targeted review only where evidence is attached; all other rows explicitly lack a complete semantic signoff. A passed repository audit-ledger check is a check of that ledger, not independent proof that all product flows work.

Dependency order

The register includes explicit prerequisites for each finding. Build these changes as coherent transactions/contracts, and validate each dependency before calling its consumer repaired. Security corrections that can be isolated, especially F74/F65 and stopping dispatch after a deferred consent check, should be addressed immediately.

Work area

What to establish

Findings

Canonical fixtures, persistence and required gates

Fail configured test infrastructure honestly; repair schema/DTO contracts; remove false-green contrast behavior.

F01, F07, F52, F63, F70, F76, F77, F78, F83, F85, F86, F87

Accounting and collection

One logical usage/payment identity; immutable period pricing; authoritative remaining balance; exclusive collection ownership and durable retries.

F08, F09, F29, F31, F32, F33, F34, F36, F60, F71, F72, F73

Authorization, consent and request ownership

Trusted tenant identity, independent holds, definitive consent decisions, bounded owner leases and exact replay.

F18, F19, F20, F21, F55, F65, F74

Delivered-message contract

One mailbox model, correct MIME and attachments/templates, recipient state reconciliation and trusted SES feedback.

F13, F25, F26, F48, F75

Console, integrations and reporting

Consume repaired ledgers/models; wire advertised features; show unavailable data honestly; fix SCIM and analytics.

F04, F14, F42, F61, F62, F67, F79, F80, F81, F82, F84, F88, F89

Release verification

Run the complete configured database, provider sandbox, browser, SDK and deployment gates after the integrated changes.

All P1 flows and enabled P2 components

One valid dependency sequence, also included as an ordered JSON array: F01, F70, F07, F52, F63, F76, F77, F78, F83, F85, F86, F87, F08, F09, F29, F32, F31, F72, F60, F73, F34, F71, F33, F36, F18, F19, F21, F20, F55, F65, F74, F48, F26, F13, F25, F75, F04, F14, F42, F61, F62, F67, F79, F81, F80, F82, F84, F88, F89. Dependencies express prerequisites, not a demand to ship dozens of separate changes. In particular F26 and F48 belong to one coordinated send-contract change.

Open findings register

ID

Priority

Status

Finding

Scope

F01

P1

partial

Canonical test setup can turn a configured database failure into a passing skipped test

Required database-test infrastructure

F04

P1

partial

The console outstanding balance still ignores confirmed allocations and credits

Production code path

F07

P1

partial

Contact CRUD still disagrees with the canonical metadata and UUID model

Production code path

F08

P1

partial

Invoice-address snapshots still fall back to mutable values field by field

Production code path

F09

P1

partial

Payment recovery can still clear unrelated restrictions

Production code path

F13

P2

partial

Signed originating-message attribution exists but is not connected to outgoing mail

Outgoing attribution integration; standalone codec is repaired

F14

P1

partial

Required missing-schema failures are still rendered as empty console data

Production code path

F18

P1

partial

Dispatch still fails open on tenant restrictions and recovery access is overbroadly denied

Production code path

F19

P1

partial

Oversized idempotent requests lose their body and payload binding

Production code path

F20

P1

partial

Durable send replay changes the response envelope and can swallow ledger failures

Production code path

F21

P1

partial

Request cancellation can leave the Redis idempotency lease renewing forever

Production code path

F25

P1

partial

Parent message progress is reconciled only on successful recipients

Production code path

F26

P1

partial

Restored To/Cc values are serialized as one malformed mailbox

Production code path

F29

P1

partial

Existing-invoice recovery executes inside an aborted transaction

Production code path

F31

P1

partial

One bad period still aborts the sweep and unresolved work ages out

Production code path

F32

P1

partial

Period pricing still reads mutable rates and defaults currency to EUR

Production code path

F33

P1

partial

Collection can overstate debt, has no exclusive owner, and marks failed work done

Production code path

F34

P1

partial

Stripe items still have no complete mapping to the original local invoice

Production code path

F36

P1

partial

Subscription updates still accept stale state across the new entitlement lock

Production code path

F42

P1

partial

Standard SCIM PATCH bodies are rejected and concurrent patches can undo deactivation

Production code path

F48

P1

partial

SDK fields now reach the API but still violate its delivery contract

Production code path

F52

P1

partial

The contrast gate can pass without execution and can downgrade real gradient failures

Required CI/browser audit infrastructure

F55

P1

partial

A failed consent recheck requeues the job and then continues sending

Production code path

F60

P2

partial

Crediting an unpaid invoice both cancels debt and creates spendable wallet value

Standalone credit-note service; no production caller found

F61

P2

partial

The standalone entitlement response still disagrees with enforced limits

Standalone entitlement helper; no production caller found

F62

P2

partial

Stored-template cache omits an option that changes output

Stored-template renderer; source-only HTTP rendering is a separate path

F63

P2

partial

Optional component migration coverage is still incomplete

Conditional HA/isolation components; deployment enablement not established

F65

P2

partial

Application request logs still include verification tokens

Production code path

F67

P2

partial

Reply analytics persistence is repaired but has no production ingestion caller

Separate analytics component; no production caller found

F70

P1

new

Contact-tag normalization accepts nonstrings and can abort a populated upgrade

Production code path

F71

P1

new

Generic usage deduplication is a check-then-insert race

Production code path

F72

P1

new

Stripe invoice.paid infers a persisted invoice from a constant SELECT result

Production code path

F73

P1

new

Stripe paid callbacks allocate the full invoice total instead of the confirmed payment

Production code path

F74

P1

new

SES attribution headers disagree with the sender and caller-controlled aliases can select another tenant

SES-enabled sending and callbacks

F75

P1

new

SES delivery persistence writes a missing column and bypasses recipient aggregation

SES-enabled delivery callbacks

F76

P1

new

Audit live/archive UNION queries have incompatible column counts

Compliance audit component when enabled

F77

P1

new

Content scanning selects content_policies.active although the schema uses enabled

Compliance content-scanner component when enabled

F78

P1

new

Compliance overview fails against its required GDPR deadline column

Production code path

F79

P2

new

Activation analytics uses invalid nested aggregates and reports zero on failure

Production code path

F80

P2

new

Standalone financial analytics uses nonexistent invoice fields, wrong month windows and fabricated totals

Standalone compliance reporting helper; no production caller found

F81

P2

new

Optional tax reports use stale rates and treat all revenue/costs as domestic VAT

Optional/standalone statutory report helpers; no filing performed

F82

P2

new

Subject export skips canonical invoices because it searches a nonexistent customer_email

Compliance subject-export component when enabled

F83

P2

new

Optional event compaction requires provider/region fields absent from canonical events

Optional PostgreSQL analytics compaction; deployment enablement not established

F84

P2

new

Optional placement analytics queries a missing domain and equates delivery with inbox placement

Separate analytics helper; no production caller found

F85

P2

new

Optional campaign optimization has no canonical campaign_arms store

Separate optional analytics helper; no production caller found

F86

P2

new

The optional incident repository requires resolved_at and does not clear it on reopening

Standalone IncidentRepo; no production caller found

F87

P2

new

The optional warmup repository uses an ISP-profile shape for a per-pool schedule table

Standalone WarmupRepo; no production caller found

F88

P2

new

Importing a contact without tags clears its existing tags

Production code path

F89

P2

new

The incident-advice tool returns SQL for an audit identity column that does not exist

AI operational-advice output; query is not executed by this tool

Exact remediation requirements

<a id="f01"></a>

F01 · P1 · Canonical test setup can turn a configured database failure into a passing skipped test

Status: partial. Scope: Required database-test infrastructure. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/migrator/src/lib.rs:207; services/mail-server/crates/migrator/src/lib.rs:219; services/mail-server/crates/migrator/src/lib.rs:292; services/mail-server/crates/api-server/src/routes/contacts.rs:1328; services/mail-server/crates/integration-tests/tests/schema_contract_tests.rs:100.

Already repaired: API/integration/sales test helpers now have a shared canonical migration path.

Remaining defect: The shared migrator is a substantial improvement. However, fresh_canonical_db returns None for connection, migration and clone failures. Callers can return successfully without assertions. TEMPLATE_VERIFIED is set before asynchronous initialization succeeds, so another test can clone a partial template; the logged direct-apply fallback is not actually invoked. Handwritten test DDL also still supplies fields absent in production, including contacts.metadata. The latest schema-contract wrapper correctly panics on None; other callers still permit successful early returns, and the shared initialization contract remains unchanged.

Required changes:

In migrator/src/lib.rs return Result<Option<PgPool>, ProvisionError>: None only when tests are explicitly unconfigured. Configured infrastructure failures must fail the test.

Replace the preemptive OnceLock.set with an asynchronous get_or_try_init that publishes success only after migrations and lineage verification finish. Hold initialization coordination through a verified clone; give different migration revisions distinct template names.

Execute the documented direct fallback or remove that misleading branch. Verify the clone migration ledger before returning it. Convert database contract tests, including contacts CRUD, to this shared canonical fixture instead of inventing missing columns.

Verification: Break a migration and separately deny clone permission with DATABASE_URL set: the test command must fail. Run two concurrent initializers and verify both returned databases contain the complete pinned migration ledger.

Evidence: Source/control-flow review; service integration not executed.

<a id="f70"></a>

F70 · P1 · Contact-tag normalization accepts nonstrings and can abort a populated upgrade

Status: new. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/migrations/150_contacts_tags_canonical.sql:26; services/mail-server/migrations/150_contacts_tags_canonical.sql:46.

Remaining defect: The validator iterates jsonb_array_elements_text, which converts numbers, booleans and objects to strings before checking them. The database therefore accepts nonstring JSON tags. The normalization UPDATE invokes jsonb_array_elements(tags) on legacy scalar values without guarding their type, so a populated upgrade aborts with 22023.

Required changes:

Validate array element types using jsonb_array_elements and jsonb_typeof(element) = string; validate the actual strings after trimming, including nonempty value, length, uniqueness and count bounds.

Normalize through a CASE that feeds an empty array to the set-returning function for nonarrays. Decide and record how scalar/object legacy values are reconciled; deduplicate before applying the count cap.

For databases where 150 already applied, add a new numbered repair migration and replace the validation function there. For pending invalid-data upgrades, use a documented preflight/reconciliation path and migration-checksum policy; do not blindly rewrite an applied migration.

Verification: Migrate fixtures with null, scalar, object, mixed-type arrays, duplicates and oversized tags. All valid strings survive; invalid shapes are rejected or explicitly reconciled, and no deployment aborts halfway.

Evidence: Canonical PostgreSQL validator accepts [42,true,{...}]; applying the normalization to a scalar legacy value fails with SQLSTATE 22023.

<a id="f07"></a>

F07 · P1 · Contact CRUD still disagrees with the canonical metadata and UUID model

Status: partial. Scope: Production code path. Prerequisites: F01, F70

Files and exact locations: services/mail-server/crates/api-server/src/routes/contacts.rs:209; services/mail-server/crates/api-server/src/routes/contacts.rs:386; services/mail-server/crates/api-server/src/routes/contacts.rs:417; services/mail-server/crates/api-server/src/routes/contacts.rs:573; services/mail-server/crates/api-server/src/routes/contacts.rs:606; services/mail-server/crates/apexmail-db/src/repos/contacts.rs:23.

Already repaired: The original absent tags column has been added.

Remaining defect: Migration 150 adds tags, but no canonical migration adds contacts.metadata. Create/read/update/import and repository operations still select or write metadata. In addition, ContactRow.id is String although contacts.id is UUID, and detail/update/delete bind text IDs without a UUID boundary. Adding metadata alone will expose the next failure.

Required changes:

Add a new numbered canonical migration for metadata JSONB with the chosen object/null contract, default, shape constraint and a deliberate legacy backfill. Update canonical contact readers/writers together.

Use uuid::Uuid for ContactRow.id and repository IDs. Parse path IDs once and return a controlled 400 for invalid UUIDs; bind UUID values, or cast a validated parameter explicitly with $1::uuid. Convert IDs to strings only in response DTOs.

Keep tags, metadata and tenant predicates identical across create, list, detail, update, delete, bulk import and export. Replace the contact tests that hide metadata drift with canonical fixtures.

Verification: Fresh migrations → create → list → get → update → import → export → delete, with populated metadata/tags and a second tenant. Assert invalid IDs return 400, never 500.

Evidence: Executed exact contact INSERT: PostgreSQL 42703. Prepared DELETE with text ID binding: 42883. UUID result mismatch established from Rust DTO and canonical column type.

<a id="f52"></a>

F52 · P1 · The contrast gate can pass without execution and can downgrade real gradient failures

Status: partial. Scope: Required CI/browser audit infrastructure. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: ci/stages/test.sh:218; ci/stages/test.sh:219; tools/contrast-audit/audit.mjs:480; tools/contrast-audit/audit.mjs:556.

Already repaired: Tag-balance no longer depends on Node/Playwright, and layout is required by default.

Remaining defect: Missing Node, gate script or Playwright still returns CI_EXIT_OK from run_contrast_gate. The latest audit.mjs also adds floorGuard: a high contrast ratio against the solid fallback downgrades a failing rendered gradient ratio to pixel-suspect. Gate mode counts only fail-aa. An opaque light gradient can cover a dark fallback completely, so a good fallback contrast does not prove readable rendered text. Actual screenshot disagreement needs investigation, not a universal pass rule.

Required changes:

Make contrast required by default on release CI and fail required runs on missing prerequisites. Provision the browser toolchain and persist an executed/skipped/failed result bound to the reviewed revision.

Remove the fallback-color exemption for rendered gradient failures. Fix sticky/full-page coordinate sampling using viewport/element screenshots and scroll-aware bounds, or require unresolved measurements to block the required gate pending explicit review.

Add an independent negative fixture: white text on an opaque white gradient with a black background-color must fail. Also test a passing gradient and sticky-header sampling without relying on a prior committed report.

Keep layout/tag-balance independent and preserve their newly required behavior. Re-run actual contrast/layout after fixes; a clean fixture report is not a production browser signoff.

Verification: Remove Playwright on a required runner: CI must fail. Run the deliberately unreadable gradient and assert a failed gate; then verify real sticky-header pages with correct screenshot coordinates.

Evidence: Latest CI branches and gradient classifier inspected; an extracted-classifier counterexample demonstrates a rendered 1:1 gradient being downgraded to a nonblocking pixel-suspect. Browser pixel sampling itself was not executed in this re-audit.

<a id="f63"></a>

F63 · P2 · Optional component migration coverage is still incomplete

Status: partial. Scope: Conditional HA/isolation components; deployment enablement not established. Prerequisites: F01

Files and exact locations: services/mail-server/crates/ha/src/health_check.rs:264; services/mail-server/crates/ha/src/health_check.rs:286; services/mail-server/crates/isolation/src/data_isolation.rs:482; services/mail-server/crates/isolation/src/encryption.rs:330; services/mail-server/crates/isolation/src/encryption.rs:415.

Already repaired: All originally enumerated edge-case/backup/chaos/region/isolation/contact-person tables received canonical migrations.

Remaining defect: Migrations 160–168 cover the originally listed tables, but connected methods still reference ha_health_checks, iso_access_attempts and iso_encryption_policies. No canonical migration or runtime initializer for these relations was found; their SQL fails when the corresponding feature is enabled.

Required changes:

Add new numbered canonical migrations matching the actual INSERT/SELECT row contracts for all three relations, including canonical tenant/workspace foreign keys, timestamps, uniqueness, policy ownership and retention.

Wire writers/readers and lifecycle cleanup into each enabled component. Fail component readiness when its required schema is missing.

Add canonical create/read/update/restart tests rather than migration-content substring assertions. Include the separately listed analytics/repository contracts F83–F87 in the same schema-coverage gate.

Verification: Enable each component on a fresh canonical database, create and read a health result, access attempt and encryption policy, restart and reread with another tenant excluded.

Evidence: Canonical-schema SQL preparation returns 42P01 for the listed relations; repository-wide CREATE searches found no producer initializer.

<a id="f76"></a>

F76 · P1 · Audit live/archive UNION queries have incompatible column counts

Status: new. Scope: Compliance audit component when enabled. Prerequisites: F01

Files and exact locations: services/mail-server/crates/compliance/src/audit_logger.rs:452; services/mail-server/crates/compliance/src/audit_logger.rs:486; services/mail-server/crates/compliance/src/audit_logger.rs:640; services/mail-server/crates/compliance/src/audit_logger.rs:727; services/mail-server/crates/compliance/src/audit_logger.rs:739; services/mail-server/crates/compliance/src/audit_logger.rs:751; services/mail-server/crates/compliance/src/audit_logger.rs:763.

Remaining defect: Seven queries UNION ALL SELECT * from audit_logs and audit_logs_archive. On the canonical chain the live table has 18 columns and the archive 16; the live-only created_at/fts_vector additions make the UNION invalid. Search, export, statistics and integrity consumers using it fail even when both tables are empty.

Required changes:

Replace every SELECT * union with the same explicit, type-aligned list of audit fields needed by the consumer, or introduce a canonical read view with that projection.

Keep archive insertion/copying and the read model aligned. Preserve live search indexes and audit-chain fields instead of deleting columns merely to equalize counts.

Test searches, exports, counts and integrity checks against empty, live-only, archived-only and mixed canonical data.

Verification: Apply fresh migrations and exercise all seven query callers. Move a known event to archive and verify it remains visible once with unchanged integrity fields.

Evidence: Exact UNION fails on canonical PostgreSQL with SQLSTATE 42601: each UNION query must have the same number of columns.

<a id="f77"></a>

F77 · P1 · Content scanning selects content_policies.active although the schema uses enabled

Status: new. Scope: Compliance content-scanner component when enabled. Prerequisites: F01

Files and exact locations: services/mail-server/crates/compliance/src/content_scanner.rs:952.

Remaining defect: Loading policies queries WHERE active=true, but the canonical content_policies column is enabled. The error propagates from policy loading and prevents scans from evaluating stored policies.

Required changes:

Change the query to the canonical enabled predicate and confirm the selected name/rules DTO matches the canonical row.

Use canonical migration fixtures to seed enabled and disabled policies and exercise the actual scan entry point; do not suppress policy-store errors as an empty policy set.

Verification: An enabled policy must affect scan output and a disabled one must not. A policy-store outage must produce an explicit unavailable/deferred result.

Evidence: Canonical query execution fails with SQLSTATE 42703: active does not exist.

<a id="f78"></a>

F78 · P1 · Compliance overview fails against its required GDPR deadline column

Status: new. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/api-server/src/routes/admin/compliance_overview.rs:203; services/mail-server/crates/api-server/src/routes/admin/compliance_overview.rs:214.

Remaining defect: The overview checks that gdpr_requests exists, then queries sla_deadline twice. That column is absent from the canonical gdpr_requests model. The table exists on a fresh database, so the guard passes and the route propagates the SQL error instead of returning its overview.

Required changes:

Define one authoritative request deadline field and calculation policy, with creation, authorized extension and status transitions writing it. Add a canonical numbered migration/backfill and use that field in both overview queries.

If deadlines are deliberately derived, derive them from existing request timestamps through the shared calendar-aware policy rather than querying an invented column. Surface unknown legacy deadlines for reconciliation.

Test the overview against the canonical schema with no requests, an open request, an extended request and an overdue request.

Verification: The empty overview must succeed; overdue counts must agree with the request workflow across calendar boundaries and extensions.

Evidence: Canonical-schema preparation fails with 42703 for sla_deadline; route guard and error propagation inspected.

<a id="f83"></a>

F83 · P2 · Optional event compaction requires provider/region fields absent from canonical events

Status: new. Scope: Optional PostgreSQL analytics compaction; deployment enablement not established. Prerequisites: F01

Files and exact locations: services/mail-server/crates/analytics/src/compaction.rs:99.

Remaining defect: The compaction batch SELECT includes events.provider and events.region. Neither column exists on the canonical PostgreSQL events table, so compaction fails before writing a batch. The separate ClickHouse schema does not repair this PgPool query.

Required changes:

Align EventRow and the archival projection with the canonical event contract. Derive provider/region from validated metadata or add explicit canonical columns together with their producer/backfill if they are required.

Keep tenant/message/event identity and all promised archived fields complete; do not silently invent provider/region values. Test retention and restart behavior against the actual canonical schema.

Verification: Compact eligible canonical events, interrupt between archive and deletion, restart and verify one durable copy per event with all fields intact.

Evidence: Canonical-schema preparation fails with 42703 for provider.

<a id="f85"></a>

F85 · P2 · Optional campaign optimization has no canonical campaign_arms store

Status: new. Scope: Separate optional analytics helper; no production caller found. Prerequisites: F01

Files and exact locations: services/mail-server/crates/analytics/src/campaign_autopilot.rs:97; services/mail-server/crates/analytics/src/campaign_autopilot.rs:162.

Remaining defect: The optimization helper reads and updates campaign_arms, but no canonical migration or runtime initializer creates it. sales_campaigns has its own runtime initialization; that does not create the arm model.

Required changes:

Add the intended tenant-owned campaign/template arm schema with unique campaign/arm index, validated positive finite alpha/beta values, bounded counters and foreign keys to the actual campaign/template model.

Create arms through a production campaign workflow and feed idempotent outcome events to the updater. Check affected rows and use checked arm-index conversion.

Include component readiness and canonical create/select/update/restart tests; keep ownership verification and mutation within an appropriate transaction.

Verification: Create a two-arm campaign through its real producer, ingest outcomes once under replay, restart and obtain a report whose counters match those outcomes.

Evidence: Canonical-schema preparation returns 42P01; repository-wide schema searches found no campaign_arms initializer.

<a id="f86"></a>

F86 · P2 · The optional incident repository requires resolved_at and does not clear it on reopening

Status: new. Scope: Standalone IncidentRepo; no production caller found. Prerequisites: F01

Files and exact locations: services/mail-server/crates/apexmail-db/src/repos/incidents.rs:21; services/mail-server/crates/apexmail-db/src/repos/incidents.rs:40; services/mail-server/crates/apexmail-db/src/repos/incidents.rs:55; services/mail-server/crates/apexmail-db/src/repos/incidents.rs:89; services/mail-server/crates/apexmail-db/src/repos/incidents.rs:100.

Remaining defect: IncidentRepo reads/returns/updates status_page_incidents.resolved_at, absent from the canonical table. Even after adding it, the unresolved update branch changes status without clearing resolved_at, while list_active filters resolved_at IS NULL. Reopened incidents would remain invisible.

Required changes:

Add the canonical resolved_at timestamp with a deliberate backfill from existing status/history, or refactor the repository to the chosen canonical incident model consistently.

Make one typed state transition determine status and resolution timestamp. Reopening must clear the timestamp; callers must not supply contradictory status and resolved booleans.

Do not confuse this repository with the separate trust-portal incident relation. Wire and verify the model used by the deployed status page.

Verification: Create → resolve → reopen → list_active on canonical schema. The incident must reappear after reopening, with an auditable transition history.

Evidence: Multiple canonical queries fail with 42703; reopened-state predicate/update mismatch inspected.

<a id="f87"></a>

F87 · P2 · The optional warmup repository uses an ISP-profile shape for a per-pool schedule table

Status: new. Scope: Standalone WarmupRepo; no production caller found. Prerequisites: F01

Files and exact locations: services/mail-server/crates/apexmail-db/src/repos/warmup.rs:21; services/mail-server/crates/apexmail-db/src/repos/warmup.rs:40; services/mail-server/crates/apexmail-db/src/repos/warmup.rs:54; services/mail-server/crates/apexmail-db/src/repos/warmup.rs:65; services/mail-server/crates/apexmail-db/src/repos/warmup.rs:80.

Remaining defect: WarmupRepo expects isp_name, mx_patterns and warmup_schedule on isp_warmup_schedules. Canonical migrations instead define per-pool/day schedules with target/actual volume and status. All profile-oriented CRUD queries fail. The corrected admin warmup path uses the canonical execution model and is not the same defect.

Required changes:

Define a separate ISP warmup profile/catalog relation if that advertised profile capability is required, and keep per-pool daily execution rows in isp_warmup_schedules.

Update repository DTOs, constructors, producer and consumer joins to the two explicit models; add canonical migrations and ownership constraints for each.

Do not append unrelated nullable profile columns to execution rows merely to make SQL preparation pass.

Verification: Create an ISP profile, instantiate a pool schedule from it and record daily actuals. Both profile CRUD and admin execution views must round-trip on canonical migrations.

Evidence: Canonical-schema preparation fails with 42703 for isp_name/warmup_schedule.

<a id="f08"></a>

F08 · P1 · Invoice-address snapshots still fall back to mutable values field by field

Status: partial. Scope: Production code path. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/billing-service/src/accounting_export.rs:89; services/mail-server/crates/billing-service/src/accounting_export.rs:106; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1685.

Already repaired: Migration 132 adds state/email; invoice writers and exports now include an address snapshot.

Remaining defect: The new resolver uses the live address whenever an individual snapshot value is null, empty or missing. A valid issued snapshot with no address_line2 or VAT number therefore acquires a later account value on re-export. Malformed snapshot JSON is also silently replaced with live data.

Required changes:

Choose snapshot versus legacy live fallback once for the whole invoice, not separately for each field. When a valid snapshot exists, null/empty fields remain null/empty.

Add a versioned snapshot DTO and require its successful parsing for issued documents. Surface corrupt snapshots for repair; allow an explicit, labelled legacy fallback only for invoices that genuinely predate snapshotting.

Freeze every export-relevant identity field at issue time, including company/registry identity used by the export. Use the same snapshot contract in the API admin writer and Stripe importer.

Verification: Issue an invoice whose optional address/VAT fields are empty, edit those fields on the account, and export again: the historical values must be byte-for-byte unchanged.

Evidence: Source/control-flow review; service integration not executed.

<a id="f09"></a>

F09 · P1 · Payment recovery can still clear unrelated restrictions

Status: partial. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/migrations/133_abuse_reports_status.sql:28; services/mail-server/crates/billing-service/src/maintenance.rs:3270; services/mail-server/crates/api-server/src/routes/billing.rs:3982; services/mail-server/crates/api-server/src/routes/billing.rs:4003.

Already repaired: The missing abuse status column and constrained lifecycle labels now exist.

Remaining defect: Migration 133 labels every legacy report resolved without review evidence. Recovery then writes tenants.status=active whenever no open abuse row exists, including tenants independently suspended by an administrator or still pending verification. The manual reset also releases dunning_queued messages without its own abuse predicate. A status column plus a report check does not establish the cause of a tenant restriction.

Required changes:

Represent billing, administrative, verification and abuse restrictions independently, with actor/reason/timestamps. Derive effective send access from all applicable restrictions.

Clear only the billing restriction after confirmed recovery. Recompute tenant state and queued-message eligibility in the same transaction, preserving pending verification and administrative restrictions; apply the identical rule to manual reset.

Reconcile legacy reports conservatively: only evidence-backed reviewed cases become resolved. For already-applied migration 133, use a new reconciliation migration/job and review queue rather than rewriting migration checksums.

Wire abuse creation/review/resolution through authorized production callers and an audited state-transition function; a CHECK of allowed labels alone is not transition authorization.

Verification: Pay an invoice for an administratively suspended tenant, a pending tenant, and a tenant with an unresolved legacy abuse report: none may become eligible to send. A billing-only hold must recover.

Evidence: Source/control-flow review; service integration not executed.

<a id="f29"></a>

F29 · P1 · Existing-invoice recovery executes inside an aborted transaction

Status: partial. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/billing-service/src/overage.rs:540; services/mail-server/crates/billing-service/src/invoices.rs:160; services/mail-server/migrations/136_invoices_unique_overage_period.sql:1.

Already repaired: Advisory lock lifetime now covers invoice insertion; migration 136 adds period uniqueness.

Remaining defect: Invoice creation is now inside the lock transaction and a unique index exists. However, when INSERT raises 23505 the handler immediately SELECTs the existing invoice in that same transaction. PostgreSQL has already aborted it, so the recovery SELECT raises 25P02. Existing invoices not yet adopted by billing_periods can therefore block collection/sweeping.

Required changes:

Use INSERT ... ON CONFLICT on the exact intended invoice identity, with RETURNING plus an explicit existing-row fetch, or wrap invoice creation in a SAVEPOINT and roll back to it before recovery.

Do not reinterpret arbitrary unique violations (invoice number, external invoice ID, etc.) as a period replay. Check the constraint/operation identity and compare tenant, usage kind, period, amount and currency.

Atomically link the existing invoice to its billing period and ensure exactly one resumable collection operation. Reconcile legacy duplicates before strengthening the identity constraint.

Verification: Seed an existing period invoice without a billing_periods link and sweep it twice, including concurrent sweepers. It must adopt the one invoice without 25P02 or another collection.

Evidence: Database reproduction: duplicate period INSERT returns 23505; immediate recovery SELECT in the same transaction returns 25P02.

<a id="f32"></a>

F32 · P1 · Period pricing still reads mutable rates and defaults currency to EUR

Status: partial. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/billing-service/src/overage.rs:118; services/mail-server/crates/billing-service/src/overage.rs:373; services/mail-server/crates/billing-service/src/overage.rs:491; services/mail-server/crates/billing-service/src/overage.rs:533; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1248; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1278; services/mail-server/migrations/137_billing_periods.sql:1.

Already repaired: The immediate base-plan/override-plan mismatch was removed and an immutable period table was introduced.

Remaining defect: Plan and allowance selection are now aligned, but billing_periods.overage_rate_millicents and currency are not used by the sweep. Writers leave the rate unset and hardcode EUR; invoicing re-reads the current hardcoded plan rate. Seeded periods can have no allowance and fall back to current entitlements. A later price/override change can still alter a past period invoice.

Required changes:

At period creation/transition persist the complete effective pricing snapshot: allowance, integer rate, currency, applicable override/contract/version, tax context and metering boundary.

Select those fields into BillingPeriodRow and price exclusively from the snapshot. Pass its currency into CreateInvoiceInput and collection; reject unresolved snapshots for reconciliation instead of using today’s plan.

Backfill existing incomplete snapshots from historical authoritative records. Where history is unavailable, surface an explicit review state rather than inferring free/zero/current pricing.

Verification: Close a period, change the current plan rate/override/currency, then invoice the old period. Its amount/currency must be unchanged; missing historical pricing must produce a visible reconciliation failure.

Evidence: Source/control-flow review; service integration not executed.

<a id="f31"></a>

F31 · P1 · One bad period still aborts the sweep and unresolved work ages out

Status: partial. Scope: Production code path. Prerequisites: F29, F32

Files and exact locations: services/mail-server/crates/billing-service/src/overage.rs:118; services/mail-server/crates/billing-service/src/overage.rs:285; services/mail-server/crates/billing-service/src/overage.rs:292.

Already repaired: Completed periods are excluded in SQL and the fixed one-page scan was replaced with pagination.

Remaining defect: The new query excludes completed periods and paginates, but process_subscription_period(...).await? aborts the whole sweep on the first failing unresolved period. The same oldest failure is revisited next run, delaying every later period. The query also permanently excludes unresolved periods once they are over 40 days old. The (period_end,tenant_id) cursor is not a unique row ordering.

Required changes:

Persist per-period attempt/error/next-attempt state and isolate failures so other eligible periods progress. Use a complete keyset (period_end,tenant_id,id) or durable SKIP LOCKED claims.

Do not use raw-event retention as the expiry policy for unresolved financial work. Persist the metering watermark/aggregate needed to invoice and retain unresolved periods until explicitly reconciled.

Expose oldest-unresolved age and failed-period counts. Add a recovery command for periods that already crossed the old cutoff.

Verification: Seed 1,201 periods, a failing first row, zero-overage rows, tied cursor values and an unresolved >40-day row. Every healthy period must progress and the failed/old work must remain visible and retryable.

Evidence: Source/control-flow review; service integration not executed.

<a id="f72"></a>

F72 · P1 · Stripe invoice.paid infers a persisted invoice from a constant SELECT result

Status: new. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1496; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1525.

Remaining defect: The paid handler executes a modifying CTE ending in SELECT 1, then treats rows_affected > 0 as proof that an invoice was updated. PostgreSQL returns CommandComplete SELECT 1 even when the matched/marked invoice CTEs contain zero rows. Counting that result cannot distinguish a real update from a missing invoice, so the fallback import can be bypassed.

Required changes:

Return the actual marked/matched row count with SELECT COUNT(*)::bigint FROM marked and fetch_one/query_scalar, or fetch explicitly returned invoice identities. Never use the top-level constant SELECT command count as mutation evidence.

If no owned invoice matches, invoke the intended external-invoice reconciliation/import path with a unique Stripe invoice identity. Preserve local overage mappings from F34.

Add a real SQLx integration assertion for both zero matches and one match; keep CTE allocation and invoice-state transitions transactionally linked.

Verification: Process invoice.paid for an unknown Stripe invoice and then a known one. Each must persist exactly the intended invoice/allocation and replay without creating another logical invoice.

Evidence: Exact CTE returns one result row with zero invoices persisted; an independent PostgreSQL protocol probe returns CommandComplete SELECT 1. PGlite affectedRows is 0, showing adapter semantics differ. The SQLx branch consequence is source inference, not an executed Rust integration test.
Primary references: PostgreSQL protocol — CommandComplete counts SELECT rows retrieved.

<a id="f60"></a>

F60 · P2 · Crediting an unpaid invoice both cancels debt and creates spendable wallet value

Status: partial. Scope: Standalone credit-note service; no production caller found. Prerequisites: F01

Files and exact locations: services/mail-server/crates/billing-service/src/credit_notes.rs:160; services/mail-server/crates/billing-service/src/credit_notes.rs:314; services/mail-server/crates/billing-service/src/overage.rs:1079; services/mail-server/crates/billing-service/src/overage.rs:1332.

Already repaired: Migration 134, tenant/key replay lookup, replay ordering and currency checks were added.

Remaining defect: Credit-note creation permits unpaid pending/uncollectible invoices and credits the full amount to the wallet. Outstanding calculation separately subtracts the same credit note. A 20-unit credit on an unpaid 100-unit invoice therefore reduces debt to 80 and creates 20 spendable units: twice the intended economic benefit. Wallet application also ignores credit notes when deriving its initial amount to debit.

Required changes:

Split credit treatment into reduction of unpaid obligation and refund of previously settled value. Mint wallet/refund value only for the part actually paid and eligible for refund.

Link credit notes to invoice lines, payment/refund allocations and a unique operation. Lock and derive the remaining credit/refund capacity from that ledger in the same transaction.

Use a single outstanding-balance function in wallet application, Stripe collection, console, dunning and credit limits. Validate tenant/currency identity and prevent double application.

Verification: Test unpaid, partially paid and fully paid invoices. A 20-unit credit must produce exactly 20 units of benefit across debt reduction plus refunds, under replay and concurrent requests.

Evidence: Database statement reproduction: debt 10000→8000 and wallet increases by 2000 on an invoice with no payment. This reproduces the accounting transformations, not a live exposed endpoint.

<a id="f73"></a>

F73 · P1 · Stripe paid callbacks allocate the full invoice total instead of the confirmed payment

Status: new. Scope: Production code path. Prerequisites: F60, F72

Files and exact locations: services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1507; services/mail-server/migrations/140_invoice_payment_allocations.sql:1.

Remaining defect: The CTE records invoices.total as the Stripe allocation. It does not use the actual confirmed remaining payment. On a 100-unit invoice with 40 wallet units already allocated, a 60-unit Stripe payment records another 100 units. A zero-value paid invoice instead violates the allocation amount_cents > 0 CHECK and fails the callback.

Required changes:

Allocate the verified payment amount in the matching currency to the owned invoice, capped/validated against authoritative remaining obligation and the external payment identity.

Handle zero-value invoices as settled without inserting a positive payment allocation. Define legacy nullable totals through the canonical amount resolver.

Represent refunds, credits and wallet payments through the same balance model, retaining each independent payment identity and rejecting over-allocation instead of marking arbitrary totals paid.

Verification: Test zero-value settlement, wallet 40 + Stripe 60, replay, a mismatched currency and a refund. Allocations must total actual paid value and leave the correct balance.

Evidence: Executed zero-value callback CTE fails with SQLSTATE 23514. Partial-wallet over-allocation follows directly from SELECT total in the allocation INSERT.

<a id="f34"></a>

F34 · P1 · Stripe items still have no complete mapping to the original local invoice

Status: partial. Scope: Production code path. Prerequisites: F08, F32, F72, F73

Files and exact locations: services/mail-server/crates/billing-service/src/overage.rs:1172; services/mail-server/crates/billing-service/src/overage.rs:1501; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1496; services/mail-server/migrations/139_invoices_stripe_item_id.sql:1.

Already repaired: Migration 139 separates stripe_invoice_item_id from stripe_invoice_id.

Remaining defect: The ii_ identifier now has its own column, but creation still only posts a pending /invoiceitems entry. There is no explicit local-invoice → Stripe invoice/line mapping or finalization. invoice.paid matches stripe_invoice_id, which this path never sets. Final usage for a cancelled/PAYG customer can remain uncollected when no future subscription invoice occurs.

Required changes:

Create/finalize the intended Stripe invoice, or explicitly associate its line item with a known invoice; persist local invoice ID, external invoice/item IDs and confirmed payment identity.

Include immutable local operation identity in Stripe metadata and idempotency keys, including usage kind. Reconcile callbacks by the persisted mapping rather than creating an unrelated second local invoice.

Freeze the external operation amount/currency before issuing its idempotency key. Retries with a changed wallet balance must not reuse one Stripe key with different request parameters.

Provide an immediate final-usage collection path that does not rely on another renewal. Apply confirmed remaining amounts through the allocation ledger, together with F72/F73.

Verification: Create a 100-unit invoice, pay 40 from wallet and 60 through Stripe, cancel the subscription and replay callbacks. Exactly the original invoice must become settled; no second logical invoice or orphan item may remain.

Evidence: Source/control-flow review; service integration not executed.

<a id="f71"></a>

F71 · P1 · Generic usage deduplication is a check-then-insert race

Status: new. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/billing-service/src/usage.rs:238; services/mail-server/crates/billing-service/src/usage.rs:260; services/mail-server/crates/billing-service/src/usage.rs:807.

Remaining defect: Usage checks whether an event ID exists before inserting, but metering_events is unique on (id,timestamp), not on logical operation ID. Two attempts can both see no event and insert the same ID at different timestamps, counting usage twice. The send ledger reduces this for its own callers; it does not establish uniqueness for the generic usage path or coordinate all Redis/DB retry stages.

Required changes:

Claim a globally unique logical usage operation in a canonical ledger before applying quota/billing effects. Bind the operation to tenant, kind and immutable payload; reject reuse with different content.

Use an immutable original timestamp and an atomic insertion/deduplication contract appropriate for the partitioned event table. Coordinate Redis counters and durable recording with an idempotent outbox/reconciliation operation.

Use this shared operation API for generic metering and send reservations, retaining the send-specific claim ordering repaired under F22.

Verification: Race two identical logical operations with different arrival times, inject Redis/DB failures between stages and retry after restart. One logical operation must produce one billable quantity and one quota change.

Evidence: Executed statement interleaving: both existence checks return false, then two different timestamps permit two rows and quantity 2. This is not a two-session Rust concurrency test.

<a id="f33"></a>

F33 · P1 · Collection can overstate debt, has no exclusive owner, and marks failed work done

Status: partial. Scope: Production code path. Prerequisites: F29, F31, F32, F34, F60, F71, F72, F73

Files and exact locations: services/mail-server/crates/billing-service/src/overage.rs:1121; services/mail-server/crates/billing-service/src/overage.rs:1133; services/mail-server/crates/billing-service/src/overage.rs:1185; services/mail-server/crates/billing-service/src/overage.rs:1247; services/mail-server/crates/billing-service/src/overage.rs:1417; services/mail-server/crates/billing-service/src/overage.rs:1461; services/mail-server/crates/billing-service/src/overage.rs:1475.

Already repaired: Collection outbox, checked commits and invoice payment allocations were added; external calls moved outside the wallet lock.

Remaining defect: Claiming accepts pending and in_progress rows without an owner lease; claim failure only logs and collection proceeds. An outstanding-query error falls back to total minus this attempt’s wallet debit, ignoring prior payments/credits. Stripe failure is converted to None, then finalize_collection marks the outbox done and writes dunning_events only. No producer/consumer was found that turns dunning_entered into the dunning_records work the retry jobs actually read.

Required changes:

Make claiming return an acquired owner/lease or stop. Fence every collection transition by that owner; give stale owners a safe reclaim path and backoff/dead-letter handling.

Treat an unavailable authoritative balance as retryable failure. Never initiate an external amount from a fallback total. Have wallet application use the same credited/outstanding balance and invoice currency.

Only mark an outbox operation done after confirmed settlement or a committed handoff to an actual durable retry/dunning operation. Insert/update dunning_records (or an explicitly consumed invoice collection job) transactionally with the handoff.

Propagate Stripe, database and commit errors. Verify affected counts, preserve pending work after any failure, and expose exhausted attempts rather than silently omitting rows after the attempt cap.

Verification: Inject failures after claim, wallet debit, external item creation, local ID persistence and finalize. Restart two collectors. Verify one external operation, correct remaining amount, and durable retry or settlement in every case.

Evidence: Source/control-flow review; service integration not executed.

<a id="f36"></a>

F36 · P1 · Subscription updates still accept stale state across the new entitlement lock

Status: partial. Scope: Production code path. Prerequisites: F32

Files and exact locations: services/mail-server/crates/billing-service/src/stripe_webhooks.rs:787; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:893; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:928; services/mail-server/crates/billing-service/src/stripe_webhooks.rs:969.

Already repaired: The old-subscription deletion path now uses the tenant transaction and reconciles remaining active/trialing subscriptions.

Remaining defect: Deleting an old subscription now reconciles the remaining one. However, handle_subscription_change reads and validates current_subscription before acquiring the tenant lock, then cancels other active rows and applies its event unconditionally. A delayed active update can pass validation against an earlier snapshot, wait while a replacement commits, then restore the old subscription and cancel the new one. Same-status older price/period updates also have no ordering guard.

Required changes:

Read/lock current subscription and tenant entitlement state inside the same transaction after acquiring the tenant lock. Recheck ownership and permitted transition against that state.

Persist an event/version ordering watermark or reconcile against authoritative current Stripe subscription state before applying stale-sensitive fields. Define same-timestamp ordering/replay behavior.

Cancel a superseded subscription only after proving the incoming event represents the current replacement. Snapshot closing periods from the locked state and recompute entitlement from the surviving authoritative subscriptions.

Verification: Pause update A after its initial read; process replacement B; resume A. B must remain entitled. Also replay an older same-status plan/period update after an upgrade and verify it cannot downgrade or rewind the cycle.

Evidence: Source/control-flow review; service integration not executed.

<a id="f18"></a>

F18 · P1 · Dispatch still fails open on tenant restrictions and recovery access is overbroadly denied

Status: partial. Scope: Production code path. Prerequisites: F09

Files and exact locations: services/mail-server/crates/worker-processors/src/email/processor.rs:1702; services/mail-server/crates/api-server/src/middleware/auth.rs:983; services/mail-server/crates/api-server/src/routes/admin/tenants.rs:348.

Already repaired: API, SSR and SMTP user authentication gained active-tenant checks; control-plane updates invalidate the API status cache.

Remaining defect: API/SSR authentication now rejects non-active tenants, but worker tenant_suspended returns false for a database error, missing tenant or empty ID and only blocks the literal suspended status. Its independent 30-second allow cache is not invalidated by the API. Conversely, the blanket authentication gate prevents a suspended customer from using authenticated billing recovery operations.

Required changes:

Use one explicit tenant policy result: Allowed, Restricted(reason), or TemporarilyUnavailable. Only a confirmed active/eligible tenant may reach the external transport; lookup failures defer the job and exit dispatch.

Eliminate cached allow decisions at dispatch or add a reliable tenant policy version/invalidation mechanism with missed-event recovery. Do not treat pending/unknown as permitted.

Separate authentication from operation authorization. Define a narrow recovery allowlist for viewing invoices, updating payment methods and entering the billing portal, while keeping send/key/domain mutations blocked. Integrate independent holds from F09.

Verification: Prime a worker allow decision, suspend on another instance and dispatch immediately. Repeat with unavailable DB, missing tenant and pending status. Assert no external send; only the explicitly allowed recovery operations remain accessible.

Evidence: Source/control-flow review; service integration not executed.

<a id="f19"></a>

F19 · P1 · Oversized idempotent requests lose their body and payload binding

Status: partial. Scope: Production code path. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/api-server/src/middleware/idempotency.rs:36; services/mail-server/crates/api-server/src/middleware/idempotency.rs:120; services/mail-server/crates/api-server/src/middleware/idempotency.rs:308; services/mail-server/crates/api-server/src/app.rs:720.

Already repaired: Method/route/principal binding and normal-sized payload hashes were added.

Remaining defect: The middleware buffers only 1 MiB. On overflow/read failure it rebuilds an EMPTY body and stores no payload hash. replay_verdict compares hashes only when both are present, so a different oversized request can replay a prior success under the same key. On a cache miss the handler receives an empty body. The overall API accepts larger requests.

Required changes:

Buffer/hash the entire request within the actual route body limit, preserving the bytes for the downstream extractor. Return 413 on size overflow and an explicit error on body-read failure; never proceed with an empty replacement.

Require all replay identity dimensions, including the payload hash, to match. Treat old unbound cache entries as misses requiring authoritative ledger validation.

Choose and document one normalization contract for both Redis and durable-ledger hashes. Keep method, route, tenant and principal binding; do not weaken matching when any dimension is absent.

Verification: Send a valid >1 MiB message with an idempotency key, retry it, and retry a different >1 MiB body under that key. Expect normal acceptance/replay for the same request and 409 for the conflict. Exceed the actual body limit and expect 413 before mutation.

Evidence: Source/control-flow review; service integration not executed.

<a id="f21"></a>

F21 · P1 · Request cancellation can leave the Redis idempotency lease renewing forever

Status: partial. Scope: Production code path. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/api-server/src/middleware/idempotency.rs:230; services/mail-server/crates/api-server/src/middleware/idempotency.rs:447; services/mail-server/crates/api-server/src/app.rs:724.

Already repaired: Random owner tokens, conditional Redis transitions and periodic renewal were added.

Remaining defect: The renewal task is aborted only after next.run(req).await returns. The outer 30-second TimeoutLayer can drop that middleware future first. Dropping its JoinHandle detaches the renewal task, which can keep refreshing the in-flight key indefinitely and make retries return 409 until process restart or manual cleanup.

Required changes:

Wrap the spawned renewal handle in an abort-on-drop guard and share a cancellation token with the renewer. Tie its lifetime to the request/operation owner, not merely the normal return path.

Use owner-conditional cleanup on every exit, including timeout/cancellation. Keep the durable ledger authoritative when the original transaction may have committed before cancellation.

Bound renewal lifetime independently and record lease age so an abnormal request cannot renew indefinitely.

Verification: Force the handler beyond the outer timeout and separately drop the client/request future. Verify renewal stops, the lease expires or is owner-safely released, and a retry resolves through the durable ledger.

Evidence: Source/control-flow review; service integration not executed.

<a id="f20"></a>

F20 · P1 · Durable send replay changes the response envelope and can swallow ledger failures

Status: partial. Scope: Production code path. Prerequisites: F01, F19, F21

Files and exact locations: services/mail-server/crates/api-server/src/routes/messages.rs:979; services/mail-server/crates/api-server/src/routes/messages.rs:1529; services/mail-server/crates/api-server/src/routes/messages.rs:1552; services/mail-server/crates/api-server/src/routes/messages.rs:1556; services/mail-server/crates/api-server/src/routes/messages.rs:1867; services/mail-server/crates/api-server/src/routes/messages.rs:1898.

Already repaired: A transactionally linked durable batch/single ledger, payload identity and stable item IDs now exist.

Remaining defect: First responses use ApiResponse {data,error}; the durable ledger stores only MessageResponse/BatchSendResponse and replay emits that JSON directly. Redis loss/eviction therefore changes a successful response shape and breaks SDK deserialization. complete_ledger_in_tx logs SQL errors or zero-row fenced completion and returns success; a failed SQL statement can leave the enclosing transaction aborted while later code continues toward a success response.

Required changes:

Construct and serialize the complete final HTTP response envelope once. Persist its body/status and replay the same contract for single and batch sends, independently of Redis and client response consumption.

Return Result from complete_ledger_in_tx; require exactly one owner-fenced row to complete. Propagate SQL/ownership errors and roll back message/queue writes, with the appropriate idempotent quota compensation.

Reject corrupt persisted response bodies explicitly rather than synthesizing a success. Add response schema versioning if compatibility with already-written unwrapped ledger rows is needed.

Verification: Accept a single and batch send, lose the response, disable Redis and retry: status/body/IDs must match the first response. Inject ledger-completion SQL failure and verify no accepted-but-absent message or orphan quota remains.

Evidence: Source/control-flow review; service integration not executed.

<a id="f55"></a>

F55 · P1 · A failed consent recheck requeues the job and then continues sending

Status: partial. Scope: Production code path. Prerequisites: F18

Files and exact locations: services/mail-server/crates/worker-processors/src/email/processor.rs:1566; services/mail-server/crates/worker-processors/src/email/processor.rs:1736; services/mail-server/crates/worker-processors/src/email/processor.rs:1757; services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs:649.

Already repaired: Cached negative results were removed and a dispatch-time authoritative recheck was added; consent changes are published.

Remaining defect: current_suppression_reason catches a database error, requeues the job, and returns Ok(None). The caller interprets None as permission to continue into transport. The message can therefore send during a consent lookup failure while its row is already retryable. Positive suppression cache entries can also terminalize a recently resubscribed job before the authoritative recheck. Category preferences are persisted/published, but no worker consumer or send-category enforcement was found.

Required changes:

Return an explicit Allowed/Suppressed/Deferred result or propagate a retryable error. After a successful requeue, immediately exit dispatch; never use None for both no suppression and failed verification.

Recheck authoritative consent before any cached positive decision permanently suppresses a job, or implement reliable versioned invalidation covering unsubscribe, resubscribe and missed notifications.

Carry a validated server-owned message category through enqueue and dispatch, and enforce subscription_preferences together with global suppression. Define transactional/service-message exemptions explicitly rather than ignoring saved category choices.

Verification: Cause the consent SELECT to fail while requeue succeeds and spy on the transport: zero calls. Test cache-prime → unsubscribe/resubscribe on another replica, category opt-out and lost pub/sub notifications.

Evidence: Source/control-flow review; service integration not executed.

<a id="f65"></a>

F65 · P2 · Application request logs still include verification tokens

Status: partial. Scope: Production code path. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/api-server/src/middleware/request_logger.rs:222; services/mail-server/crates/api-server/src/middleware/request_logger.rs:239; services/mail-server/crates/api-server/src/app.rs:725; deploy/nginx/nginx.conf:27.

Already repaired: Nginx access-log redaction, no-referrer behavior and browser redirects were added.

Remaining defect: Nginx redacts the verification route and successful browser exchanges redirect to a clean URL. However, request_logger still logs req.uri().path() at INFO, including the raw token. The uncustomized outer TraceLayer also includes the full URI in its request span when that tracing level is enabled.

Required changes:

Use a shared route-normalization/redaction helper at every application logging boundary, preferably MatchedPath plus a safe fallback. Never put the raw token-bearing URI in a structured field or span.

Customize TraceLayer.make_span_with to use the same redacted route and approved correlation fields. Retain no-referrer and clean redirects; cover failure paths as well as success.

Extend the proxy map to every deployed token-bearing endpoint and test actual proxy/application log capture with a recognizable non-secret sentinel token.

Verification: Exercise valid, invalid, expired and malformed verification routes at INFO and DEBUG. The sentinel token must be absent from request_logger, TraceLayer, proxy access/error logs and follow-up referrers.

Evidence: Source/control-flow review; service integration not executed.

<a id="f74"></a>

F74 · P1 · SES attribution headers disagree with the sender and caller-controlled aliases can select another tenant

Status: new. Scope: SES-enabled sending and callbacks. Prerequisites: None beyond the stated canonical fixture/environment.

Files and exact locations: services/mail-server/crates/api-server/src/routes/ses_notifications.rs:624; services/mail-server/crates/api-server/src/routes/ses_notifications.rs:684; services/mail-server/crates/api-server/src/routes/ses_notifications.rs:785; services/mail-server/crates/api-server/src/routes/messages.rs:113; services/mail-server/crates/api-server/src/routes/messages.rs:617; services/mail-server/crates/worker-processors/src/email/processor.rs:1946; services/mail-server/crates/worker-processors/src/email/processor.rs:1970; services/mail-server/crates/worker-processors/src/email/processor.rs:2010; services/mail-server/crates/api-server/src/routes/ses_notifications.rs:715.

Remaining defect: The worker emits X-ApexMail-Message-ID and X-ApexMail-Tenant-ID. SES handlers use exact case-sensitive lookup of X-ApexMail-MessageId and X-ApexMail-TenantId, so normal outbound mail loses attribution. More seriously, the reserved-header lists block the hyphenated spellings but allow the legacy aliases. A caller-supplied TenantId alias is forwarded and then trusted by SES bounce/complaint handling as the tenant authority. A valid provider signature does not make caller-supplied message headers trustworthy.

Required changes:

Reserve the entire internal X-ApexMail-* namespace case-insensitively at every external submission boundary and again before transport. Generate internal identity headers exclusively from authenticated persisted job context.

Share canonical header constants and parse legitimate compatibility aliases case-insensitively, while rejecting ambiguous duplicate identity headers.

Resolve the provider message ID to the stored tenant/message/recipient delivery record. Verify ownership and callback recipient identity there; never authorize suppression, events or customer webhooks from raw email headers alone.

Backfill a durable provider-message mapping for outstanding sends and make missing/ambiguous mappings observable and retryable rather than silently misattributed.

Verification: Generate real outbound MIME and feed a signed SES fixture derived from it. Attribution must work. Submit legacy aliases, case variants, duplicates and another tenant’s ID through custom headers: none may affect another tenant.

Evidence: Header names, reserved-header validation, merge order and callback tenant use traced in source. No live cross-tenant request or external send performed.

<a id="f48"></a>

F48 · P1 · SDK fields now reach the API but still violate its delivery contract

Status: partial. Scope: Production code path. Prerequisites: F07, F19, F20, F74

Files and exact locations: services/mail-server/crates/api-server/src/routes/messages.rs:187; services/mail-server/crates/api-server/src/routes/messages.rs:580; packages/sdk-go/apexmail.go:870; packages/sdk-java/src/main/java/ee/apexmail/Emails.java:33; packages/sdk-php/src/Resources/Emails.php:179; packages/sdk-ruby/lib/apexmail.rb:519; packages/sdk-python/src/apexmail/resources/emails.py:339; services/mail-server/crates/api-server/src/app.rs:720; deploy/nginx/nginx.conf:90.

Already repaired: Reply-To, custom headers, attachments and additional options are serialized instead of silently discarded; unsupported templates are explicitly rejected.

Remaining defect: Go/Java expose priority as a string (Ruby/PHP document/pass string values), whereas the API requires an integer 1–10: supplied priorities now yield 422. SDK display-name strings are emitted but the API validates bare email strings, so named mailboxes are rejected. Python documents a sender dictionary but passes it directly to a regex expecting str. Template fields still deliberately return 422. The 25 MiB aggregate/10 MiB individual decoded attachment contract cannot fit through a 10 MiB JSON/proxy limit, even before the smaller F19 hashing limit.

Required changes:

Publish one authoritative OpenAPI/send schema and use common contract fixtures across all SDKs and API. Make priority an integer or map named priorities explicitly and consistently, preserving documented compatibility.

Implement structured mailbox parsing/validation and MIME rendering through persistence, EmailJob/PreparedEmail and both transports. In Python validate the extracted bare address rather than a dictionary or formatted display name.

Implement template sending with tenant ownership, chosen version, data validation and deterministic rendering before queue persistence. Persist the rendered snapshot/version for retries; do not resolve a mutable template again at dispatch.

Align decoded attachment, JSON/base64, route, middleware and proxy limits with a documented supported maximum. Keep reserved-header and attachment validation, and address F74’s trusted-header gap.

Verify every accepted option by both serialized request capture and delivered MIME; serializer-only tests are insufficient.

Verification: Across all five SDKs send priority, named From/To/Reply-To, template data, custom headers and boundary-sized attachments. Verify actual MIME/queue behavior and identical controlled errors for invalid inputs.

Evidence: Source/control-flow review; service integration not executed.

<a id="f26"></a>

F26 · P1 · Restored To/Cc values are serialized as one malformed mailbox

Status: partial. Scope: Production code path. Prerequisites: F48

Files and exact locations: services/mail-server/crates/api-server/src/routes/messages.rs:725; services/mail-server/crates/worker-processors/src/email/processor.rs:2616; services/mail-server/crates/worker-processors/src/email/transport.rs:390; services/mail-server/crates/worker-processors/src/email/transport.rs:689.

Already repaired: Original visible addressing is now retained on queue copies, separately from their envelope destinations.

Remaining defect: mime_headers_for joins To/Cc into strings, which both transports pass to MessageBuilder.to/cc as &str. In pinned mail-builder 0.3.2, From<&str> creates one EmailAddress and wraps the whole string in angle brackets. Two recipients become a form such as <a@example.com, b@example.com>, rather than two mailbox entries.

Required changes:

Persist structured mailbox arrays for visible To and Cc; keep the single-recipient envelope destination separate. Backfill or explicitly parse the legacy comma-joined representation.

Carry those arrays through EmailJob/PreparedEmail and call mail_builder::headers::address::Address::new_list or the Vec conversion in both SMTP and SES MIME construction.

Use the same structured mailbox model for display names, Reply-To and logical Message-ID preservation; Bcc must remain exclusively in envelope data.

Verification: Build real MIME using mail-builder 0.3.2 for two To, two Cc and one Bcc recipients. Parse it with an independent MIME parser, assert exact visible mailbox lists, no Bcc header, and one intended envelope destination per copy.

Evidence: Source contract verified against mail-builder commit c2b37e978853923bcac573f422fc013613746a62 (v0.3.2), address.rs From<&str>/EmailAddress::write_header. Rust MIME execution was unavailable.
Primary references: mail-builder 0.3.2 Address conversions (pinned source).

<a id="f13"></a>

F13 · P2 · Signed originating-message attribution exists but is not connected to outgoing mail

Status: partial. Scope: Outgoing attribution integration; standalone codec is repaired. Prerequisites: F26, F48

Files and exact locations: services/mail-server/crates/tracking-service/src/codec.rs:216; services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs:804; services/mail-server/crates/worker-processors/src/email/tracking.rs:1.

Already repaired: Legacy recipient-array lookup, id::text, tenant predicate, unknown marker and v2 parsing/generation were implemented.

Remaining defect: The old nonexistent-column/UUID query is fixed, and a v2 token can carry message identity. Repository-wide call-site inspection found that generator used only in tests. No production outgoing-mail caller creates those tokens, so the intended deterministic attribution is not delivered by the new codec. Legacy latest-message lookup can associate an old link with a newer message to the same recipient.

Required changes:

Integrate generate_unsubscribe_token_with_message, or a shared compatible codec, into the actual outgoing campaign/broadcast pipeline with server-owned tenant, originating message and envelope recipient identity.

Persist that identity with the outgoing message and use it for List-Unsubscribe and visible preference/unsubscribe links. Keep legacy decoding and its explicit unknown fallback for old links.

Do not make suppression persistence depend on successful attribution. Keep the separate sales-autopilot unsubscribe format explicit until it is deliberately unified.

Verification: Send two messages to one recipient and activate the first message’s link after the second send: the event must name the first message. Cover both production transports and an old legacy link.

Evidence: Canonical fallback SQL inspected; all v2 generator call sites outside its definition/documentation are under tests. No deployed transport execution performed.

<a id="f25"></a>

F25 · P1 · Parent message progress is reconciled only on successful recipients

Status: partial. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/worker-processors/src/email/processor.rs:2206; services/mail-server/crates/worker-processors/src/email/processor.rs:2281; services/mail-server/crates/worker-processors/src/email/processor.rs:2379; services/mail-server/crates/worker-processors/src/email/processor.rs:2453; services/mail-server/crates/worker-processors/src/email/processor.rs:2502.

Already repaired: Scheduled parents can enter processing; success aggregation and sent_at were added.

Remaining defect: Scheduled → processing and successful-recipient aggregation were repaired, but suppression, hard bounce, exhausted retry and permanent rejection do not call the same parent reconciliation. A message whose recipients all fail or are suppressed can remain processing indefinitely. Mixed terminal outcomes can also leave a stale partial state.

Required changes:

Run a single tenant/message-scoped progress function after every durable recipient transition, including suppression, bounce, terminal error, cancellation and delivery feedback.

Define parent state from all recipient records and distinguish provider acceptance from confirmed delivery. Persist timestamps for their actual events and make reconciliation safe under concurrent child completions.

Add a restart reconciliation job for parents whose child rows are all terminal but whose aggregate status is not. Coordinate the SES repair in F75 with this same model.

Verification: Exercise all-failed, all-suppressed, mixed success/bounce, scheduled retry and concurrently finishing recipients. Each parent must reach the documented terminal/partial state without depending on a later successful send.

Evidence: Source/control-flow review; service integration not executed.

<a id="f75"></a>

F75 · P1 · SES delivery persistence writes a missing column and bypasses recipient aggregation

Status: new. Scope: SES-enabled delivery callbacks. Prerequisites: F25, F74

Files and exact locations: services/mail-server/crates/api-server/src/routes/ses_notifications.rs:902; services/mail-server/crates/worker-processors/src/email/processor.rs:2206.

Remaining defect: Delivery callbacks UPDATE messages.delivered_at, which is absent in the canonical schema. Errors are logged while SNS is acknowledged, losing the status update. Setting the whole parent delivered for one recipient also bypasses the recipient aggregation that multi-recipient messages require.

Required changes:

Persist delivery confirmation on the matching recipient delivery record using a canonical timestamp field/migration and the trusted mapping from F74.

Call the shared parent reconciliation from F25 after every confirmed recipient transition. If a parent delivered_at is required, define its aggregate meaning and add the canonical column/writer contract explicitly.

Commit callback state/events or a durable processing job before acknowledging success. Database failures must trigger safe retry, with event deduplication preventing duplicate effects.

Verification: Use a two-recipient message, deliver one then bounce the other, and replay both callbacks. Assert the documented aggregate state and timestamps. A transient DB failure must not permanently lose the callback.

Evidence: Exact canonical UPDATE reproduced PostgreSQL 42703: messages.delivered_at does not exist.

<a id="f04"></a>

F04 · P1 · The console outstanding balance still ignores confirmed allocations and credits

Status: partial. Scope: Production code path. Prerequisites: F60, F73

Files and exact locations: services/mail-server/crates/api-server/src/routes/web/data.rs:1813; services/mail-server/crates/api-server/src/routes/web/data.rs:1820.

Already repaired: Canonical invoice list fields, status handling and currency grouping were corrected.

Remaining defect: The invoice list now uses the right canonical columns, but its outstanding summary still sums full invoice totals. A 100-unit invoice with 40 units already paid from the wallet is shown as 100 outstanding instead of 60. The new allocation ledger exists but this query does not consult it.

Required changes:

Replace this SUM with the shared authoritative invoice balance: invoice obligation minus valid payment allocations and applicable credits/refunds, using the accounting model repaired by F60/F73.

Aggregate the entire eligible invoice set, independently of list pagination, and keep distinct currency buckets. Propagate an unavailable balance instead of displaying zero.

Verification: Create a 100-unit invoice, allocate 40 wallet units and issue an eligible credit. The console, API, collector and dunning service must agree on the remaining amount before and after Stripe settlement.

Evidence: Exact console SQL on canonical fixtures returns 10000; allocation-aware SQL returns 6000.

<a id="f14"></a>

F14 · P1 · Required missing-schema failures are still rendered as empty console data

Status: partial. Scope: Production code path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/api-server/src/routes/web/data.rs:115; services/mail-server/crates/api-server/src/routes/web/data.rs:198.

Already repaired: Most other database failures now have a typed Unavailable state.

Remaining defect: load_query treats every undefined-table/undefined-column error (42P01/42703) as a successful default value. The same helper handles required financial and operational datasets. A misdeployed invoices or api_keys schema can therefore still display an empty state or zero.

Required changes:

Make optionality an explicit property of each dataset, tied to a disabled optional component. Required datasets must map every query/decoding error, including 42P01/42703, to Unavailable.

Preserve query identity and correlation ID through KPI/list rendering. Never call into_value_or_default without carrying the unavailable flag to the view.

Add required-schema readiness checks so missing production columns fail deployment before a page supplies fabricated empty data.

Verification: Drop a required column in an isolated canonical test DB, request the page and assert an unavailable indication and correlation ID. A deliberately disabled optional component may show a labelled unavailable/not-enabled state.

Evidence: Source/control-flow review; service integration not executed.

<a id="f42"></a>

F42 · P1 · Standard SCIM PATCH bodies are rejected and concurrent patches can undo deactivation

Status: partial. Scope: Production code path. Prerequisites: F01, F18

Files and exact locations: services/mail-server/crates/api-server/src/routes/scim.rs:701; services/mail-server/crates/api-server/src/routes/scim.rs:1090; services/mail-server/crates/api-server/src/routes/scim.rs:1118; services/mail-server/crates/api-server/src/routes/scim.rs:501; services/mail-server/crates/api-server/src/routes/scim.rs:1509.

Already repaired: Bounded User filter parsing, User PATCH operations and normalized pagination were implemented.

Remaining defect: ScimPatchRequest denies unknown fields but declares only Operations. A normal RFC 7644 PATCH includes schemas, so User and Group PATCH reject it before applying any operation. Separately, User PATCH reads the current row outside a transaction, folds changes onto that snapshot and writes every field; a concurrent name-only patch can restore active=true after a deactivation.

Required changes:

Add and validate schemas containing urn:ietf:params:scim:api:messages:2.0 to the request DTO shared by both PATCH handlers. Include that field in real IdP fixtures.

Validate the complete operation list, then lock/read/apply the user under one transaction, or emit a parameterized UPDATE that changes only fields explicitly supplied. Preserve omitted fields under concurrent requests.

Return SCIM-formatted errors/content types and align ServiceProviderConfig with tested filtering/PATCH behavior. Keep User/Group ownership and member authorization checks.

Verification: Run User and Group PATCH with the RFC schemas field. Race name-only PATCH against active=false: the resulting account must stay inactive. Invalid multi-operation patches must leave no partial change.

Evidence: DTO and read/modify/write control flow inspected. RFC 7644 §3.5.2 requires the PatchOp schemas attribute; full IdP integration not executed.
Primary references: RFC 7644 §3.5.2 — Modifying with PATCH.

<a id="f61"></a>

F61 · P2 · The standalone entitlement response still disagrees with enforced limits

Status: partial. Scope: Standalone entitlement helper; no production caller found. Prerequisites: F32, F48, F71

Files and exact locations: services/mail-server/crates/compliance/src/entitlements.rs:150; services/mail-server/crates/compliance/src/entitlements.rs:190; services/mail-server/crates/compliance/src/entitlements.rs:255; services/mail-server/crates/compliance/src/entitlements.rs:265; services/mail-server/crates/api-server/src/routes/messages.rs:48.

Already repaired: Missing contract/discount joins were replaced with canonical billing relations.

Remaining defect: The helper now uses existing billing tables, but current_usage is calendar-month usage while quota enforcement can use subscription billing-cycle boundaries. It also hardcodes batch/attachment limits that differ from the send API (e.g. Developer batch 500 versus the API default 100; higher-plan attachment values exceed accepted HTTP bodies). Feature keys and fallback values form another parallel entitlement model.

Required changes:

Use the shared effective-entitlement resolver and the same billing-cycle window/usage aggregation as enforcement.

Expose batch, attachment, retention, domain and feature limits from one versioned plan contract; remove independent hardcoded ladders. If a higher-plan feature is advertised, implement its actual enforcement/transport capacity.

Add parity tests across API, console, quota and this response for free, paid, overridden, expired and restricted tenants.

Verification: A tenant whose cycle starts on the 15th must receive the same usage/remaining amount from enforcement and this helper. Every displayed limit must accept its exact boundary and reject boundary+1 consistently.

Evidence: Source/control-flow review; service integration not executed.

<a id="f62"></a>

F62 · P2 · Stored-template cache omits an option that changes output

Status: partial. Scope: Stored-template renderer; source-only HTTP rendering is a separate path. Prerequisites: F01

Files and exact locations: services/mail-server/crates/template-renderer/src/renderer.rs:82; services/mail-server/crates/template-renderer/src/renderer.rs:310; services/mail-server/crates/template-renderer/src/renderer.rs:346.

Already repaired: Canonical template/version repository, tenant ownership and content/version cache identity were implemented.

Remaining defect: Stored rendering now uses canonical templates and tenant IDs, but missing_field_fallback affects rendering and is absent from stored_render_cache_key. Otherwise identical requests with different fallback strings return the first cached output. The plaintext override also needs metadata recomputed after replacing generated text.

Required changes:

Serialize/hash a versioned structure containing every output-affecting RenderOptions field, including missing_field_fallback, rather than maintaining an incomplete positional key.

Preserve tenant/template/version/content stamp binding. Recompute plaintext_size_bytes and other derived metadata after selecting the final stored/plaintext body.

Verification: Warm the cache with an unresolved merge field and fallback A, then render with fallback B; both results must match an uncached render and their final metadata.

Evidence: Source/control-flow review; service integration not executed.

<a id="f67"></a>

F67 · P2 · Reply analytics persistence is repaired but has no production ingestion caller

Status: partial. Scope: Separate analytics component; no production caller found. Prerequisites: F01

Files and exact locations: services/mail-server/crates/analytics/src/reply_tracking.rs:190; services/mail-server/migrations/159_reply_events_canonical.sql:1; services/mail-server/crates/worker-processors/src/reply_handler/processor.rs:1.

Already repaired: Canonical schema, ID types, idempotent storage, average decoding, cache window identity and bounded tenant-scoped thread lookup were added.

Remaining defect: Migration 159 and process_reply now implement a real, replay-safe reply_events model. However, ReplyTrackingService/process_reply are instantiated/called only in tests. The separate inbound reply processor does not hand its events to this model, so real replies do not populate these metrics through any caller found in the repository.

Required changes:

Add an adapter from authenticated inbound reply ingestion to a durable reply-analytics operation, with tenant, canonical message, recipient and a stable provider/inbound event ID.

Commit the analytics handoff with inbound acceptance, then retry idempotently through restart. Wire thread lookup/cache generation invalidation through the existing service.

Expose readiness/lag and an explicit unavailable/no-events state. Keep this integration separate from merely creating the table.

Verification: Ingest a real inbound fixture through the production entry point, retry it and restart before consumption. Exactly one reply event must appear and metrics must update only for its tenant.

Evidence: Source/control-flow review; service integration not executed.

<a id="f79"></a>

F79 · P2 · Activation analytics uses invalid nested aggregates and reports zero on failure

Status: new. Scope: Production code path. Prerequisites: F25

Files and exact locations: services/mail-server/crates/api-server/src/routes/admin/growth_analytics.rs:361; services/mail-server/crates/api-server/src/routes/admin/growth_analytics.rs:639.

Remaining defect: Both time-to-first-email queries calculate AVG(...MIN(m.created_at)...), nesting aggregate calls at the same query level. PostgreSQL rejects this with 42803, and the fallback renders zero instead of unavailable. Queuing created_at also needs an explicit decision if the metric is advertised as first actual send.

Required changes:

Compute one first-send timestamp per tenant in a subquery/CTE, then average the tenant deltas in the outer SELECT; use a typed floating result.

Use the event/status/timestamp that matches the product metric, and distinguish never-sent tenants from zero elapsed time.

Propagate query errors as unavailable instead of a numerical zero and share the corrected query across both endpoints.

Verification: Seed two tenants with different first-send delays and multiple messages. Verify the exact expected average, no-message behavior and explicit error state.

Evidence: Exact aggregate expression fails with SQLSTATE 42803 on canonical PostgreSQL.

<a id="f81"></a>

F81 · P2 · Optional tax reports use stale rates and treat all revenue/costs as domestic VAT

Status: new. Scope: Optional/standalone statutory report helpers; no filing performed. Prerequisites: F08, F32

Files and exact locations: services/mail-server/crates/compliance/src/financial_analytics.rs:19; services/mail-server/crates/compliance/src/estonia_ou.rs:57; services/mail-server/crates/compliance/src/estonia_ou.rs:59; services/mail-server/crates/compliance/src/estonia_ou.rs:1021; services/mail-server/crates/compliance/src/estonia_ou.rs:1234; services/mail-server/crates/compliance/src/estonia_ou.rs:1249.

Remaining defect: Financial analytics fixes VAT at 20%; the Estonia helper retains 20% wage/dividend assumptions and a universal 2% pension rate. Current official 2026 values include 22% withheld income tax, corporate income tax of 22/78 and personal pension choices of 2/4/6%. Standard VAT is 24% from July 2025. Separately, the VAT declaration sums revenue across currencies, treats it all as domestic taxable sales, and assumes every operating cost produces 24% deductible input VAT.

Required changes:

Use a single versioned, date-effective tax policy with qualified accounting review. For net dividend distributions use the applicable net-to-tax fraction; merely changing 0.20 to 0.22 is not sufficient.

Record employee-specific pension participation/rate, exemption and insurance eligibility inputs. Calculate by the applicable payment period rather than one permanent constant.

Build VAT returns from actual invoice/tax snapshots and eligible input-tax records, with currency conversion provenance, reverse-charge/exempt/zero-rated classifications and correction history.

Keep missing source data explicit and prevent an incomplete generated report from being presented as a ready statutory filing. Implement the advertised workflow rather than hiding it.

Verification: Use approved reference fixtures across the July 2025 and 2026 boundaries, pension choices, reverse charge, exempt expenses and foreign currency. Reconcile each return box to source records.

Evidence: Current code compared with Estonian Tax and Customs Board official tax-rate pages retrieved on 2026-09-10. This is a software calculation finding, not certification of the company’s tax position.
Primary references: Estonian Tax and Customs Board — 2026 tax rates, Estonian Tax and Customs Board — July 2025 VAT change.

<a id="f80"></a>

F80 · P2 · Standalone financial analytics uses nonexistent invoice fields, wrong month windows and fabricated totals

Status: new. Scope: Standalone compliance reporting helper; no production caller found. Prerequisites: F04, F32, F60, F73, F81

Files and exact locations: services/mail-server/crates/compliance/src/financial_analytics.rs:245; services/mail-server/crates/compliance/src/financial_analytics.rs:267; services/mail-server/crates/compliance/src/financial_analytics.rs:305; services/mail-server/crates/compliance/src/financial_analytics.rs:576; services/mail-server/crates/compliance/src/financial_analytics.rs:601; services/mail-server/crates/compliance/src/financial_analytics.rs:620.

Remaining defect: The dynamic invoice query still hardcodes amount_cents and issue_date, neither present on canonical invoices, despite inspecting other columns. Query errors become empty/zero reports. Monthly ranges use 30/31/32-day arithmetic and can cover two months or repeat/skip labels. USD/GBP nominal amounts are added into total_revenue_eur without conversion, and subscription/usage/one-time values are invented as 85%/10%/5% of the total.

Required changes:

Use canonical total/subtotal/issued_at/due_at and the authoritative payment/credit model. Remove broad unwrap_or_default financial fallbacks; unavailable data must be visible.

Construct exact [month_start,next_month_start) boundaries with calendar-month arithmetic; subtract months from the month start, not 30 days from today.

Categorize actual invoice line items and maintain per-currency totals. If a reporting currency is required, persist the source/rate/date of conversion instead of adding nominal amounts.

Use invoice tax snapshots for VAT analysis together with F81. Add fixtures that would make zero/fixed-percentage reports obviously incorrect.

Verification: Use January/February/leap-year boundaries, invoices exactly at midnight, two currencies and known line categories. Totals and classifications must reconcile to the ledger without overlap.

Evidence: Static query/schema comparison, error fallback and date/currency/category arithmetic inspected. The standalone Rust report was not run.

<a id="f82"></a>

F82 · P2 · Subject export skips canonical invoices because it searches a nonexistent customer_email

Status: new. Scope: Compliance subject-export component when enabled. Prerequisites: F08

Files and exact locations: services/mail-server/crates/compliance/src/gdpr_automation.rs:632; services/mail-server/crates/billing-service/src/accounting_export.rs:89.

Remaining defect: The subject export queries invoices.customer_email, absent from canonical invoices, then classifies the undefined-column error as a missing/skipped store. Invoices can contain the subject email in billing_address_snapshot and therefore exist despite being omitted from this export.

Required changes:

Resolve subject-owned invoice identity using the canonical immutable billing snapshot and the actual customer/tenant identity relation. Keep the tenant predicate and the intended export redaction policy.

Do not classify schema errors in a required implemented store as an optional missing store. Return a visible incomplete export and retain retry work until required data is included.

Apply the same explicit identity mapping to the export/erasure inventory while preserving legitimately retained financial records and approved redaction behavior.

Verification: Issue an invoice containing the subject’s snapshot email, change the live billing address and request the export. The relevant invoice must still be included or explicitly accounted for by the documented retention policy.

Evidence: Canonical-schema query preparation returns 42703 for customer_email; skipped-store error handling and snapshot writer inspected.

<a id="f84"></a>

F84 · P2 · Optional placement analytics queries a missing domain and equates delivery with inbox placement

Status: new. Scope: Separate analytics helper; no production caller found. Prerequisites: F75

Files and exact locations: services/mail-server/crates/analytics/src/inbox_placement.rs:46.

Remaining defect: This PgPool query uses events.recipient_domain, absent from canonical PostgreSQL events. Its classification is also conceptually wrong: delivered is counted as inbox and complained as spam. A provider delivery event does not establish the folder where a message was placed; a complaint is a user action, not a seed-mailbox placement measurement.

Required changes:

Consume the real seed-placement result model produced by the dedicated inbox-placement workflow, with verified provider/recipient identity and observation timestamps.

Keep SMTP delivery, complaints and measured inbox/spam placement as distinct metrics. Represent unknown placement explicitly.

Use the canonical recipient/domain relation for provider grouping; do not assume the ClickHouse event model exists in PostgreSQL.

Verification: Feed delivery-only events and assert placement remains unknown. Then feed measured inbox/spam seed results and verify the rate against those measurements only.

Evidence: Canonical-schema preparation fails with 42703; CASE classification inspected.

<a id="f88"></a>

F88 · P2 · Importing a contact without tags clears its existing tags

Status: new. Scope: Production code path. Prerequisites: F07, F70

Files and exact locations: services/mail-server/crates/api-server/src/routes/contacts.rs:513; services/mail-server/crates/api-server/src/routes/contacts.rs:528.

Remaining defect: Bulk import binds absent tags as [] for the new NOT NULL column. The conflict update uses COALESCE(EXCLUDED.tags, contacts.tags), but EXCLUDED.tags is now never null. A name-only import therefore replaces existing tags with an empty list.

Required changes:

Carry a tags_present flag through the staging input/CTE. Default missing tags to [] only for a new contact; on conflict update tags only when explicitly supplied.

Preserve the distinction between omitted tags and an explicit [] clear operation, and align metadata/name update semantics with the documented import contract.

Fix the canonical metadata/UUID blockers in F07 first, then verify the actual chunked import path.

Verification: Import an existing tagged contact with tags omitted: preserve tags. Repeat with []: clear tags. New contacts with tags omitted must receive [].

Evidence: Binding/default and ON CONFLICT source inspected; the broader import currently also encounters F07.

<a id="f89"></a>

F89 · P2 · The incident-advice tool returns SQL for an audit identity column that does not exist

Status: new. Scope: AI operational-advice output; query is not executed by this tool. Prerequisites: F76

Files and exact locations: services/mail-server/crates/ai-service/src/tools.rs:529.

Remaining defect: generate_incident_timeline returns an apexmail_audit_log_query filtering audit_logs.api_key_id, which is absent from the canonical schema. This is user-facing response text rather than SQL executed by the tool, but following the proposed scope-assessment query fails during an incident.

Required changes:

Generate the query from a supported audit search interface and the actual recorded principal/key identity. If key identity is not persisted, add its writer/schema/index contract before claiming a key-scoped investigation is available.

Use a tenant-owned, parameterized investigation endpoint and derive the requested exposure window instead of returning a fixed 48-hour query.

Validate generated operational queries against canonical fixtures; keep the response clear about which evidence has actually been retrieved.

Verification: Record actions under two keys and tenants, ask for one key’s timeline and execute the supplied investigation path. Return only the intended key/tenant/window evidence.

Evidence: Returned SQL text and canonical audit schema inspected; its preparation fails with 42703.

File-by-file change index

Every path below has an open action. The detailed finding supplies the operation-level fix and acceptance case; the linked lines identify the current implementation. New migrations must use unused canonical version numbers and an explicit backfill, without silently modifying an already-applied checksum. The accompanying CSV additionally inventories every tracked file, including files without a reported defect.

File

Open findings and locations

ci/stages/test.sh

F52: line 218, line 219

deploy/nginx/nginx.conf

F48: line 90; F65: line 27

packages/sdk-go/apexmail.go

F48: line 870

packages/sdk-java/src/main/java/ee/apexmail/Emails.java

F48: line 33

packages/sdk-php/src/Resources/Emails.php

F48: line 179

packages/sdk-python/src/apexmail/resources/emails.py

F48: line 339

packages/sdk-ruby/lib/apexmail.rb

F48: line 519

services/mail-server/crates/ai-service/src/tools.rs

F89: line 529

services/mail-server/crates/analytics/src/campaign_autopilot.rs

F85: line 97, line 162

services/mail-server/crates/analytics/src/compaction.rs

F83: line 99

services/mail-server/crates/analytics/src/inbox_placement.rs

F84: line 46

services/mail-server/crates/analytics/src/reply_tracking.rs

F67: line 190

services/mail-server/crates/apexmail-db/src/repos/contacts.rs

F07: line 23

services/mail-server/crates/apexmail-db/src/repos/incidents.rs

F86: line 21, line 40, line 55, line 89, line 100

services/mail-server/crates/apexmail-db/src/repos/warmup.rs

F87: line 21, line 40, line 54, line 65, line 80

services/mail-server/crates/api-server/src/app.rs

F19: line 720; F21: line 724; F48: line 720; F65: line 725

services/mail-server/crates/api-server/src/middleware/auth.rs

F18: line 983

services/mail-server/crates/api-server/src/middleware/idempotency.rs

F19: line 36, line 120, line 308; F21: line 230, line 447

services/mail-server/crates/api-server/src/middleware/request_logger.rs

F65: line 222, line 239

services/mail-server/crates/api-server/src/routes/admin/compliance_overview.rs

F78: line 203, line 214

services/mail-server/crates/api-server/src/routes/admin/growth_analytics.rs

F79: line 361, line 639

services/mail-server/crates/api-server/src/routes/admin/tenants.rs

F18: line 348

services/mail-server/crates/api-server/src/routes/billing.rs

F09: line 3982, line 4003

services/mail-server/crates/api-server/src/routes/contacts.rs

F01: line 1328; F07: line 209, line 386, line 417, line 573, line 606; F88: line 513, line 528

services/mail-server/crates/api-server/src/routes/messages.rs

F20: line 979, line 1529, line 1552, line 1556, line 1867, line 1898; F26: line 725; F48: line 187, line 580; F61: line 48; F74: line 113, line 617

services/mail-server/crates/api-server/src/routes/scim.rs

F42: line 701, line 1090, line 1118, line 501, line 1509

services/mail-server/crates/api-server/src/routes/ses_notifications.rs

F74: line 624, line 684, line 785, line 715; F75: line 902

services/mail-server/crates/api-server/src/routes/web/data.rs

F04: line 1813, line 1820; F14: line 115, line 198

services/mail-server/crates/billing-service/src/accounting_export.rs

F08: line 89, line 106; F82: line 89

services/mail-server/crates/billing-service/src/credit_notes.rs

F60: line 160, line 314

services/mail-server/crates/billing-service/src/invoices.rs

F29: line 160

services/mail-server/crates/billing-service/src/maintenance.rs

F09: line 3270

services/mail-server/crates/billing-service/src/overage.rs

F29: line 540; F31: line 118, line 285, line 292; F32: line 118, line 373, line 491, line 533; F33: line 1121, line 1133, line 1185, line 1247, line 1417, line 1461, line 1475; F34: line 1172, line 1501; F60: line 1079, line 1332

services/mail-server/crates/billing-service/src/stripe_webhooks.rs

F08: line 1685; F32: line 1248, line 1278; F34: line 1496; F36: line 787, line 893, line 928, line 969; F72: line 1496, line 1525; F73: line 1507

services/mail-server/crates/billing-service/src/usage.rs

F71: line 238, line 260, line 807

services/mail-server/crates/compliance/src/audit_logger.rs

F76: line 452, line 486, line 640, line 727, line 739, line 751, line 763

services/mail-server/crates/compliance/src/content_scanner.rs

F77: line 952

services/mail-server/crates/compliance/src/entitlements.rs

F61: line 150, line 190, line 255, line 265

services/mail-server/crates/compliance/src/estonia_ou.rs

F81: line 57, line 59, line 1021, line 1234, line 1249

services/mail-server/crates/compliance/src/financial_analytics.rs

F80: line 245, line 267, line 305, line 576, line 601, line 620; F81: line 19

services/mail-server/crates/compliance/src/gdpr_automation.rs

F82: line 632

services/mail-server/crates/ha/src/health_check.rs

F63: line 264, line 286

services/mail-server/crates/integration-tests/tests/schema_contract_tests.rs

F01: line 100

services/mail-server/crates/isolation/src/data_isolation.rs

F63: line 482

services/mail-server/crates/isolation/src/encryption.rs

F63: line 330, line 415

services/mail-server/crates/migrator/src/lib.rs

F01: line 207, line 219, line 292

services/mail-server/crates/template-renderer/src/renderer.rs

F62: line 82, line 310, line 346

services/mail-server/crates/tracking-service/src/codec.rs

F13: line 216

services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs

F13: line 804; F55: line 649

services/mail-server/crates/worker-processors/src/email/processor.rs

F18: line 1702; F25: line 2206, line 2281, line 2379, line 2453, line 2502; F26: line 2616; F55: line 1566, line 1736, line 1757; F74: line 1946, line 1970, line 2010; F75: line 2206

services/mail-server/crates/worker-processors/src/email/tracking.rs

F13: line 1

services/mail-server/crates/worker-processors/src/email/transport.rs

F26: line 390, line 689

services/mail-server/crates/worker-processors/src/reply_handler/processor.rs

F67: line 1

services/mail-server/migrations/133_abuse_reports_status.sql

F09: line 28

services/mail-server/migrations/136_invoices_unique_overage_period.sql

F29: line 1

services/mail-server/migrations/137_billing_periods.sql

F32: line 1

services/mail-server/migrations/139_invoices_stripe_item_id.sql

F34: line 1

services/mail-server/migrations/140_invoice_payment_allocations.sql

F73: line 1

services/mail-server/migrations/150_contacts_tags_canonical.sql

F70: line 26, line 46

services/mail-server/migrations/159_reply_events_canonical.sql

F67: line 1

tools/contrast-audit/audit.mjs

F52: line 480, line 556

Original findings now closed

ID

Original finding

Current evidence and disposition

F02

Several console pages decode UUIDs as strings

The affected console projections now use explicit UUID-to-text casts. This closes the reported decoding mismatch, not every console query; F04/F14 remain open. services/mail-server/crates/api-server/src/routes/web/data.rs:555. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F03

The API Keys console selects a nonexistent column

The API key console now uses key_prefix and derives expiration status from the canonical fields. services/mail-server/crates/api-server/src/routes/web/data.rs:1609. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F05

Invoice list/detail fail on both their primary and fallback queries

xml_url is migrated and invoice queries/fallback DTOs align with canonical types and optional fields. The original list/detail query failure is repaired. services/mail-server/migrations/130_invoice_xml_url.sql:1. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F06

Plan override creation/update references absent updated_at

The override timestamp is migrated; the writer validates plan/expiry, audits in the transaction and invalidates entitlement cache. services/mail-server/migrations/131_plan_overrides_updated_at.sql:1. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F10

Webhook retry branches write the wrong error column

All reported retry branches now use error_message and owner-fenced claim-token predicates. services/mail-server/crates/worker-processors/src/webhook/processor.rs:398. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F11

AI draft approval compares a string ID against UUID

Draft approval uses the canonical text identifier and couples draft consumption to the durable reply outbox transaction. services/mail-server/crates/api-server/src/routes/admin/ai_drafts.rs:99. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F12

Bot detection silently loses its send-time signal

The bot-detection message join/send-time signal uses canonical types and handles the nullable result rather than the old broken projection. services/mail-server/crates/api-server/src/routes/ai_insights.rs:337. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F15

Email verification fails against canonical UUID user IDs

Verification now parses and binds the canonical UUID user identity, eliminating the reported UUID/text failure. services/mail-server/crates/api-server/src/routes/auth.rs:3116. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F16

Verification expiry and consumption are not enforced atomically

Verification locks the user, checks the stored expiry strictly and consumes the token conditionally in the same transaction. Tenant activation is limited to the pending-verification state. Expiry remains serialized metadata, so canonical integration still needs the configured DB gate. services/mail-server/crates/api-server/src/routes/auth.rs:3116. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F17

Wildcard administrators cannot create ordinary scoped keys

Shared key minting validates the scope registry and recognizes administrator wildcard authorization for ordinary permitted scopes. services/mail-server/crates/api-server/src/routes/auth.rs:3260. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F22

Concurrent duplicate sends reserve quota twice

Single/batch send paths claim the durable logical operation before quota reservation and use stable reservation identities. The broader generic metering race is tracked separately as F71. services/mail-server/crates/api-server/src/routes/messages.rs:1430. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F23

Batch responses can report accepted messages that were rolled back

Per-item savepoints and rollback protect accepted batch members from a later rejected member’s SQL error. Ledger-completion and replay defects are separately open under F20. services/mail-server/crates/api-server/src/routes/messages.rs:1788. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F24

Cancellation races worker claims

Cancellation locks the queue before the parent and rejects a worker-claimed operation. Pending queue cancellation and parent transitions are verified for affected counts in one transaction. services/mail-server/crates/api-server/src/routes/messages.rs:357. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F27

Stripe subscription upsert omits the stored plan and preserves stale prices

The upsert now persists plan and updates Stripe price; existing subscription rows have a canonical backfill. Stale event ordering is separate under F36. services/mail-server/crates/billing-service/src/stripe_webhooks.rs:969. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F28

Three existence checks decode INT4 into i64

The reported INT4-to-i64 existence checks now use boolean EXISTS and matching Rust types. services/mail-server/crates/billing-service/src/overage.rs:1052. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F30

Renewal can erase the period before overage billing reads it

Subscription transition now records the closing billing period inside the transaction before replacing live cycle fields. Snapshot completeness and eventual sweep progress remain F32/F31. services/mail-server/crates/billing-service/src/stripe_webhooks.rs:903. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F35

Wallet deductions lack durable invoice payment allocations

Wallet movements and invoice allocations are now committed together. The existing unique wallet transaction reference also rejects a second debit on retry; the suspected duplicate-wallet debit was disproved. services/mail-server/migrations/140_invoice_payment_allocations.sql:1. Evidence: Canonical migrations plus executed retry fixture: SQLSTATE 23505 prevents the second debit; wallet debit and allocation remain 4000 each after a later top-up.

F37

Malformed Unicode unsubscribe tokens can panic before verification

Token validation now rejects malformed/non-ASCII inputs before byte slicing and verification. The reported Unicode panic is repaired. services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs:49. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F38

Unsubscribe → resubscribe → unsubscribe can lose the final choice

Current suppression choice is persisted independently of analytics-event deduplication, so unsubscribe → resubscribe → unsubscribe can restore the final opt-out. services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs:135. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F39

Manual unsubscribe mutates state through GET

Manual unsubscribe confirmation uses POST; GET renders the confirmation without changing consent. One-click behavior remains explicit. services/mail-server/crates/tracking-service/src/routes/mod.rs:75. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F40

SCIM create bodies require server-generated IDs

Separate SCIM create DTOs no longer require a server ID; handlers generate identity and return the created resource/Location. services/mail-server/crates/api-server/src/routes/scim.rs:124. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F41

SCIM ignores active=false during user creation

active=false is mapped into persisted account state and checked by authentication, including cache invalidation. The PATCH concurrency problem is distinct under F42. services/mail-server/crates/api-server/src/routes/scim.rs:394. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F43

SCIM pagination metadata contradicts the query, and offset arithmetic can overflow

User/Group pagination now shares bounded normalization, overflow-safe offsets and response metadata matching the effective page. This uses the archived final F43 pagination identity, correcting the older JSON title. services/mail-server/crates/api-server/src/routes/scim.rs:661. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F44

Caller metadata can poison a shared queue claim

Caller metadata shape/reserved keys are validated; server-owned queue fields are constructed separately and legacy poisoned shapes are repaired. services/mail-server/crates/api-server/src/routes/messages.rs:76. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F45

Customer metadata can override validated recipients

Caller metadata cannot replace the validated server-owned recipient fields. F74 concerns a different custom-header trust boundary. services/mail-server/crates/api-server/src/routes/messages.rs:76. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F46

Console-created API keys bypass the JSON endpoint’s expiry policy

SSR now calls the shared mint helper for scope, expiry, key-count transaction and persistence policy. services/mail-server/crates/api-server/src/routes/web.rs:3155. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F47

A clean Python SDK installation lacks an import dependency

The package now declares pydantic[email], including the import dependency originally missing from clean installs. packages/sdk-python/pyproject.toml:37. Evidence: Dependency declaration inspected; available Python SDK suite passed 59 tests. A clean wheel installation was not executed.

F49

Homepage Features partial has an unclosed container

The missing homepage container closure remains repaired. This was already closed in the previous final review; it is not a newly discovered repair. apps/marketing-zola/templates/partials/home/features.html:30. Evidence: Latest Zola build and strict tag-balance checks passed; visual browser verification was not repeated.

F50

Features page template ends in the middle of its third card

The interrupted feature card/content and closing wrappers remain complete. This was already closed in the previous final review. apps/marketing-zola/templates/partials/features/details.html:147. Evidence: Latest Zola build and strict tag-balance checks passed; visual browser verification was not repeated.

F51

Features-page examples use incorrect response/tag shapes

Examples use response.data and the supported list-shaped tags, closing the reported documentation contract mismatch. apps/marketing-zola/templates/partials/features/details.html:57. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F53

README gives an invalid Zola invocation

README now instructs building within the Zola project root; the invalid invocation is removed. README.md:64. Evidence: Zola 0.22.1 build executed successfully from apps/marketing-zola on the final reviewed revision.

F54

Suppression/preference IDs exceed their column lengths

Suppression/preference IDs fit their canonical VARCHAR bounds in both immediate and asynchronous writers. services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs:923. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F56

Thirty-two routes use capture syntax incompatible with pinned Axum

The 32 affected route captures use the syntax supported by the pinned Axum version. Source syntax passes; full router startup was not run locally. services/mail-server/crates/compliance/src/routes.rs:32. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F57

Risk assessment reads three nonexistent tables

The reported nonexistent risk-factor tables were replaced with canonical data-source queries and explicit missing-data handling. This closes that schema defect, without certifying the risk model’s calibration. services/mail-server/crates/compliance/src/risk_scoring.rs:831. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F58

IP pool rows also have incompatible UUID and INET decoding

IP pool projections now use id::text and host(inet) for the string response fields. services/mail-server/crates/api-server/src/routes/web/data.rs:2815. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F59

Queue metrics retain stale nonzero values after draining

Successful queue snapshots emit the complete bounded status set with zero defaults, while query failures do not masquerade as drained queues. services/mail-server/crates/worker-processors/src/email/processor.rs:1304. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F64

Overage estimates accept another tenant’s identifier

The estimate now binds to AuthUser. A different requested tenant passes an explicit administrative tenant-access check before lookup. services/mail-server/crates/api-server/src/routes/billing.rs:2817. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F66

Hourly subscription cleanup targets a nonexistent persistence model

The hourly cleanup no longer targets an unimplemented subscription saga table. Current subscription operations use their implemented Stripe checkout/portal and webhook persistence flows; no missing-table hourly cleanup remains. services/mail-server/crates/billing-service/src/maintenance.rs:337. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F68

Reply metrics cache ignores the requested time window

Reply metric cache identity contains tenant, validated/clamped time window and data generation. The reported one-day/thirty-day collision is repaired. services/mail-server/crates/analytics/src/reply_tracking.rs:179. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

F69

Reply thread lookup omits tenant ownership

Reply thread lookup passes tenant ownership and uses bounded maximum-depth increment rather than an unscoped recursive walk. services/mail-server/crates/analytics/src/reply_tracking.rs:61. Evidence: Current source and applicable repository/schema checks; Rust integration not executed.

Reproductions and discarded hypotheses

Check

Observed result

contacts_canonical_metadata_missing

reproduced: column "metadata" of relation "contacts" does not exist

contacts_uuid_text_binding

reproduced: operator does not exist: uuid = text

contact_tags_validator_accepts_nonstring_elements

reproduced: {"valid"}

contact_tags_populated_scalar_upgrade_aborts

reproduced: cannot extract elements from a scalar

wallet_retry_duplicate_debit_blocked

guard_verified_suspicion_disproved: {"wallet_balance":6000,"debited":4000,"allocated":4000,"retry_error":{"code":"23505","error":"duplicate key value violates unique constraint "uq_wallet_transactions_reference""},"top_up_after_first_payment":6000}

console_outstanding_ignores_confirmed_wallet_payment

reproduced: {"console":[{"currency":"EUR","coalesce":10000}],"authoritative":{"outstanding":"6000"}}

stripe_paid_reports_affected_row_when_no_invoice_exists

reproduced: {"pglite_affectedRows":0,"result_rows":[{"?column?":1}],"persisted_invoices":0,"note":"Top-level SELECT returns one row despite zero invoice mutations. The independent PostgreSQL wire probe returns SELECT 1; this is not an executed Rust/SQLx integration test."}

stripe_paid_zero_invoice_fails_allocation_check

reproduced: new row for relation "invoice_payment_allocations" violates check constraint "invoice_payment_allocations_amount_cents_check"

metering_check_then_insert_allows_duplicate_logical_id

reproduced: {"first_check":[{"exists"}],"second_check":[{"exists"}],"rows":2,"quantity":2,"note":"Statement interleaving reproduces two prechecks before either insert; not a two-session Rust runtime test."}

credit_note_unpaid_invoice_reduces_debt_and_mints_wallet_credit

reproduced: {"debt":"8000","wallet":8000,"wallet_before":6000,"wallet_credit_delta":2000,"invoice_paid_before_credit":0,"credit_note":2000,"total_economic_benefit":4000}

invoice_unique_violation_recovery_transaction_is_aborted

reproduced: {"conflict":{"code":"23505","error":"duplicate key value violates unique constraint "uq_invoices_tenant_overage_period""},"recovery":{"code":"25P02","error":"current transaction is aborted, commands ignored until end of transaction block"}}

stripe_paid_wire_command_tag_is_select_one

reproduced: {"command_complete_tags":["SELECT 1"],"matched_invoices":0}

required_audit_union_has_incompatible_shapes

reproduced: each UNION query must have the same number of columns

content_scanner_canonical_policy_column_mismatch

reproduced: column "active" does not exist

activation_analytics_nested_aggregate_invalid

reproduced: aggregate function calls cannot be nested

ses_delivery_canonical_timestamp_column_missing

reproduced: column "delivered_at" of relation "messages" does not exist

The duplicate-wallet-debit suspicion was discarded because uq_wallet_transactions_reference blocks the second debit and rolls back that attempt. F35 remains closed. F60 is different: a newly accepted unpaid-invoice credit both reduces debt and mints wallet value. The Stripe constant-SELECT check reports both PGlite’s affectedRows=0 and PostgreSQL’s SELECT 1 wire tag; the driver-sensitive distinction is not hidden.

SQL triage classification

Count

different_backend_or_fragment

6

dynamic_fragment

17

explicit_optional_source

7

interpolated_template

10

legacy_fallback

2

migration_runner_metadata

2

prepared

2094

reported_finding

48

requires_sqlx_parameter_types

9

runtime_initializer

108

test_fixture_or_test_query

98

Runtime-created sales/breach/DSR/retention stores, the inbound processing_at initializer and SQLx’s own migration ledger were not relabelled as absent production tables solely because the canonical-file-only probe omits their initializer. Legacy fallback statements and ClickHouse/dynamically assembled SQL were likewise separated. Ambiguous PostgreSQL PREPARE parameter inference must be checked with the actual SQLx bound types before it becomes a finding.

Remaining verification required for release

Run the pinned Rust workspace checks and enabled service integration tests on the actual supported toolchain and PostgreSQL version, with a required DATABASE_URL and no soft skip for provisioning failures. Assert result DTO types as well as SQL preparation.

Run the canonical fresh migration gate and representative populated upgrade lineages, including migration 150 malformed legacy tags and migration 169 both with/without from_address. Validate migration checksums and production lineage explicitly.

Run controlled send/queue/provider tests for cancellation, Redis loss, handler timeout, DB failure, consent changes on another replica, every recipient terminal outcome and actual SMTP/SES MIME. Use sandbox providers and no real customer recipients.

Run Stripe sandbox cases for unknown external invoices, wallet-partial settlement, zero-value invoices, credits/refunds, concurrent collectors, retry/restart and stale subscription events. Reconcile every invoice and payment to one ledger identity.

Run real IdP-shaped SCIM User/Group operations, clean installations and end-to-end contract suites for all supported SDKs, plus tenant ownership tests for each exposed integration.

Run the required browser contrast/layout/accessibility checks with independent failing fixtures and captured execution metadata. Validate the production app, not just static fixture exports.

For each optional finding, establish whether the component is enabled/reachable, wire the advertised feature and its producer/consumer, and run its canonical persistence test. Do not close an advertised capability merely by removing documentation.