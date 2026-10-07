# Adversarial review — the gates and the migrations

Scope: `tools/` gate surface (Slice 1) and `services/mail-server/migrations/**` (Slice 2), per
`docs/audit/dogfood-2026-10-06/brief-review-gates-migrations.md`. No code was edited.

## Snapshot and method (read this before trusting a finding)

* HEAD: `61c7110f` ("fix(sales): immediately-due actions are claimable across sub-second clock
  skew"), branch `main`.
* **The working tree was being modified by another process while this review ran.** Observed
  during the session: `services/mail-server/crates/billing-service/src/plans.rs` (mtime
  2026-10-06 22:55, blame "Not Committed Yet"), `tools/check_knowledge_consistency.py`,
  `tools/check_web_error_honesty.py`, `api-server/src/routes/web.rs` (mtime 2026-10-07 10:40),
  hundreds of `tools/contrast-audit/fixtures/*`, and more. Where a finding depends on the dirty
  tree I say so and give the committed-HEAD counter-evidence (the `ci/runs/20261006T201028_91588`
  validate log shows HEAD was green).
* Method for gates: read the file; run its shipped self-test with the real exit code captured;
  where no self-test exists, run the gate itself and/or feed it a crafted bad input (probes under
  `/tmp`, never in the repo). Method for migrations: read the queue/ledger/audit/suppression/
  session files in full (41 files), and screen **all 216** with a statement-splitting analyzer
  (`/tmp/migscan.py`) that flags unscoped `DELETE`/`UPDATE`, self-incrementing `UPDATE`s,
  `INSERT ... SELECT`/`VALUES` rerun hazards, unguarded `ALTER TABLE ADD COLUMN`/`CREATE
  TABLE`/`CREATE INDEX`, plus targeted greps (duplicate table definitions, dedup keys, DOWN/
  rollback text, comments claiming triggers/immutability). Files that were screened but not read
  line-by-line are marked `[s]` in the ledger — see "What I did not reach".

---

## Findings

### <P1> tools/check_knowledge_consistency.py:147-158 — the gate crashes; CI's validate stage cannot go green on the working tree

Evidence:

```
$ python3 tools/check_knowledge_consistency.py --self-test
  File ".../tools/check_knowledge_consistency.py", line 397, in run_checks
    catalog, parse_billing_seeds(billing_src), parse_billing_overage(billing_src)
  File ".../tools/check_knowledge_consistency.py", line 157, in parse_billing_overage
    assert out, "billing overage parse produced no arms"
AssertionError: billing overage parse produced no arms
$ echo $?
1
```

`parse_billing_overage` (line 147) requires literal match arms
(`"pro" => Some(60)`) in
`services/mail-server/crates/billing-service/src/plans.rs`. The working tree (uncommitted) rewrote
`plan_overage_rate_millicents` to delegate:

```rust
pub fn plan_overage_rate_millicents(plan_name: &str) -> Option<i64> {
    platform_catalog::plan_by_name(plan_name)
        .and_then(|catalog_row| catalog_row.overage_millicents_per_email)
}
```

(`git blame -L 325,328` shows the three lines "Not Committed Yet".) Both `main()` and
`--self-test` die on a bare `AssertionError`, so the gate reports nothing actionable and its
self-test proves nothing. `ci/stages/validate.sh:311-315` runs both the gate and its self-test
under `ci_check`; validate would fail. The last committed-tree validate run
(`ci/runs/20261006T201028_91588/stages/validate.log:606,615`) shows
`PASS knowledge-consistency` and `knowledge-consistency self-test: PASS`, confirming this is
caused by the in-flight refactor, not HEAD.

Why: the refactor that made `platform-catalog` the single source of plan facts removed the very
literal arms this gate parses. The gate must be updated in the same change, or it becomes a
permanently red required check that blocks the validate stage.

Fix: replace `parse_billing_overage` with a parse of the canonical
`platform_catalog::PLANS` `overage_millicents_per_email` fields (the authority the function now
delegates to), keep the cross-check against `plans.rs` via the delegation shape, and replace the
bare `assert out` with a `fail(...)`/exit-1 message that names both files.

### <P1> tools/check_web_error_honesty.py — its self-test fails (exit 1); the masker hides lines 8973-26265 of web.rs

Evidence:

```
$ python3 tools/check_web_error_honesty.py --self-test; echo $?
SELF-TEST PASS unmutated sandbox copy stays green
SELF-TEST FAIL injected .ok().flatten() swallow fails the gate: exit=0, needle='ok-flatten swallow'
SELF-TEST FAIL injected db-result .unwrap_or default fails the gate: exit=0, needle='db-swallow'
web-error-honesty self-test: FAIL
1
```

Root cause, measured: the self-test appends its injections at EOF of a sandbox copy of
`web.rs`. `mask()` output has **1833 `{` vs 1830 `}`** (imbalance 3), so the brace matcher in
`blank_test_regions()` (line 187) never closes the `#[cfg(test)] mod tests {` that starts at
`web.rs:8973` (attr offset 356519, `{` at 356542): the module span runs to EOF (stop=1065445), so
every appended byte is blanked as "test code". A direct measurement of the span:

```
line 8973: kw=mod pos=356519 brace=356542 stop=1065445 covers_injection=True
```

Consequence: the meta-proof cannot pass, and structurally the gate only ever scans `web.rs`
lines 1-8972 (about 34% of the file, though today all production code appears to sit before the
first `#[cfg(test)] mod`, so this is currently a self-test defect rather than a live blind spot —
state that honestly). CI does not notice because `validate.sh:256` runs the gate **without**
`--self-test`. The gate's core detection itself does work: injecting
`fn ... { r.ok().flatten() }` at line 20 of a sandbox copy produced
`web.rs:21 ok-flatten swallow` and exit 1.

Fix: stop brace-matching masked text; either use a real Rust item scanner, or have the self-test
place the mutation before the first `#[cfg(test)]` item and run the gate over that file (with a
separate "test-region exclusion" unit case). Also wire `--self-test` into the `ci_check` in
`validate.sh` so a broken meta-proof is red.

### <P1> tools/validate_pricing_drift.py:359-378 — same refactor makes a REQUIRED gate fail with "cannot parse runtime overage rates"

Evidence:

```
$ python3 tools/validate_pricing_drift.py; echo $?
cannot parse runtime overage rates: no overage rate arms parsed from the runtime catalog
1
```

`extract_overage_rates` (line 359) uses the same `pub fn plan_overage_rate_millicents(...) {
<arms> }` regex as the knowledge gate and raises `ValueError("no overage rate arms parsed...")`
(line 378) which is turned into an error at line 423. `ci/stages/validate.sh:595-597` calls this
gate **REQUIRED** inside `zola_gates` ("one of deploy.yml's pr-gate required checks"). On HEAD it
passes (`ci/runs/20261006T201028_91588/stages/validate.log:684` "pricing drift validation
passed").

Why: two independent gates both hard-code the pre-refactor shape of one function; the
platform-catalog refactor silently invalidated both parsers, and each fails in its own
non-actionable way (bare assert vs ValueError).

Fix: derive expected overage rates from `platform_catalog::PLANS` (the same source the runtime
now uses) and keep a separate assertion that `plans.rs` delegates to it.

### <P2> tools/check_knowledge_consistency.py (committed HEAD) — the consistency gate omits `apps/ai`; the working tree adds it (the brief's named coverage class)

Evidence: `git show HEAD:tools/check_knowledge_consistency.py | grep -c AI_TRAINING` → `0`.
The uncommitted diff adds `AI_TRAINING_PRICING = ROOT/"apps/ai/training/validate_pricing.py"` and
`check_ai_training_matches_catalog()` (40 added lines, `git diff -- tools/check_knowledge_consistency.py`).
The gate the brief cites as the example class ("checks billing + docs but not apps/ai") is
exactly this: HEAD verifies catalog vs billing seeds, verifier tables, knowledge.rs, sales KB and
`docs/pricing.md`, but not the Python training/eval corpus that shipped an inverted price table
(per the added comment).

Why: the training canon is a live consumer of plan facts; until the working-tree addition lands,
drift there is unpinned.

Fix: land the in-flight `check_ai_training_matches_catalog` addition together with the P1 parser
fix above, and add its mutation to `--self-test`.

### <P2> tools/check_marketing_contrast.py — a gate that cannot fail against the thing it names, and nothing runs it

Evidence: the file contains only hardcoded `COLORS`/`REQUIRED_PAIRS` (lines 8-40) and
`main()` computes contrast ratios over those constants — it opens no CSS/template file.
`grep -rl check_marketing_contrast` over the repo (excluding `.git`, `.kilo`, `node_modules`,
`target`) finds only the file itself and the audit worklist. It currently prints
`marketing contrast token validation passed`.

Why: it validates a copy of the palette, not the shipped palette; a stylesheet regression cannot
make it fail. It is also orphaned (see the wiring ledger), so it runs nowhere.

Fix: delete it (the pixel-verified `tools/contrast-audit/gate.sh` is the authoritative WCAG
check, per `ci/pipeline.conf:128`), or rewrite it to parse the actual CSS custom properties and
wire it into `ci/stages/ui.sh`.

### <P2> Orphaned gates: tools/check-risk-lua-parity.sh and tools/check_hsts_preload.py never run

Evidence: repo-wide reference scan (excluding `.git/.kilo/node_modules/target`):

```
check-risk-lua-parity.sh => (self + docs/audit/.../worklist.txt)
check_hsts_preload.py    => docs/security/hsts-preload.md (manual step), worklist
```

`check-risk-lua-parity.sh` enforces two real invariants (byte-identical packaged Lua copies;
`event == 3` trust-neutrality) that "slipped through" once before (its own header, rounds
83/84) — but it is not in `ci/stages/validate.sh`, `ci/pipeline.sh`, the Makefile,
`.pre-commit-config.yaml`, or `.woodpecker.yml`. `check_hsts_preload.py` is documented as a manual
command (`docs/security/hsts-preload.md:37`) but is not listed in `tools/README.md`'s supported
workflow list either.

Why: a gate that never runs is documentation, not enforcement; the Lua-parity invariants are
exactly the class that regressed silently before.

Fix: add `bash tools/check-risk-lua-parity.sh` to the validate stage's python/shell block;
either wire `check_hsts_preload.py` to a scheduled URL check or list it in `tools/README.md`
under supported scripts (the README maintenance rule says to do one of the two).

### <P2> tools/check_outbound_delivery_contract.py:48-66 — SQL files are never scanned and the `migrations/` allowlist entry can never match

Evidence: `suffixes = {".md", ".rs", ".toml", ".yml", ".yaml", ".sh", ".py", ".json"}` (line 48)
excludes `.sql`. `RETIRED_NAME_ALLOWLIST` (lines 29-34) contains `"migrations/"`, but the
comparison is `relative.startswith(prefix)` against paths like
`services/mail-server/migrations/052_...`, which never starts with `migrations/`. Meanwhile
`grep -o "crates/outbound-queue/[A-Za-z0-9_./-]*"` finds live references in
`services/mail-server/migrations/052_add_missing_foundation_tables.sql` and
`056_fix_critical_schema_issues.sql`; the gate still prints "outbound delivery contract guardrail
passed".

Why: the allowlist entry is dead code that documents an exemption which is not implemented, and
any future `.sql` reference to the retired package (or path-shaped resurrection) is uncovered.

Fix: either add `.sql` to `suffixes` **and** change the allowlist prefix to
`services/mail-server/migrations/`, or delete the dead entry and say SQL is out of scope.

### <P3> tools/check-forbidden-patterns.sh:47-52 — silently passes when the built site is absent

Evidence (probe in a temp cwd with no `apps/marketing-zola/public`):

```
$ bash tools/check-forbidden-patterns.sh; echo $?
No HTML files found in public/ directory.
0
```

With a planted `signed proof` page it exits 1 correctly (`FORB_RC=1`). The script is also a
pre-commit hook (`.pre-commit-config.yaml`, `forbidden-pattern-gate`), where a clean checkout has
no `public/` — so at commit time it always takes the vacuous branch.

Why: "no input" is treated as "no violations"; the gate's README claim ("quality gate that
blocks known regression patterns") only holds after a build.

Fix: treat an empty `public/` as a hard failure in CI mode (or require
`apps/marketing-zola/public/index.html`) and note the ordering requirement in the hook name.

### <P3> tools/check_flash_copy.py:30,114-116 — the documented root argument crashes for any path outside the repo

Evidence:

```
$ python3 tools/check_flash_copy.py /tmp/flashfix
  ...
  File ".../tools/ui_flash_extract.py", line 285, in production_text
    rel = path.resolve().relative_to(ROOT).as_posix()
ValueError: '/private/tmp/flashfix/sample.rs' is not in the subpath of '.../ApexMail'
```

The docstring advertises `Usage: python3 tools/check_flash_copy.py [root …]`; the crash is a
non-actionable traceback rather than a usage error.

Why: probing the gate with external fixtures (the natural way to test it) is impossible, and a
typo'd in-repo root would fail the same way.

Fix: resolve root-relative paths for in-repo roots and print a clear "root must be inside the
repository" error (exit 2) for external ones.

### <P3> tools/migration_lint.py — the chain lint has no DML-scope rule (the brief's unscoped `DELETE`/`UPDATE` class is unguarded)

Evidence (probe with a synthetic migration in a temp root; the lint reads
`<tmp>/services/mail-server/migrations/*.sql`):

```
$ printf -- '-- Migration 999: test\nDELETE FROM users;\n' > 999_bad.sql
$ python3 /tmp/probe/tools/migration_lint.py
migration_lint: stale LEGACY_HEADER entry (no such file): 001_initial_schema.sql
... (stale-exemption noise only)
# no line mentioning 999_bad.sql
```

The same probe with `CREATE TABLE t (id int);` produced
`999_bad.sql:2: [create-table] CREATE TABLE without IF NOT EXISTS...`. So `DELETE FROM users;`
— an unscoped destructive statement — is not reported by the lint that advertises "enterprise
conventions for the canonical chain". (The whole chain happens to be free of unscoped DML today:
my statement-level scan of all 216 files found none.)

Why: the one defect class where a mistake destroys data rather than merely wedging a deploy is
the one class the linter does not cover.

Fix: add a `[dml]` rule that rejects `DELETE`/`UPDATE` statements with no top-level `WHERE`
(respecting dollar-quoted bodies and CTEs) to `check_file`.

### <P3> tools/check_ui_links.py:103-104 — with no built marketing site every marketing link target is assumed alive

Evidence: `marketing_page_exists` returns `True` when `apps/marketing-zola/public` is absent
("no built site: assume alive"). The gate prints
`marketing public: ABSENT (existence assumed)` but still exits 0 for `/pricing`, `/de`,
`/compare/...` targets. The `ui` stage does not build zola (the contrast gate explicitly does;
`ci/stages/ui.sh` does not), so in a fresh CI checkout the marketing half of the dead-link gate
is vacuous.

Why: honest in its note, but a green run cannot distinguish "all marketing links resolve" from
"the site was never built".

Fix: in CI (`CI_*` set or a `--require-marketing` flag) fail when `public/` is absent; locally
keep the note.

### <P3> Ratchet/self-test coverage notes (gate hygiene, not defects)

* `tools/check_rust_panic_paths.py` (857/1700 at review) is env-overridable
  (`MAX_RUST_PANIC_PATHS`); a probe with `MAX_RUST_PANIC_PATHS=1` exits 1 with examples, proving
  the failure path. The count only matches `.unwrap(`/`.expect(`: `panic!(`, indexing, and
  `unwrap_err` are invisible; the docstring claims only "unwrap/expect", so this is a scope note.
* `tools/contrast-audit/layout-audit.mjs` ships **no** self-test (its sibling `audit.mjs` does —
  12/12 pass), so the layout classifier's ability to flag a known-bad page is unproven.
  `docs-lint.sh`, `check_topology_contracts.py`, `check_claim_expiry.py`,
  `validate_security_feature_flags.py`, `check_cargo_cycles.py`,
  `check_compare-pricing-parity.py` and `generate_repo_map.py --check` likewise ship no
  self-test; their can-fail paths are by-construction (see ledger).
* `tools/check_ui_terminology.py` is advisory by design (`ci/pipeline.conf:160`,
  `CI_UI_TERMINOLOGY_CHECK`) — verified failing on a crafted fixture
  (`wrong-case-brand 'Apexmail'`, `banned-phrase 'seamless'`), so the advisory wiring is the only
  thing between the repo and those findings.
* `tools/check_soft_skips.py` is fail-closed but only runs when
  `APEXMAIL_RELEASE_TEST_MODE=1` (`ci/stages/test.sh:198`); non-release runs do not exercise it
  (documented in the stage).

### Working-tree gate failures that are evidence the gates work (not gate defects)

Reproduced in this snapshot; attribute them to the concurrent uncommitted edits:

* `python3 tools/check_flash_copy.py` → exit 1:
  `FAIL leaked-error-display .../web.rs:5670 — 'redirect_error(&error.to_string()'` (the gate's
  output at run time; a later edit shifted the call site to :5684, where I confirmed it) — a
  newly-added `form_demo_create` failure path (`git diff` shows the line as uncommitted) passes
  an internal `Display` string to the browser; the UI stage would fail. Real copy-hygiene issue
  in the in-flight change.
* `python3 tools/i18n-audit.py` → exit 1: de/fr/es lack `footer.your_privacy_choices`.
* `python3 tools/extract_ui_strings.py --check` → exit 1 (`FAIL catalog drift: docs/development/ui-strings-catalog.json`,
  total 1077 vs committed) — this is the exact failure recorded by the last pipeline run
  (`ci/runs/20261006T201533_37440/stages/ui.log:103-106`, stage `ui` fail).
* The two P1 parser failures above (knowledge consistency, pricing drift).

---

## Slice 2 findings (migrations)

### <P1> services/mail-server/migrations/050_partition_high_volume_tables.sql:191-208 (and 309-325, 472-488, 600-616, 716-732) — the H-08 guard warns that rows were lost, then drops the only copy

Evidence — the email_queue copy (identical shape at all five partition conversions):

```sql
-- H-08: Verify data integrity before dropping old table. Only DROP if counts match.
...
IF v_old_count > v_new_count THEN
    RAISE WARNING 'email_queue: % rows in old table but only % in new table — some data may have been lost during migration', v_old_count, v_new_count;
END IF;
-- Only drop old table if migration succeeded
EXECUTE 'DROP TABLE IF EXISTS email_queue_old';
```

There is no `ELSE`/`RETURN`/`EXCEPTION` on the mismatch branch: the `DROP` executes
unconditionally once the count check runs. The only hard abort is `v_old_count > 0 AND
v_new_count = 0`; any partial shortfall (the realistic failure mode of the `INSERT ... SELECT`
copy, e.g. constraint or OOM interruption that still commits the guarded block) is reported and
then made irreversible. The comment "Only DROP if counts match" is false.

Why: the old table is the only complete copy of the queue/delivery-log/mail_messages/audit_logs/
bounce rows; dropping it after a WARNING turns a recoverable partial copy into permanent data
loss. The same pattern is repeated five times in this one file.

Fix: `IF v_old_count > v_new_count THEN RAISE EXCEPTION ...` (rolling back the whole migration
file, which sqlx runs in one transaction) or `RETURN` from the inner block before the `DROP`.

### <P1> services/mail-server/migrations/115_repair_partition_conversion_losses.sql:96-116 — the comment promises a guard the code does not implement; `*_old` remnants are dropped unconditionally

Evidence:

```sql
-- 1. Stray *_old remnants (interrupted 050) ...
-- A crash between RENAME and DROP left the un-partitioned *_old table behind
-- AND left the production table empty. Dropping the remnant is the recovery
-- the interrupted migration never reached; only do it when the real
-- (partitioned) table also exists, so this can never delete the only copy.
DO $$
...
    IF to_regclass(format('public.%I', old_table)) IS NOT NULL THEN
        RAISE NOTICE '115: dropping stray remnant %', old_table;
        EXECUTE format('DROP TABLE IF EXISTS %I', old_table);
    END IF;
```

The code checks only that the `*_old` table exists; it never checks
`pg_partitioned_table`/`to_regclass` for the replacement. In the very scenario the comment
describes (an interrupted 050 that left `email_queue_old` as the only copy), this migration
destroys it.

Why: this is the exact "comment claiming a behaviour the SQL does not implement" class, and the
behavior difference is data loss.

Fix: add the promised probe before the DROP, e.g. `IF to_regclass('public.email_queue') IS NOT
NULL AND EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid='public.email_queue'::regclass)
THEN ... DROP ...`.

### <P2> services/mail-server/migrations/095_mta_bounce_fbl_hardening.sql:10-14,42 — the "canonical definition" comment is false and its CREATE is dead DDL; the installed shape is 093's

Evidence: 095's header says complaint_events "was created ad-hoc on production and does not exist
in any migration plus a partial unique index". But `093_deep_schema_convergence.sql:219` (an
earlier file in the same chain) already does `CREATE TABLE IF NOT EXISTS complaint_events` with a
different shape:

```
093: id UUID PRIMARY KEY, feedback_type TEXT (nullable, no default), arrival_date TIMESTAMPTZ
095: id TEXT PRIMARY KEY,  feedback_type TEXT NOT NULL DEFAULT 'abuse', arrival_date TEXT
```

On every canonical-chain database 093's table exists, so 095's `CREATE TABLE IF NOT EXISTS`
silently no-ops: the claimed `feedback_type NOT NULL DEFAULT 'abuse'` and TEXT `arrival_date`
never exist. Runtime code binds a `Uuid` id and treats `arrival_date` as TIMESTAMPTZ
(`crates/mta/src/servers/feedback_loop.rs:797,826`), i.e. it follows 093 — the comment and the
dead DDL mislead the next reader. (The bounce_events part of 095 is accurate: the code's
`ON CONFLICT (original_message_id, original_recipient) WHERE ...` at
`crates/mta/src/servers/bounce.rs:606-613` correctly matches the partial index.)

Why: a migration that claims to install a canonical shape but cannot do so on any chain database
is a trap for anyone reconciling drift.

Fix: correct the comment to name 093 as the canonical definition and either delete the dead
`CREATE TABLE` (replacing it with the two `ALTER`s the drift actually needs) or fold the
divergent column defaults into guarded ALTERs.

### <P2> services/mail-server/migrations/110_uid_backfill.sql:20-24 (same pattern in 002:23-27) — UIDNEXT is recomputed downward, violating the IMAP monotonicity invariant

Evidence:

```sql
UPDATE mail_mailboxes mb
SET uidnext = COALESCE((SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id), 1);
```

The comment calls the file an "idempotent copy". On a live database, any mailbox whose
highest-UID message was expunged has `uidnext > max(uid)+1`; this statement lowers `uidnext` back
to `max(uid)+1`. RFC 3501 requires UIDNEXT to be non-decreasing (a client that cached the higher
value will believe deliveries were lost, and UID reuse after expunge becomes possible). 002 runs
during the initial backfill, but 110 is a later file applied to long-lived mailboxes.

Why: a backfill that is not idempotent in the harmful direction — it can move a protocol counter
backwards.

Fix: `SET uidnext = GREATEST(mb.uidnext, COALESCE((SELECT MAX(uid)+1 ...), 1))` in both files
(110 is not ledger-frozen; 002 is, so a 111-style forward repair would be needed for a fresh
deployment that re-runs 110).

### <P3> services/mail-server/migrations/213_compliance_runtime_ddl_to_migrations.sql:31-44 — `dsr_verification_outbox` has no dedup key

Evidence: the table is `id TEXT PRIMARY KEY, request_id TEXT NOT NULL, ...` with only
`idx_dsr_outbox_pending`; `crates/compliance/src/gdpr_automation.rs:338` inserts a fresh random
`Uuid::new_v4()` id with no `ON CONFLICT`/`NOT EXISTS` guard. Compare the dedicated ledgers that
were hardened for exactly this class: 205 (`send_unit` PK), 210 (`(message_id, recipient)` PK),
212 (`send_unit` PK), 231 (batch UUID + exact per-event rows). A replayed automation for the same
`request_id` enqueues a second row and re-sends the verification mail.

Why: the queue is the one in the C-2/D (audit/suppression/GDPR) cluster without the idempotency
identity the sibling migrations treat as mandatory.

Fix: `CREATE UNIQUE INDEX IF NOT EXISTS uq_dsr_outbox_request ON dsr_verification_outbox
(request_id);` plus a guarded insert (or `ON CONFLICT (request_id) DO NOTHING`) in
`gdpr_automation.rs`.

### <P3> services/mail-server/migrations/050:67-70 — false comment about the copied column set

Evidence: "Create partitioned table (includes ALL columns from the original schema + the uid
column that was added by migration 002 ...)". Migration 002 adds `uid` to **mail_messages**
(`002_mailstore_uid.sql:7-8`), and `email_queue` has no `uid` column in 001 or 050. The
`INSERT INTO email_queue SELECT * FROM email_queue_old` is in fact correct (27 columns in both,
same order — I diffed 001's column list against 050's), but the comment sends a reader looking
for a column that does not exist.

Why: cosmetic, but this comment is load-bearing for anyone auditing the positional `SELECT *`
copy, where column-count mismatch would abort the migration.

Fix: correct the sentence to scope the `uid` remark to `mail_messages`.

### <P3> services/mail-server/migrations/127_webhook_retry_ladder.sql:14-25 — rows whose `retry_policy` object lacks `maxRetries` are not raised

Evidence:

```sql
WHERE retry_policy IS NULL
   OR (retry_policy->>'maxRetries')::int < 10;
...
UPDATE webhooks SET retry_policy = '{...}'::jsonb WHERE retry_policy IS NULL;
```

For `retry_policy = '{}'::jsonb` the key extraction yields NULL, `NULL::int < 10` is NULL, and
the second UPDATE only catches whole-column NULL — so a `{}` policy keeps its empty shape instead
of adopting the 10-attempt ladder, contrary to "raise any maxRetries below 10 to 10". (A
non-numeric value would instead abort the migration on the cast.)

Why: the stated contract and the SQL disagree for a shape the column's JSONB type permits.

Fix: `OR COALESCE(retry_policy->>'maxRetries', '0')::int < 10` (and
`COALESCE(...,'{}')` for the second UPDATE).

### Verified-clean observations (no finding, recorded because they were checked against the brief's bar)

* **Hash chain / head advance.** The brief's example is "a hash-chain table without the
  head-advance trigger". `audit_chain_head` (105) has no trigger by design: the head is advanced
  by an `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING prev_hash` in the same transaction as
  the `audit_logs` insert (`crates/api-server/src/audit_log.rs:218-223`), and the migration
  documents the mixed-version fork risk. Nothing in the database forces a writer to advance the
  head; the contract is application-level. Informational only — the mechanism exists where the
  code writes audit rows.
* **Queue dedup keys.** `email_queue` itself has no unique send key, but every exactly-once
  layer the chain intends is present and keyed: `messages.idempotency_key` (096, unique per
  tenant), `idempotency_records` (153, unique tenant+key), `usage_operations.operation_key`
  (179, global unique), `invoice_collection_outbox` (138, unique invoice+operation),
  `sales_delivery_acceptances`/`outbound_relay_ledger` (205/212, `send_unit` PK),
  `automation_trigger_events`/`automation_runs`/`automation_run_actions` (224, derived keys),
  `campaign_recipients` (236, unique campaign+contact). No orphaned duplicate-send path found.
* **Suppression stores are split but reconciled.** `suppression_list` (038) and `suppressions`
  (088) are both live: the preference center and GDPR automation write `suppression_list`, the
  send gate/API/worker write `suppressions`, and the only reason a preference-center opt-out is
  enforced is `compliance/src/consent_enforcement.rs:405-428`, which checks `suppressions` then
  falls back to `suppression_list`; `billing-service/src/send_admission.rs:157` (labelled "THE
  canonical tenant suppression lookup") checks only `suppressions`. This is a load-bearing dual
  store with no migration reconciling it — worth a consolidation task, not a present defect.
* **Unscoped DML.** Statement-level scan of all 216 files: no `DELETE`/`UPDATE` without a
  top-level `WHERE`. The only self-incrementing UPDATE (213:93,
  `statutory_due_at = received_at + interval '1 month'`) is scoped and idempotent via
  `WHERE ... IS NULL`.
* **Partition conversion column fidelity.** No migration between 001 and 049 adds a column to
  `email_queue`/`mail_messages`/`audit_logs`/`bounce_analytics_daily`/`email_delivery_log` other
  than 002's `mail_messages.uid`, which 050 handles with an explicit column list; the other four
  use `SELECT *` against shape-identical recreated tables.
* **Legacy slots.** 004-019 are byte-identical stubs (`shasum -a 256` gives one digest for all
  16; content is a four-line comment plus `SELECT 1;`).
* **migration_lint on the current tree.** `migration_lint: 216 migrations clean (136 header-style
  grandfathered, 2 semantic exemptions — all ledger-frozen)`; can-fail proven with synthetic
  files (CREATE TABLE without guards is caught; stale exemptions are caught).

---

## Coverage ledger — gates

Status key: **VERIFIED** = can-fail demonstrated by execution; **BY-CONSTRUCTION** = failure path
read in code, not executed; **BROKEN** = the gate or its self-test does not work as shipped;
**ORPHANED** = no CI/Makefile/pre-commit caller; **NOT-A-GATE** = helper.

| Gate | Wired from | Can-fail evidence | Status |
|---|---|---|---|
| tools/check_audit_coverage.py | ci/stages/test.sh:1035 | temp-root probe: missing ledger crates → exit 1 | VERIFIED |
| tools/check_capability_claims.py | ci/stages/validate.sh:289 | `--self-test` PASS; registry/compose/docker source reads | VERIFIED |
| tools/check_cargo_cycles.py | ci/stages/test.sh:1020 | DFS cycle detection on `cargo metadata` (not executed; needs a real cycle) | BY-CONSTRUCTION |
| tools/check_claim_expiry.py | validate.sh:393 (advisory) | registry parse + expiry math (not executed) | BY-CONSTRUCTION |
| tools/check_docs_architecture_truth.py | ci/stages/docs.sh:56,61 (`--selftest` also wired) | `--selftest` PASS (7 cases + pristine) | VERIFIED |
| tools/check_eval_corpora.py | validate.sh:321-322 (`--self-test` also wired) | `--self-test` PASS (6 mutations + pristine) | VERIFIED |
| tools/check_feature_entitlements.py | test.sh:1026 | `--selftest` PASS (synthetic unclassified field detected) | VERIFIED |
| tools/check_flash_copy.py | ci/stages/ui.sh:102 | currently FAILS on uncommitted web.rs leaked-error-display (gate printed :5670; site now at :5684); external-root arg crashes (P3) | VERIFIED (failure real) |
| tools/check_hsts_preload.py | nothing (manual doc only) | missing header → exit 1 by code path (not executed; needs network) | ORPHANED |
| tools/check_image_pinning.py | validate.sh:265-271, images.sh, deploy.sh:183 | `--self-test` ALL OK + pass/fail fixtures invoked in CI | VERIFIED |
| tools/check_knowledge_consistency.py | validate.sh:311-315 (gate + `--self-test`) | `--self-test` and `main()` crash (AssertionError, line 157) on current sources | BROKEN |
| tools/check_marketing_contrast.py | nothing | validates hardcoded constants only; no file input | ORPHANED + CANNOT-FAIL vs real surface |
| tools/check_outbound_delivery_contract.py | validate.sh:248 | unapproved `SmtpSender` in a synthetic tree (by construction); `.sql` not scanned (P2) | BY-CONSTRUCTION |
| tools/check_rust_panic_paths.py | validate.sh:247 | `MAX_RUST_PANIC_PATHS=1` probe → exit 1 with examples | VERIFIED |
| tools/check_security_posture.py | validate.sh:250, deploy.sh:192 | `--self-test` PASS (4 mutation classes + fixtures) | VERIFIED |
| tools/check_soft_skips.py | test.sh:203 (release mode only) | `--self-test`: 42/42 cases | VERIFIED |
| tools/check_topology_contracts.py | validate.sh:249 | plain run PASS; exhaustiveness both directions in code | BY-CONSTRUCTION |
| tools/check_ui_a11y.py | ui.sh:108 | bad-fixture probe → exit 1 (`img-alt`) | VERIFIED |
| tools/check_ui_form_hygiene.py | ui.sh:105 | bad-fixture probe → exit 1 (`unregistered-action`) | VERIFIED |
| tools/check_ui_links.py | ui.sh:111 | bad-fixture probe → exit 1 (`dead-link`); marketing-absent vacuous path (P3) | VERIFIED |
| tools/check_ui_terminology.py | ui.sh:114 (advisory) | bad-fixture probe → exit 1 (wrong-case-brand + banned phrases) | VERIFIED |
| tools/check_web_error_honesty.py | validate.sh:256 | core: production-region injection → exit 1; `--self-test` fails (masker bug, P1) | BROKEN self-test |
| tools/check-compare-pricing-parity.py | Rust test `ui-foundation/tests/compare_pricing_parity_gate.rs:34` (runs under cargo test) | locale/date/vocabulary checks by construction (not executed) | BY-CONSTRUCTION |
| tools/check-forbidden-patterns.sh | validate.sh:589, pre-commit | temp-cwd probe with `signed proof` → exit 1; empty public/ → vacuous 0 (P3) | VERIFIED (+ vacuous path) |
| tools/check-kiwi-marketing-isolation.sh | validate.sh:243, Makefile, pre-commit | temp-cwd probe with `kiwicaptcha` → exit 1 | VERIFIED |
| tools/check-risk-lua-parity.sh | nothing | parity/trust-neutral checks in code | ORPHANED |
| tools/docs-lint.sh | validate.sh:328-345 | empty baseline → exit 1 (total 2827); baseline ratchet + integrity | VERIFIED |
| tools/migration_lint.py | validate.sh:370, pipeline.sh:502 | synthetic bad files → `[create-table]` failure + stale-exemption failure; no DML rule (P3) | VERIFIED |
| tools/validate-prod-env.sh | validate.sh:52, Makefile | bad env probe → exit 1 with named vars | VERIFIED |
| tools/validate_legal_identity.py | validate.sh:598 | empty build dir → exit 1 | VERIFIED |
| tools/validate_pricing_drift.py | validate.sh:597 (REQUIRED), scripts/consistency-test.sh | currently fails `cannot parse runtime overage rates` (P1); green on HEAD run 201028 | BROKEN on working tree |
| tools/validate_security_feature_flags.py | test.sh:1021 | flag/default grep (not executed) | BY-CONSTRUCTION |
| tools/i18n-audit.py | test.sh:954 | currently exit 1 (3 missing keys) | VERIFIED |
| tools/extract_ui_strings.py | ui.sh:117 (`--check`) | currently exit 1 (catalog drift; last CI ui failure) | VERIFIED |
| tools/generate_repo_map.py | validate.sh:349 (`--check`) | generated-vs-committed diff (green now; not executed as failure) | BY-CONSTRUCTION |
| tools/contrast-audit/gate.sh | test.sh:877 | audit.mjs `--self-test` 12/12 PASS; missing prereqs exit 1 by script | VERIFIED |
| tools/contrast-audit/layout-gate.sh | test.sh:929 | prereq-fail paths in script; layout-audit.mjs has no self-test | BY-CONSTRUCTION |
| tools/contrast-audit/audit.mjs | via gate.sh, test.sh:878 | `--self-test` 12/12 PASS (reports/self-test.json) | VERIFIED |
| tools/contrast-audit/layout-audit.mjs | via layout-gate.sh | no self-test | BY-CONSTRUCTION |
| tools/contrast-audit/tag-balance.py | test.sh:907 | bad-fixture probe → exit 1 (unclosed tags) | VERIFIED |
| tools/contrast-audit/gen-summary.py, crop.mjs | support (referenced by each other/package.json) | n/a | NOT-A-GATE |
| tools/browser_smoke.py, run-browser-smoke.sh, run-compose-smoke.sh, run-mail-server-tests.sh, dev-start.sh, bootstrap.sh, update-checksums.sh, e2e_signup_login.sh, poll_instance.sh, route_audit.sh, post_github_status.sh | not CI gates (post_github_status.sh is called by .woodpecker.yml:255,270 and its presence is asserted by validate.sh:185) | n/a | NOT-A-GATE (several undocumented in tools/README) |

## Coverage ledger — migrations (216 files)

`[x]` = read in full; `[p]` = read in part (the brief-relevant sections, noted per file);
`[s]` = screened by the statement-splitting analyzer + targeted greps (unscoped DML, rerun
hazards, unguarded DDL, dedup keys, duplicate table definitions, comments claiming behavior) but
not read line-by-line. Findings/notes referenced by filename where applicable.

Ledger totals: 41 `[x]`, 14 `[p]`, 161 `[s]` = 216 files.

- [x] 001_initial_schema.sql
- [x] 002_mailstore_uid.sql
- [s] 003_dedicated_ips.sql
- [s] 004_legacy_schema_slot_reserved.sql
- [s] 005_legacy_schema_slot_reserved.sql
- [s] 006_legacy_schema_slot_reserved.sql
- [s] 007_legacy_schema_slot_reserved.sql
- [s] 008_legacy_schema_slot_reserved.sql
- [s] 009_legacy_schema_slot_reserved.sql
- [s] 010_legacy_schema_slot_reserved.sql
- [s] 011_legacy_schema_slot_reserved.sql
- [s] 012_legacy_schema_slot_reserved.sql
- [s] 013_legacy_schema_slot_reserved.sql
- [s] 014_legacy_schema_slot_reserved.sql
- [s] 015_legacy_schema_slot_reserved.sql
- [s] 016_legacy_schema_slot_reserved.sql
- [s] 017_legacy_schema_slot_reserved.sql
- [s] 018_legacy_schema_slot_reserved.sql
- [s] 019_legacy_schema_slot_reserved.sql
- [s] 020_ses_monitoring.sql
- [p] 021_hybrid_infrastructure.sql — analyzer-flagged indexes are inside an IF-NOT-EXISTS DO block (verified clean)
- [s] 022_enterprise_billing_contracts.sql
- [s] 023_enterprise_support_sso.sql
- [s] 024_billing_alert_runtime.sql
- [s] 025_mfa_recovery_codes.sql
- [s] 026_metering_events_composite_index.sql
- [s] 027_vat_kmd_returns.sql
- [s] 028_month_end_closing.sql
- [s] 029_add_performance_indexes.sql
- [s] 030_bounce_analytics.sql
- [s] 031_system_alerts_tenant_scope.sql
- [s] 032_grader_results.sql
- [s] 033_seed_providers.sql
- [s] 034_seed_accounts.sql
- [s] 035_placement_tests.sql
- [s] 036_placement_results.sql
- [s] 037_seed_accounts_failure_tracking.sql
- [x] 038_compliance_core_tables.sql
- [s] 039_soc2_hipaa_trust_portal.sql
- [s] 040_postmaster_reputation.sql
- [s] 041_provider_throttle_overrides.sql
- [s] 042_warmup_schedule_drift_fix.sql
- [s] 043_enterprise_private_deploy.sql
- [s] 044_ai_send_time_cache.sql
- [s] 045_create_dunning_config.sql
- [x] 046_add_text_column_constraints.sql
- [s] 047_add_labels_gin_index.sql
- [s] 048_add_mailboxes_parent_id_index.sql
- [s] 049_add_delivery_log_composite_index.sql
- [x] 050_partition_high_volume_tables.sql — P1 H-08 warn-then-drop x5; P3 uid comment
- [s] 051_add_missing_performance_indexes.sql
- [p] 052_add_missing_foundation_tables.sql — dead_letter_queue has no dedup key (052/056/059 re-create it); not treated as a finding (worker-owned)
- [x] 053_recreate_delivery_log_fk.sql
- [s] 054_remaining_schema_fixes.sql
- [s] 055_e2e_schema_fixes.sql
- [s] 056_fix_critical_schema_issues.sql
- [s] 057_add_mfa_constraints.sql
- [s] 058_fix_high_severity_faults.sql
- [s] 059_verify_all_p0_faults_resolved.sql
- [s] 060_add_down_migration_support.sql
- [s] 061_fix_remaining_db_faults.sql
- [x] 062_add_email_queue_new_schema.sql
- [s] 063_add_db_audit_fixes.sql
- [p] 064_standardize_tenant_id_varchar26.sql — _tenant_id_map temp INSERT is inside a per-row DO loop with candidate guard (verified clean)
- [s] 065_webhook_dual_secret_rotation.sql
- [s] 066_fix_remaining_db_faults_v2.sql — metering_events conversion: CREATE + dynamic partitions under early-RETURN guard; registered ledger exemption
- [s] 067_fix_remaining_db_faults_v3.sql
- [s] 068_create_lists_tables.sql
- [s] 069_create_missing_app_tables.sql
- [s] 070_fix_column_mismatches.sql
- [p] 071_fix_live_sim_schema.sql — ADD COLUMN guarded by to_regclass + DROP COLUMN IF EXISTS (verified clean)
- [s] 072_seed_system_tenant_domain.sql
- [s] 073_fix_messages_table_schema.sql
- [s] 074_stripe_billing_schema_fixes.sql
- [s] 075_create_missing_tables.sql
- [s] 076_fix_column_mismatches.sql
- [s] 077_add_hipaa_event_signature.sql
- [s] 078_race_condition_fixes.sql
- [s] 079_estonia_ou_compliance.sql
- [s] 080_report_history.sql
- [s] 081_audit_fts.sql
- [s] 082_health_check_history.sql
- [s] 083_add_analytics_indexes.sql
- [s] 084_enhance_compliance_submissions.sql
- [x] 085_cp_access_log.sql
- [s] 086_add_reply_to_headers_attachments_stream.sql
- [s] 087_create_scim_users_and_dunning_records.sql
- [x] 088_unify_email_queue_inbound_schema.sql
- [s] 089_analytics_hourly.sql
- [s] 090_widen_events_id_columns.sql
- [s] 091_add_message_stats_columns.sql
- [s] 092_enterprise_missing_tables.sql
- [p] 093_deep_schema_convergence.sql — creates complaint_events/sender_reputation shapes that make 095's CREATE dead (see P2 finding)
- [s] 094_add_domain_dkim_key_columns.sql
- [x] 095_mta_bounce_fbl_hardening.sql — P2 comment/DDL divergence vs 093
- [x] 096_messages_idempotency_column.sql
- [s] 097_drop_account_message_id_unique.sql
- [s] 098_billing_service_schema_fixes.sql
- [s] 099_admin_override_columns.sql
- [s] 100_domain_dkim_readiness_hardening.sql
- [s] 101_billing_revenue_integrity_fixes.sql
- [x] 102_message_dedup_delivery_scope.sql
- [x] 103_queue_lease_token.sql
- [s] 104_usage_metering_reconciliation_wallet_width.sql
- [x] 105_audit_chain_head.sql
- [s] 106_users_login_functional_indexes.sql
- [s] 107_template_version_snapshots.sql
- [s] 108_analytics_reality_writers.sql
- [x] 109_init.sql
- [x] 110_uid_backfill.sql — P2 UIDNEXT can decrease (GREATEST fix)
- [s] 111_raw_message.sql
- [s] 112_mailbox_unique_name.sql
- [x] 113_dedup_exempt.sql
- [s] 114_inbound_legacy_columns_nullable.sql
- [x] 115_repair_partition_conversion_losses.sql — P1 comment promises partitioned-parent check the code omits
- [p] 116_financial_integrity_constraints.sql — unique indexes inside pg_indexes guards (verified clean)
- [s] 117_metering_events_reconciliation.sql
- [s] 118_dunning_event_invoice_id_width.sql
- [x] 119_ha_audit_tables.sql
- [s] 120_ip_pool_allocated_to_varchar26.sql
- [x] 121_compliance_retention_legal_hold.sql
- [s] 122_invoice_vat_rate_double_precision.sql
- [s] 123_ai_assistant.sql
- [s] 124_user_identities.sql
- [s] 125_verification_token_index.sql
- [s] 126_overage_period_marker.sql
- [x] 127_webhook_retry_ladder.sql — P3 matcher misses policies without maxRetries key
- [x] 128_canonical_webhook_events.sql
- [s] 130_invoice_xml_url.sql
- [s] 131_plan_overrides_updated_at.sql
- [s] 132_billing_addresses_state_email.sql
- [s] 133_abuse_reports_status.sql
- [s] 134_credit_notes.sql
- [x] 135_stripe_subscriptions_plan_backfill.sql
- [s] 136_invoices_unique_overage_period.sql
- [s] 137_billing_periods.sql
- [x] 138_invoice_collection_outbox.sql — dedup key UNIQUE(invoice_id, operation) present
- [s] 139_invoices_stripe_item_id.sql
- [s] 140_invoice_payment_allocations.sql
- [s] 150_contacts_tags_canonical.sql
- [x] 153_idempotency_ledger_queue_metadata_repair.sql — durable idempotency ledger + webhook claim token; scoped UPDATE
- [s] 159_reply_events_canonical.sql
- [s] 160_edge_case_services.sql
- [s] 161_ha_backup.sql
- [s] 162_ha_chaos.sql
- [s] 163_ha_multi_region.sql
- [s] 164_isolation_tenants.sql
- [s] 165_isolation_audit.sql
- [s] 166_isolation_data_isolation.sql
- [s] 167_isolation_encryption.sql
- [s] 168_compliance_contact_persons.sql
- [s] 169_messages_from_address_drop_not_null.sql
- [s] 170_contacts_tags_validator_repair.sql
- [s] 171_contacts_metadata.sql
- [s] 172_gdpr_request_sla_deadline_policy.sql
- [s] 177_billing_periods_sweep_state.sql
- [s] 178_billing_periods_pricing_snapshot.sql
- [x] 179_usage_operations_ledger.sql — operation_key globally unique; first-claim-wins
- [x] 180_invoice_collection_outbox_lease.sql
- [s] 181_tenant_restrictions.sql
- [s] 182_abuse_reports_legacy_reconciliation.sql
- [s] 183_credit_notes_disposition.sql
- [s] 184_stripe_subscription_event_watermark.sql
- [s] 185_invoices_billing_registry_code.sql
- [p] 186_recipient_delivery_state.sql
- [p] 187_message_category.sql
- [s] 194_ha_health_checks.sql
- [s] 195_iso_access_attempts.sql
- [s] 196_iso_encryption_policies.sql
- [s] 197_campaign_arms.sql
- [s] 198_status_page_incidents_resolved_at.sql
- [s] 199_payroll_tax_inputs.sql
- [p] 200_sales_autopilot_v2_unification.sql
- [s] 201_sales_execution_contract.sql
- [s] 202_sales_feedback_delivery_binding.sql
- [s] 203_schema_repairs.sql
- [s] 204_sales_execution_invariants.sql
- [x] 205_delivery_acceptance_and_applied_markers.sql — send_unit PK; per-event applied marker
- [s] 206_capacity_reservations.sql
- [s] 207_dedicated_ip_provisioning_state.sql
- [s] 208_dedicated_ip_routing_trigger_tenant_type.sql
- [s] 209_consent_evidence.sql
- [x] 210_inbound_delivery_ledger.sql — (message_id, recipient) PK; status CHECK + lease indexes
- [x] 211_verp_v2_and_fbl_registry.sql — token-hash PK; authoritative=FALSE default; seeds ON CONFLICT
- [x] 212_outbound_relay_ledger.sql — send_unit PK; accepted-requires-timestamp CHECK
- [p] 213_compliance_runtime_ddl_to_migrations.sql — P3 dsr_verification_outbox lacks a dedup key
- [s] 214_gdpr_governance_registry.sql
- [s] 215_service_heartbeats.sql
- [s] 216_campaign_start_state.sql
- [s] 218_vat_truth_foundation.sql
- [s] 219_oss_vd_filing_scaffold.sql
- [p] 220_accounting_core.sql
- [p] 221_statutory_filing_completion.sql
- [s] 222_validate_sales_sequence_provenance.sql
- [p] 223_sales_leads_becomes_a_view.sql — table->view with id mapping; backfill guarded; read partially
- [x] 224_automation_execution.sql — derived idempotency keys + unique indexes; triggers ON CONFLICT DO NOTHING
- [s] 225_bank_statement_ingest.sql
- [s] 226_filing_package_validation_evidence.sql
- [s] 227_postmaster_summary_unique.sql
- [s] 228_enterprise_saml_assertion_replay.sql
- [p] 229_user_id_columns_carry_users_id.sql
- [x] 230_outbound_relay_request_fingerprint.sql
- [x] 231_analytics_compaction_ledger.sql — commit-point ledger + exact per-event membership; CASCADE
- [x] 232_enterprise_sso_session_authority.sql
- [x] 233_sequence_step_execution_claim_lease.sql
- [x] 234_auth_sessions.sql — server-side revocable sessions; no request metadata (deliberate)
- [s] 235_plan_override_actor_columns.sql
- [x] 236_campaign_send_pipeline.sql — UNIQUE(campaign_id, contact_id) sender-recipient dedup
- [s] 237_api_key_prefix_display.sql
- [s] 238_campaign_fidelity_segments.sql
- [s] 239_analytics_domain_id_width.sql
- [x] 240_ai_chat_sessions.sql
- [x] 241_first_response_requests.sql — UNIQUE(tenant_id, kind, subject_ref) + claim lane index
- [s] 242_objection_library.sql
- [s] 243_demo_sessions.sql — [s] demo session tables; only schema-level screening (not in the brief's category list)
- [x] 244_first_response_queue_metrics.sql — additive column + partial index


## What I did not reach (honest limits)

* **Migrations:** 41 of 216 files were read in full (all queue/ledger/audit/suppression/session
  files that define the contracts: 001, 002, 038, 046, 050, 053, 062, 085, 088, 095, 096, 102,
  103, 105, 109, 110, 113, 115, 119, 121, 127, 128, 135, 138, 153, 179, 180, 205, 210, 211, 212,
  224, 230, 231, 232, 233, 234, 236, 240, 241, 244); 14 were read in part (the brief-relevant
  sections of 021, 052, 064, 071, 093, 116, 186, 187, 200, 213, 220, 221, 223, 229). The
  remaining 161 were screened, not line-read — in particular I did not line-read the six `fix_*_db_faults` repair files (054-067,
  ~200KB total) or the large sales/accounting unifications (200, 220, 221, 222), beyond the
  analyzer and targeted pattern checks.
  No DOWN/rollback sections were executed against a live Postgres: there is no local database in
  this environment, so every SQL-semantics claim above is static (the H-08/115 findings are
  logic/présence findings, not observed data loss).
* **Gates:** `check_cargo_cycles.py`, `check_claim_expiry.py`,
  `validate_security_feature_flags.py`, `check_topology_contracts.py`,
  `check_outbound_delivery_contract.py`, `check-compare-pricing-parity.py`,
  `generate_repo_map.py --check`, `layout-audit.mjs` and `layout-gate.sh` were not mutated/probed;
  their can-fail status is by-construction and marked as such above. `check_hsts_preload.py` was
  not run (needs a public HTTPS endpoint). The full `ci/stages/validate.sh` and `test.sh` were not
  executed end-to-end (heavy: cargo builds, zola, playwright); individual gates were run instead.
  `tools/browser_smoke.py`, `tools/run-*.sh`, `tools/e2e_signup_login.sh`, `tools/route_audit.sh`,
  `tools/poll_instance.sh`, `tools/bootstrap.sh`, `tools/dev-start.sh`,
  `tools/update-checksums.sh` were classified for wiring only, not exercised.
* **Tree drift:** the working tree changed while this review ran (see Snapshot). Findings P1-1,
  P1-3, the flash-copy leak, the i18n failure and the catalog drift are statements about this
  dirty snapshot; HEAD's validate run (`ci/runs/20261006T201028_91588`) was green for the
  knowledge-consistency and pricing-drift gates. Re-verify after the in-flight edits settle.
