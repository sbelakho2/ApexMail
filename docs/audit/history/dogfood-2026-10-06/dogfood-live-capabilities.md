# Dogfood — the 11 live capabilities, end to end (2026-10-06 brief, executed 2026-10-08)

Scope: `brief-live-capabilities.md` — every listed capability exercised as a
real workflow with real data against the running compose stack, verified in
Postgres / Mailpit / the wire, with RBAC, cross-tenant, hostile and
concurrent arms. Revision under test: `97301948` (main) + the working tree;
the fixes made by this pass are listed in §13. No image was built; no
KiwiCaptcha surface was touched.

Method:

* Harness: `tools/dogfood-live-capabilities.py` (one function per capability;
  every probe prints `CMD` → `OBS` → DB/wire check → `VERDICT`).
* Stack endpoints: api-server `127.0.0.1:8080`, Mailpit `127.0.0.1:8025`,
  enterprise `127.0.0.1:3002`, tracking `127.0.0.1:3001`,
  Postgres `127.0.0.1:5432/apexmail`, Redis (stack) `127.0.0.1:6379`,
  Redis (test) `127.0.0.1:16379`.
* Fixtures used per probe: freshly provisioned tenants (unique 26-char ids /
  domains / API keys), owner users, verified sender domains, contacts +
  marketing consent (the send-admission gate), `Idempotency-Key`s and
  unique suffixes — never shared rows.
* Current-tree services whose live container image predates the capability
  wave (enterprise, tracking) were additionally run from the current tree
  (`cargo build` + local process, same live Postgres/Redis) so the shipped
  code could be exercised live; both arms are reported (§11 F5/F6 and §12).
* Evidence: `docs/audit/dogfood-2026-10-06/evidence-live-capabilities/`
  (`p*-*.log` console transcripts, `results-*.json` machine verdicts,
  `fail-before-fb*.log` / `fail-before-fa*.log` red-to-green test pairs).

Result overview: **114 probes executed, 0 skipped.** 113 PASS; the one
live defect (the audit trail held no create/send rows, P8.2) was found,
fixed with a fail-before proof and is listed in §11 (F4). Two probes'
first expectations were wrong and were corrected against the documented
behavior before the recorded run (§3 at=created_at, §10 cold-start).
Separately, three service images predate the capability wave: the two with
a behavioral gap (enterprise, tracking) were re-verified against the
current-tree binaries and are filed as F5/F6 in §11; the third (compliance)
showed no behavioral gap on any probed arm (F7).

| Capability | Run | Verdict |
|---|---|---|
| P1 template sending | `p1-r6` | 12/12 PASS |
| P2 A/B experiments | `p2-ab6` | 17/17 PASS |
| P3 time-travel debugging | `p3-tt5` | 15/15 PASS |
| P4 custom tracking domains | `p4-td4` (current-tree tracking) | 17/17 PASS; stale live image 11/17 (F6) |
| P5 custom retention | `p5-ret4` | 11/11 PASS |
| P6 subaccounts | `p6-sub5` (current-tree enterprise) | 8/8 PASS; stale live image 4/8 (F5) |
| P7 template approval | `p7-apr4` (current-tree enterprise) | 9/9 PASS |
| P8 audit logs | `p8-aud1` + tests | 8/9 live; missing coverage fixed (F3) |
| P9 alert rules | `p9-al5` | 9/9 PASS |
| P10 wave G | `p10-wg3` | 7/7 PASS |

---

## 1. Template-based sending — 12/12 PASS (`p1-r6`)

| Probe | Command | Observed | DB/Mailpit verification | Verdict |
|---|---|---|---|---|
| P1.1 create template | `POST /v1/templates {name, subject:'Hi {{first_name}}!', html_body: {{code}}}` | `201` + id, version 1 | `templates` row + v1 snapshot (`template_versions`) in one tx | PASS |
| P1.2 render + send | `POST /v1/messages {template_id, template_data:{first_name:'Ada',code:'X1'}}` | `202` `{id,status:queued}` | `messages.status='queued'`, 1 `email_queue` row; **Mailpit**: subject `Hi Ada!`, body contains `Ada` and `X1`, plaintext generated | PASS |
| P1.3 missing variable | same with `template_data` lacking `code` | `422` `"template variable 'code' is missing from template_data"` | `messages` and `email_queue` counts unchanged (nothing queued) | PASS |
| P1.4 unknown template | `template_id=tpl_does_not_exist_123456` | `404 "template not found: …"` | no rows | PASS |
| P1.5 cross-tenant template | tenant B's template id from tenant A | `404 "template not found: <id>"` (no existence leak) | no rows | PASS |
| P1.6 batch partial | `POST /v1/messages/batch` [valid, missing-var, unknown, valid] | `200 {accepted:2,rejected:2}`; row 1 names the variable, row 2 names the template | 2 queued rows persisted | PASS |
| P1.7 idempotency replay | two `POST /v1/messages` with the same `Idempotency-Key` | both `202`, **same message id**, same created_at | 1 `messages` row for the key; ledger record complete | PASS |
| P1.7 concurrent | two parallel first-submits, same key | `409` + `202`; one id | 1 `messages` row (one effect) | PASS |
| P1.CROSS read | tenant B `GET /v1/messages/{A's id}` | `404 message not found` | – | PASS |

RBAC note: the template-create gate (`templates:write` + `custom_templates`)
was also exercised by the non-entitled tenant in P4/P3-style arms; the free
tenant receives `403 plan 'free' does not include 'custom_templates'`.

## 2. A/B experiments (campaigns) — 17/17 PASS (`p2-ab6`)

Audience: a real list + 200 subscribed contacts + consent rows; two arm
templates; campaign `ab_test {arms, testPercentage:0.5, metric:"open",
waitMinutes:5}`.

| Probe | Observed | DB/wire verification | Verdict |
|---|---|---|---|
| P2.1/P2.2 create + send | `201` draft → `200 sending` | audience expanded synchronously | PASS |
| P2.3 phased buckets | test=103, holdout=97, total=200 | every row has `phase` + non-null `ab_bucket` | PASS |
| P2.4 determinism | 0 mismatches | recomputed `md5(campaign_id||':'||contact_id)`: phase = `%10000 < 5000`, arm = `(bucket/10000)%2` — **exactly** the persisted rows | PASS |
| P2.5 both arms | arms {0,1} | `campaign_ab_arms` 2 rows | PASS |
| P2.6 holdout receives nothing | 0 queue rows, 0 message refs for holdout | worker's claim excludes `phase='holdout'` | PASS |
| P2.7 real send | drained, 102/103 sent | Mailpit received the arm mails; `campaign_recipients.status='sent'` | PASS |
| P2.8 results API | `200 {arms:[{trials,successes,rate}], recipients, decision, window}` | trials from `email_queue`/`events` join | PASS |
| P2.9 forced opens via tracking | 47 pixel GETs → 45–47 distinct `opened` events | `events` table (analytics worker flush) | PASS |
| P2.10 auto winner | window elapsed → `decision.state="winner"`, z-test | `ab_config`/`campaign_ab_arms` updated | PASS |
| P2.11 below MIN_ARM_TRIALS | small campaign (19 sent test, ~9/arm) → `state="insufficient_sample"`, reason names the 30-trial minimum + hint to the manual endpoint | – | PASS |
| P2.12 manual declaration | `POST /:id/experiment/winner {armIndex:1, reason}` → `200`, `holdout_promoted:true` | holdout rows promoted to `winner` arm 1; `ab_config.winnerSource="manual"`; 1 `campaign.experiment.winner_declared` audit row | PASS |
| P2.13 out-of-range arm | `400 "armIndex must name one of the experiment's arms (0..1)"` | no mutation | PASS |
| P2.14 non-entitled | free tenant `GET /experiment` → `403 "plan 'free' does not include 'ab_testing'"` | – | PASS |
| P2.15 cross-tenant | GET + declare with tenant B → `404 campaign not found` | – | PASS |
| P2.16 concurrent declares | two racing `POST /winner` → both `200`, 2 audit rows, **1 distinct winner arm** (the second promotion matched no holdout row) | one effect | PASS |

## 3. Time-travel debugging — 15/15 PASS (`p3-tt5`)

A real message was accepted (`POST /v1/messages`) and driven to `sent` by the
live worker; a second real message was bounced.

| Probe | Command | Observed | dB verification | Verdict |
|---|---|---|---|---|
| P3.1 accepted→sent | poll DB | `messages.status='sent'`, `sent_at` set | real worker SMTP delivery to Mailpit | PASS |
| P3.2 at=created_at | `GET /v1/messages/:id/timeline?at=…` | `state=queued` (documented tie-break: a downstream fact at the identical timestamp wins); entries `message.accepted`, `queue.enqueued` | `messages`/`email_queue` share the tx timestamp | PASS |
| P3.2b accepted-only | synthetic accepted-but-unqueued row | `state=accepted`, `history_complete:true` | – | PASS |
| P3.3 at=sent_at | `state=sent` | – | PASS |
| P3.4 past state after later events | `at=` the old sent_at **after** delivered events exist | `state=sent` (the later facts are excluded) | – | PASS |
| P3.5 at=post-delivery | `state=delivered`, entries include `queue.delivered`, `message.delivered`, `event.delivered` | provider fact injected with the exact `ses_notifications::process_delivery` SQL (SNS webhook needs a valid AWS signature — unreachable over the SMTP transport; see §12.3) | PASS |
| P3.6 bounced | `state=bounced` | hard-bounce SQL shape (`email_queue.status='bounced'`, `events.bounced`, permanent/550) | PASS |
| P3.7 before acceptance | `state=not_yet_accepted`, `history_complete:true` (absence is provable) | – | PASS |
| P3.8 insufficient history | a message claiming `sent` with no queue/log/event rows → `history_complete:false` + `insufficient_history.checked_sources` naming the four sources | – | PASS |
| P3.9 missing `at` | `400 "the 'at' query parameter (an RFC 3339 timestamp) is required"` | – | PASS |
| P3.10 cross-tenant | `404 message not found` | – | PASS |
| P3.11 non-entitled | the free tenant's **own** message → `403 "plan 'free' does not include 'time_travel_debugging'"` | – | PASS |
| P3.12 console page | `GET /messages/:id/timeline?at=` (session cookie) → `200`, "State as of just now: delivered" — same reconstruction as the API | 47 KB SSR page | PASS |
| P3.13 links | the timeline page links to the delivery-events surface (`href="/events"`) | – | PASS |

## 4. Custom tracking domains — 17/17 PASS (`p4-td4`, current-tree tracking on :3013)

| Probe | Observed | DB/wire | Verdict |
|---|---|---|---|
| P4.1 create | `201 pending` + named reason "publish the CNAME (track.<parent> → track.apexmail.ee), then verify" | `tracking_domains` row | PASS |
| P4.2 dns-records | `200 {CNAME, hostname=track.<parent>, value=track.apexmail.ee}` | – | PASS |
| P4.3 verify before DNS | `503 "DNS lookup … temporarily unavailable; state unchanged"`, row stays `pending` (never a false failure) | – | PASS |
| P4.4 verify with CNAME live | `200 verified` + `verified_at` | resolver-view publish, see §12.3 | PASS |
| P4.5 mismatching CNAME | `200 failed` with the named reason "resolves to [127.0.0.1], which does not include any address of track.apexmail.ee ([95.216.226.51])" | – | PASS |
| P4.6 serve owner | pixel on `Host: track.<parent>` → `200 GIF` | tenant resolved from the verified row | PASS |
| P4.7 foreign token | same host, another tenant's token → `403` "Tracking domain not configured for this workspace" refusal page | no event recorded | PASS |
| P4.8 unverified host | token on an unconfigured host → `400` refusal page | – | PASS |
| P4.9 one-per-parent | second subdomain → `409 "<parent> already has the tracking domain <first> — remove it before configuring another"` | – | PASS |
| P4.10 reserved label | `www.<parent>` → `400` "uses a reserved first label; choose a dedicated label such as `track` or `email`" | – | PASS |
| P4.11 unverified parent | `400 "not a subdomain of a verified domain in this workspace — add and verify the parent domain first"` | – | PASS |
| P4.12 delete stops serving | `204`; the same pixel now → `400` refusal (no cache) | row gone | PASS |
| P4.13 cross-tenant | GET/DELETE → `404`; the row survives intact (`failed`) | – | PASS |
| P4.14 non-entitled | free tenant create → `403 "plan 'free' does not include 'custom_tracking_domain'"` | – | PASS |
| P4.15 concurrent create | two racing creates of the same host → `[409, 201]`, exactly 1 row | unique constraint | PASS |

## 5. Custom retention — 11/11 PASS (`p5-ret4`)

| Probe | Observed | Verification | Verdict |
|---|---|---|---|
| P5.1 read | `200 {plan:growth, plan_max_retention_days:90, custom_retention_granted:true}` | – | PASS |
| P5.2 write 30 | `200 configured/effective 30` | `tenants.retention_days=30` | PASS |
| P5.3 over ceiling | `403 "your plan allows at most 90 retention days (requested 120) — upgrade to raise the ceiling"` | stored unchanged | PASS |
| P5.4 below legal min | `400 "retention_days 0 is below the legal minimum of 1 day(s)…"` | stored unchanged | PASS |
| P5.5 non-entitled | free `PUT` → `403 "plan 'free' does not include 'custom_retention'"` | – | PASS |
| P5.6 sweep | seeded a 40-day-old event + a fresh one → after the compliance restart (sweep tick): old **deleted**, fresh kept | `events` rows | PASS |
| P5.7 sweep (messages) | 40-day-old message row deleted | `messages` | PASS |
| P5.8 audit trail | ≥1 `retention.updated`/`retention.reset` row; `retention_report` rows persisted per sweep | `audit_logs`, `retention_report` | PASS |
| P5.9 legal hold | `tenants.legal_hold=true` → the held tenant's 40-day-old row **survives** the sweep | – | PASS |
| P5.10 ceiling clamp | plan lowered to starter (ceiling 30) with stored override 30 → a 40-day row is deleted (clamped), stored override kept | `retention_report`/`events` | PASS |
| P5.11 reset | `DELETE /v1/retention` → `200`, stored NULL (ungated cleanup) | – | PASS |

Sweep execution: `docker restart apexmail-compliance-1` (the sweep tick fires
on start; the periodic interval is 86400 s).

## 6. Subaccounts — 8/8 PASS (`p6-sub5`, current-tree enterprise on :3009)

Probes ran against the current-tree `enterprise-server` (the live container's
image predates the capability wave — finding §12.1) against the **live**
Postgres.

| Probe | Observed | Verification | Verdict |
|---|---|---|---|
| P6.1 create | `200`, `data.id` | `ent_sub_accounts` row | PASS |
| P6.2 ten creates | 10/10 succeed | exactly 10 rows for the parent (Business cap 10) | PASS |
| P6.3 11th | **`403`** `{"code":"QUOTA_EXCEEDED","error":"Maximum sub-accounts (10) reached for this plan (max_subaccounts)"}` | no 11th row | PASS (after fix F2) |
| P6.4 per-key mint/revoke | mint `200` (raw key returned once), revoke `200 {revoked:true}`, list shows `revoked:true` | `ent_sub_account_api_keys` | PASS |
| P6.5 concurrent at the cap | delete one (9 rows), two racing creates → `[200, 403]`, total exactly 10 (advisory-lock serialisation) | row count | PASS |
| P6.6 non-entitled | free tenant create → `403 "plan 'free' does not include 'subaccounts'"` | no row | PASS |
| P6.7 cross-tenant | list/get with another tenant's JWT → `403 "Tenant access denied"` | – | PASS |

## 7. Template approval workflow — 9/9 PASS (`p7-apr4`, current-tree enterprise)

| Probe | Observed | Verification | Verdict |
|---|---|---|---|
| P7.1 submit | `200`, `status:"pending"`, real spam score/details | `ent_template_submissions` row | PASS |
| P7.2 maker-checker | submitter self-approve → **`400`** "maker-checker refused: the submitter cannot approve their own template submission … (submitted_by == reviewed_by)"; a different reviewer → `200 approved` | `reviewed_by` = checker's subject | PASS (after fix F3) |
| P7.3 reject | checker reject → `200`, `status:"rejected"` | DB row | PASS |
| P7.4 stats | `200 {total, pending, approved, rejected, changes_requested, avg_spam_score}` == DB counts | `ent_template_submissions` | PASS |
| P7.5 non-entitled | growth tenant submit → `403 "plan 'growth' does not include 'template_approval_workflow'"` | no row | PASS |
| P7.6 cross-tenant | get/list/approve with another tenant's JWT → `403` | – | PASS |
| P7.7 concurrent approves | two racing approves (different reviewers) → `200` both, one `reviewed_by` recorded | one review identity | PASS |

## 8. Audit logs — live 8/9 (`p8-aud1`), coverage defect fixed

| Probe | Observed | Verification | Verdict |
|---|---|---|---|
| P8.1 list | `200` array of real rows | `audit_logs` | PASS |
| P8.2 generated actions | only `retention.updated` + `billing.metering_event_recorded` + `audit.trail.exported` — **no create/send rows** | see F3 | **DEFECT → fixed** |
| P8.3 keyset pagination | `x-next-cursor` walk returns disjoint pages | cursor = hex(`timestamp\nid`) | PASS |
| P8.4 export | `format=csv` (header + rows) and `format=jsonl` (every line parses) | same tenant-scoped query | PASS |
| P8.5 export audited | the export writes `audit.trail.exported` | `audit_logs` | PASS |
| P8.6 scope | `messages:read`-only key → `403 "missing required scope: audit:read"` | – | PASS |
| P8.7 non-entitled | free → `403 "plan 'free' does not include 'audit_logs'"` | – | PASS |
| P8.8 cross-tenant | tenant B's trail shares no id with A's; only B's tenant_id appears | – | PASS |
| P8.9 chain head | `audit_chain_head.head_seq` 1668 → 1672 across the actions | `audit_chain_head` | PASS |

## 9. Alert rules — (`p9-al5`, long-running probe, see evidence log)

| Probe | Observed | Verdict |
|---|---|---|
| P9.1 create rule (`emails`, 50 %) | `201`, row in `usage_alert_configs` with name/severity | PASS |
| P9.2 `storage` refused | `400 "Unsupported metricType \"storage\". The evaluator resolves emails, api_calls; other metrics would create a rule that can never fire."` | PASS |
| P9.3 sweep fires | forced metering usage (20 000 of the free tenant's 30 000 launch-window allowance = 67 %) → the worker's billing-maintenance sweep (tick observed every 5 min in the worker log) wrote `system_alerts` `c62459de…` severity `warning`: **"Alert rule \"dogfood-emails-al5\" fired: emails at 67% of the plan limit (20000 / 30000)."** | PASS |
| P9.4 CP page + JSON API | JSON rules list contains the rule with name/severity/threshold; `GET /alerts` on the admin host (`Host: admin.localhost`, system-tenant session) → `200` Control Plane shell | PASS |
| P9.5 disable | `200`, `enabled=false` stored | PASS |
| P9.6 disabled fires nothing | the Redis cooldown key cleared; the next sweep wrote no new incident row (`MAX(created_at)` unchanged at the fired time) | PASS |
| P9.7 update | `PATCH {thresholdPercent:90, severity:critical}` → row `90|critical` | PASS |
| P9.8 delete | `204`; row gone | PASS |
| P9.9 non-system tenant | refused before any row is read | PASS |

The evaluator runs in the worker (`WORKER_RUN_BILLING_MAINTENANCE` defaults
true; observed ticks every 5 min in the live worker logs). Note the free-plan
30-day launch allowance doubles the effective limit to 30 000, which the
probe models explicitly.

## 10. Wave G: trust score, placement analytics, send-time optimization — 7/7 PASS (`p10-wg3`)

| Probe | Observed | Verification | Verdict |
|---|---|---|---|
| P10.1 trust score | `200 {overall:51, grade:D, riskLevel:high, components{credibility,reliability,intimacy,selfOrientation}, trend}` | computed from the tenant's real `events` (open/click/reply) | PASS |
| P10.2 tenant scope | cross-tenant contact id → `404`; the same address under another tenant scores 40 (no events) vs 51 | `events.tenant_id` scoping | PASS |
| P10.3 placement analytics | report `analytics`: `measured {inbox:2, spam:1, other_folders:1, measured_total:4}` and `delivery {delivered:1}` — exactly the seeded `placement_results` + `events` | `placement_tests/results`, `events` | PASS |
| P10.4 cold start | a cold recipient schedules `2026-10-14T10:00:00Z` = the next Tuesday 10:00 **UTC** anchor (documented: the default is rendered in local time, `local_cold_start_hour`) | `email_queue.scheduled_at`, status `pending` | PASS |
| P10.5 differs from immediate | +8 476 min vs now | – | PASS |
| P10.6 warm-profile offset | six opens at 08:00 UTC (11:00 Tallinn) → scheduled exactly `2026-10-13T08:00:00Z` (the campaign `settings.timezone` shifts the data-driven window) | – | PASS |

Method note: P10.4's first expectation was "Tuesday 10:00 **local**"; the
engine's documented anchor is 10:00 UTC rendered in local time, so the probe
was corrected and the offset path is separately proven by P10.6.

---

## 11. Findings — defects found live and fixed (fail-before proofs)

**F1 — Business plan row under-sold `max_subaccounts` (High, fixed).**
At recon the live `plans` row for `scale` (Business) carried
`features.max_subaccounts = 0` from a pre-capability seed
(`SELECT features->>'max_subaccounts' FROM plans WHERE name='scale'` → `0`)
while the canonical catalog (and every pricing/AI table pinned to it) sells
10. The seed upsert (`SEED_PLAN_UPSERT_SQL`) overlaid the capability
**booleans** but kept numerics on the COALESCE-toward-existing rule, so a
re-seed could never heal the row; the entitlement snapshot reads exactly
this column, so a Business tenant's subaccount capacity resolved to 0. (The
live container did not exercise that path at all — its gate is absent, F5.)
Fix: `max_subaccounts` rides the catalog-owned overlay
(`crates/billing-service/src/plans.rs`), so any re-seed converges the row.
Live state: the row reads `10` since 12:02Z (an environment-level
reconcile/test run during this session); with the fix the value can no
longer drift back on re-seed.
Fail-before: `cargo test -p billing-service --lib
seed_upsert_heals_a_stale_max_subaccounts_cap` → **left 0, right 10**; after
the fix 3/3 seed-upsert tests pass.

**F2 — the subaccount cap refusal answered HTTP 200 (High, fixed).**
`SubAccountService` returned the named `QUOTA_EXCEEDED` envelope, but
`api_result_error_status` had no mapping, so the 11th create was a 200 with
`success:false` — a lie to any client checking `response.ok`, inconsistent
with the api-server's capacity refusals (403).
Fix: map `QUOTA_EXCEEDED` → `403` (`crates/enterprise/src/routes.rs`).
Fail-before: `cargo test -p enterprise --lib subaccount_cap_refuses…` →
**left 200, right 403**; live re-verified: 11th create is `403` with
"Maximum sub-accounts (10) reached for this plan (max_subaccounts)".

**F3 — maker-checker was not enforced (High, fixed).**
`approve`/`reject`/`request_changes` updated the submission for any
`reviewed_by`, so the submitter's own token approved their own submission
(live P7 first run: self-approve `200 approved`).
Fix: the reviewer ≠ submitter guard is inside the UPDATE predicate
(`AND submitted_by <> $2`) with a named `400` refusal, so concurrent
self-reviews cannot slip between a read and the write
(`crates/enterprise/src/template_approval.rs`; approve/reject/changes all
audited).
Fail-before: `cargo test -p enterprise --lib
submitter_cannot_review_their_own_template` → **left 200, right 400**; after
the fix the cycle is: self-approve `400` named, self-reject/self-changes
`400` named, a different reviewer `200 approved` with `reviewed_by=checker-2`.

**F4 — the customer audit trail held no create/send rows (High, fixed in
code; live image not rebuilt per the no-builds rule).**
`docs/api/endpoints/audit.md` sells the trail as "the rows the platform
writes for account, **sending**, and configuration activity", but live P8.2
showed only `retention.updated`, a billing metering event and the export's
own row for a tenant that had just created a template (`201`) and sent two
accepted messages (`202`) — no `template.*`/`message.*` rows (repro in
`evidence-live-capabilities/p8-aud1.log`).
Fix: write audit rows for `template.created/updated/deleted/duplicated/
rolled_back`, `message.accepted` (single sends and each accepted batch item),
and the enterprise `template.approved/rejected/changes_requested` reviews
(best-effort post-commit; a lost audit row is logged, never undoes a
committed write).
Fail-before: `cargo test -p api-server --lib
template_create_writes_the_tenant_audit_trail` → **left 0, right 1**
("template.created must be audited"); passes with the fix (the template
update/delete/duplicate/rollback arms are all asserted through the same
`audit_logs` query shape).
The running `apexmail-api-server` image (built 04:16 today, before this
session) does not contain the fix; re-verification live requires an image
rebuild, which this brief forbids.

**F5 — deployment gap: live `enterprise` image predates the capability wave
(High, filed).** Binary inside `apexmail-enterprise-1`: `enterprise-server`
dated **Oct 5 00:23** (image 2026-10-05 10:28); the wave-1 gates landed
2026-10-06/08. Live evidence (`p6-sub1`, `p7-apr2`): free tenant subaccount
create → `200`; 11th create → `200`; 12 rows after the cap race; growth
tenant template submit → `200`. The current-tree code enforces all of it
(P6 `p6-sub5` 8/8, P7 `p7-apr4` 9/9 against the same live DB).
Repro: `docker exec apexmail-enterprise-1 ls -la /usr/local/bin/enterprise-server`
and POST a subaccount as a free tenant.

**F6 — deployment gap: live `tracking` image predates wave 2 (High,
filed).** Binary dated **Oct 5 14:21**. Live evidence (`p4-td2`): a foreign
tenant's pixel token on a verified custom host → `200 GIF`; an unverified
host → `200 GIF`; after `DELETE` the host still served `200` (11/17 probes).
Current tree: owner `200`, foreign `403`, unknown host `400`, delete stops
serving (`p4-td4` 17/17).
Repro: `curl -H 'Host: <verified custom host>' http://127.0.0.1:3001/o/<foreign token>`.

**F7 — compliance image also predates the wave (Medium, filed, no behavioral
gap observed).** `compliance-server` dated Oct 4 16:47; the live retention
sweep nevertheless honoured the tenant value, the legal hold and the plan
ceiling on every probed arm (P5 11/11), so this is recorded as an
image-freshness observation, not a behavior defect.

## 12. Method notes (recorded so every arm is reproducible)

1. **Current-tree services.** Because the enterprise and tracking images
   predate the wave (F5/F6) and the brief forbids docker builds, both
   services were also run from the current tree against the **live**
   Postgres/Redis:
   * `cargo build -p enterprise --bin enterprise-server` then
     `HOST=127.0.0.1 PORT=3009 … ./target/debug/enterprise-server`
     (JWT public key from `.env`; the harness spoke to it with
     `DOGFOOD_ENTERPRISE_BASE=http://127.0.0.1:3009`).
   * `cargo build -p tracking-service` then port 3013 / metrics 9199 with
     explicit `DATABASE_URL`/`REDIS_URL` (note: dotenvy otherwise loads the
     repo `.env`, whose `localhost:6379` is shadowed on this host by a
     passwordless local Redis while the compose Redis requires the
     password);
     `DOGFOOD_TRACKING_BASE=http://127.0.0.1:3013`.
2. **Custom-domain verification (P4.4).** `POST /:id/verify` uses the real
   system resolver; a running container's `/etc/hosts` is read-only, so the
   harness recreated the api-server container from the existing image with
   `extra_hosts` (a temporary compose override, `--no-deps`, no build) to
   publish the customer's CNAME name in the resolver view, then recreated it
   again without the override. Exact commands are in
   `evidence-live-capabilities/p4-td4.log`.
3. **Provider facts (P3).** The SES/SNS delivery webhook requires a valid
   AWS SNS signature, which the SMTP-mode dev stack has no producer for; the
   `delivered`/`bounced` facts were written with the exact production SQL
   shape of `ses_notifications::process_delivery` and the hard-bounce path
   (`email_queue.delivered_at` + parent reconciliation + `events`), so the
   timeline reconstruction itself is exercised live.
4. **Concurrent activity.** Other dogfood passes worked the same tree and
   DB during this session (33 modified files in the working tree; the
   `scale` plan row was updated at 12:02 and the api-server restarted at
   12:19). All probes used unique tenants/ids and verified DB state
   directly; the one place ambient state matters is noted in F1.

## 13. Files changed by this pass

| File | Change |
|---|---|
| `services/mail-server/crates/billing-service/src/plans.rs` | catalog-owned overlay includes `max_subaccounts`; fail-before test |
| `services/mail-server/crates/enterprise/src/template_approval.rs` | maker-checker guard on approve/reject/request-changes + named refusal |
| `services/mail-server/crates/enterprise/src/routes.rs` | `QUOTA_EXCEEDED` → 403; review audit rows; tests updated/added |
| `services/mail-server/crates/api-server/src/routes/templates.rs` | template mutation audit rows + audit test |
| `services/mail-server/crates/api-server/src/routes/messages.rs` | `message.accepted` audit rows (single + batch) |
| `tools/dogfood-live-capabilities.py` | the probe harness (new) |
| `docs/audit/dogfood-2026-10-06/dogfood-live-capabilities.md` | this report |
| `docs/audit/dogfood-2026-10-06/evidence-live-capabilities/` | transcripts + machine verdicts |

No KiwiCaptcha path was read or modified.
