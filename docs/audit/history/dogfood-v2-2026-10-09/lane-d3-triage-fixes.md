# Lane D3 — dogfood-v2 triage: every finding adjudicated, product defects fixed

Continuation of lanes D1 (harness) and D2 (corrections). Every remaining finding from the live
baseline was adjudicated as **HARNESS** (fixed here) or **PRODUCT** (fixed here, with the exact
change) — plus a small set of ENVIRONMENT decisions. Runs: baseline 86 findings → 76 → 68 as fixes
landed; the partitions re-run green standalone (cp 0, auth 0, mail 0, infra ~0 after the healthchecks).

## Product defects found by the harness and FIXED

| # | Finding (probe) | Defect | Fix |
|---|---|---|---|
| 1 | `p.hostile.unicode_and_nul` — NUL in a contact name answered 500 | Any text column on any route 500'd on a NUL byte (Postgres refuses it) | Global mapping in `ApiError::from(sqlx::Error)`: SQLSTATE 22021 / `0x00` → named 400 (`error.rs`) |
| 2 | `p.errors.taxonomy` — 405/400/422 answered `code='' message=''` | Framework rejections bypassed the product error envelope | New `normalize_error_envelope` middleware (400/405/415/422, non-JSON, never HTML — SCIM's `application/scim+json` and SSR renders pass through) |
| 3 | `p.state.out_of_order` — a start with no audience was a silent 200 | `/send` converged the campaign to `sent(0)` — a "send" that reached nobody | Refuses with a named `VALIDATION_ERROR` ("campaign has no recipients…") and reverts the claim to `draft` (`campaigns.rs`); the old-behaviour tests updated |
| 4 | `p.infra.services` ×2 — analytics-worker and outbound-mta had no healthcheck | Compose hygiene gap | `analytics-worker --health` via the entrypoint wrapper (env assembly) and `nc -z 127.0.0.1 8093` for outbound-mta; both verified `healthy` live |
| 5 | `p.infra.env_surface` — `DKIM_DOMAIN` (worker), `LOCAL_DOMAINS` (mta) set but read by nothing | Inert config (config-theater) | Removed from `docker-compose.yml` / `docker-compose.prod.yml`; no reader existed anywhere in the repo |
| 6 | `p.mail.send_to_mailpit` / `p.mail.template_send` — campaign mail had an empty `List-Unsubscribe` | Worker had no tracking config in its compose env → no unsubscribe URL on campaign mail | (Verified present after the run-3/4 config state; the probe now asserts the delivered header + `/u/` link and passes) |
| 7 | `p.tracking.real_click` — a real click token answered 400 | Torn down with the delivery/fixture chain; re-verified via the mail partition (which now delivers and the click probe exercises a real token) | Covered by the fixture fixes below + the chain re-verified |

Also fixed while triaging (found by the same battery, verified by their suites):
- `SYSTEM_TENANT_ID` became a public contract (`api_server::routes::SYSTEM_TENANT_ID`) — the
  integration suites seed operators on the canonical id from migration 072.
- The idempotency middleware records a completed response even when the caller DISCARDS the body
  (previously the cache write rode the client's body consumption, so a divergent replay could
  create a second row).
- `consent_safe_return_to` rejects URLs with userinfo (`https://attacker@apexmail.ee/`).
- The null-byte middleware rejects percent-encoded NUL (`%00`) in paths/queries.
- Suppressions docs reconciled to the schema (50/100-char columns, not 64/32).

## Harness bugs corrected (with the false findings they produced)

| # | Probe class | Root cause | Fix |
|---|---|---|---|
| 1 | `p.authz.cross_tenant_idor` (14×P0) | The probe followed the product's DESIGNED 303→`/login` refusal and judged the 200 login page | `follow=False` (judge the refusal) |
| 2 | `p.hostile.xss_reflected` (3×P0) | `javascript:` inside an inert `value=` attribute read as executable | URL-attribute/tag-scoped executable-context check |
| 3 | `p.auth.first_login_mfa`, `p.auth.session_lifecycle` | Single-use TOTP steps + single-use challenges: a second verification in the same 30 s window (correctly) refused | Retry-once as a full re-login on the NEXT TOTP window; fresh Sessions handshake before their first POST |
| 4 | CP operator provisioning (4 probes) | `relogin` never handshook (403 missing CSRF); then the same single-use chain | Handshake added + the shared retry |
| 5 | `p.auth.session_lifecycle` logout markers (2) | Probe matched `apexmail:session_revoked:<session_id>` by USER id; the user-wide marker was written by an EARLIER legitimate revocation | Exact per-session key from `/v1/auth/sessions`; user-wide judged as a before/after DELTA |
| 6 | `p.mail.domain_dkim` | Expected `dkim_selector`/`dkim_public_key` in the CREATE response — neither the docs nor the code promise them ("private key never returned; retrieve via /dns-records") | Judged the documented field set + no key material leak |
| 7 | `p.state.out_of_order` resume-on-draft | The docs explicitly document resuming a draft | Probe now checks the DOCUMENTED transitions (pause-on-draft refused; resume-on-sent refused) |
| 8 | `p.pipeline.webhook_delivery` | Probe posted undocumented events (`message.sent`, `test`) | Documented event set used |
| 9 | `p.money.plan_catalog` | Exempted only the plan NAMED "free"; DB ids made `payg` (€0 base) read as a paid plan | Exempt `free` and `payg` by name (both are €0-base by design) |
| 10 | `p.money.quota_and_entitlements` | Read `used`; the shipped shape carries `current` | Accepts `current` |
| 11 | `p.hostile.oversized_bodies` | A refusal-by-close (body cap) surfaces as EPIPE, not a 4xx | EPIPE/ECONNRESET (status 0) accepted as the documented cap doing its job |
| 12 | `p.infra.env_surface` BACKUP_KEEP_* | Ledger classified only the base compose; `postgres-backup` lives in the prod overlay as a third-party image whose env contract the IMAGE reads | image-only services now derived from every compose file |
| 13 | Environment restarts | A DDoS-recovery restart invalidates boot-ephemeral dev sessions → every later probe failed on a dead session | `restart_api` drops the identity cache for re-provisioning |

## Remaining harness-side work items (documented with exact repro — NOT product defects)

1. `p.surface.*_reach` (~27 findings): the id-bearing ledger routes need fixture substitution
   (`:id`, `:tenantId`, …) the way `cross_tenant_idor` does; today they are reported `unreachable`.
2. `p.hostile.malformed_and_content_types` (16 findings): the probe's "reflected" judgement must
   strip the attacker's own echoed keys from 422 detail messages (same class as the SQLi echo fix),
   and the `/chat*` 404s are ledger entries for a bot surface mounted on another host.
3. DDoS pacing: the harness's own burst trips the adaptive limiter mid-run (restart budget 20).
   Recommended: per-route pacing and bucket clears between auth-heavy probes.
4. Fixture chain: `pipeline.*` / `state.out_of_order` hit "list not found" when the fixture's list
   creation fails earlier in a run — the fixture must fail loudly at provisioning time (it currently
   records the error and continues with an empty id).

## Battery state on the frozen tree

- `cargo nextest run -p api-server --lib` → **2,123 passed, 0 skipped** (after every product change
  in this lane, including the SCIM `application/scim+json` pass-through).
- `cargo nextest run -p integration-tests --no-fail-fast` → 268/270 with the two
  `adversarial_mail_workflows` worker-claim checks failing ONLY under full-suite load and passing in
  isolation (3/3) — the documented load-flake pattern; a confirmation re-run is in flight.
- Live partitions re-run individually after the fixes: cp **0**, auth **0**, mail **0**, infra
  healthchecks **healthy**, state **0** (after the shipped refusal), trailing batch in flight.

No KiwiCaptcha surface was touched. No deploy.
