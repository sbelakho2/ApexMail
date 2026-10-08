# LIVE DOGFOOD #2 — the mail plane (SMTP in → Mailpit/IMAP → outbound), 2026-10-08

Ran against the RUNNING compose stack per `brief-dogfood-mail-plane.md` (ZERO SKIPS).
Every probe below was executed; commands, observed results and the DB/wire/CH verification
are quoted verbatim. Fixture suffixes are unique per run (`pj6jsujc`).

Stack: MTA SMTP `127.0.0.1:5525` (plain inbound) / `:5587` (submission STARTTLS) /
`:5465` (implicit TLS); Mailpit SMTP `1025`, HTTP `8025`; IMAPS `993`; api-server `8080`;
tracking `3001`; ClickHouse `8123`; Postgres `5432`.
Host test env: `TEST_DATABASE_URL=postgresql://apexmail:…@127.0.0.1:5432/apexmail`,
`TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`.

Evidence bundle: `docs/audit/dogfood-2026-10-06/evidence-mail-plane-2/`
(`evidence-flow*.json`, `flow4-raw-*.eml`, `flow5-verp-delivered.eml`,
`db-and-log-evidence.txt`).

## Fixture disclosure (setup only — every product claim below is the live product's)

* Fresh tenant+user through the product's own signup → verification-email(Mailpit) →
  login(202 MFA setup) → `POST /v1/auth/mfa/verify` (TOTP) flow:
  `mp2-pj6jsujc@dogfood.test`, tenant `7myp1cnv9yscwr3z2i1fdkhiry`, owner.
* Domain `mp2-pj6jsujc.test` created through `POST /v1/domains` (product generated the DKIM
  keypair). `.test` cannot pass real DNS TXT checks, so the row the product created was
  flipped to `status='verified', dkim_enabled/spf_verified/dmarc_verified/dkim_verified=true` via SQL
  (same disclosure class as dogfood #1).
* Mailboxes provisioned through the **operator provisioning API** `POST /v1/admin/mailboxes`
  (control-plane host + static key) — the surface added after dogfood #1:
  `inbox-pj6jsujc@mp2-pj6jsujc.test` (IMAP login) and `sender-pj6jsujc@…`; later 105
  `cap-NNN-…` mailboxes for the recipient-cap probe.
* Plan raised `free→starter` via SQL because `webhooks_enabled` is not in `free` (the REST
  webhook creation gate returned the named 403 first; see Flow 6).
* Webhook sink: a python HTTP server run in the **worker's network namespace**
  (`docker run --network container:apexmail-worker-1 … python3 /data/sink.py`, port 9099)
  because the product requires `http://localhost|127.0.0.1` for plain-HTTP webhooks and only
  the worker's own loopback resolves to the sink. Disclosed; no product code involved.
* Dedicated-route probe: a `dedicated_ips` row (`203.0.113.77`, TEST-NET-3, unbindable) for
  the tenant, removed afterwards together with its ledger/queue rows.

## Environment note (important, affects which "fixes" were live)

The brief says the stack runs the current tree; verification shows this is **only partly
true**. Container image build dates (`docker inspect apexmail-<svc>-1 --format '{{.Created}}'`):

| service | created | contains the tree's Oct-07/08 fixes? |
|---|---|---|
| mta / worker | 2026-10-08 12:13 (I recreated them for the VERP wiring) | yes (built Oct 8 01:51) |
| api-server | 2026-10-08 12:48 (a concurrent agent recreated it; I restored the dev override) | yes (Oct 8 04:16) |
| tracking-service | **2026-10-05 14:21** | **no** — predates the click/allowlist and analytics_queue fixes |
| mailstore-core | 2026-10-04 23:30 | no |
| imap-server | 2026-10-04 23:35 | no |
| outbound-mta | 2026-10-04 17:10 | no |

Consequences, recorded as findings (not skips): the tracking-service fixes from
`fix-report-open-findings.md` (items 10/11/12) are **not live** (Flow 7), and my own
mailstore/imap fixes below cannot be built into the running containers (`no docker builds`
rule) — they are verified by the crate's own DB-backed tests against the same canonical
Postgres/migrations.

Also observed while working (shared tree, other agents active): `git status` carries many
unrelated modified files; at 12:47 the api-server crash-looped with
`Error: missing required environment variable: JWT_PRIVATE_KEY_PEM` because a concurrent
`docker compose up` recreated it without `docker-compose.override.yml`. Restored with
`docker compose up -d --no-deps api-server` (repo root, override applied) → healthy.

---

# Flow 1 — provision a live mailbox (tenant/domain/account/INBOX)

Probe: `POST /v1/auth/register` → verify-email token from the delivered Mailpit message →
`POST /v1/auth/login` (202 `mfa_setup_required` + TOTP secret) → `POST /v1/auth/mfa/verify`
→ `POST /v1/domains` → `POST /v1/admin/mailboxes` (×2, operator key).

Observed: register `202`, verify `200`, login `202 {"status":"mfa_setup_required",…}`,
mfa verify `200` (session for `7myp1cnv9yscwr3z2i1fdkhiry`), domain `201`
(`a275e000-…`, DKIM keypair returned by the product), mailbox provisioning `201` twice.

DB verification:

```
select a.id,a.email,a.is_active, (folders) from mail_accounts a where a.domain='mp2-pj6jsujc.test';
 56d257ba-… | inbox-…@mp2-pj6jsujc.test  | t | INBOX:inbox
 d24ad942-… | sender-…@mp2-pj6jsujc.test | t | INBOX:inbox
select … from domains where tenant_id=…;
 a275e000-… | mp2-pj6jsujc.test | verified | verified=t dkim_enabled=t dkim_selector=am-2158b614c6d14e6b91234e1945743433 key_len=2320
```

Verdict: **PASS** — account row + INBOX exist, provisioning atomic through the operator API.

---

# Flow 2 — SMTP inbound: plain + STARTTLS submission, hostile edges

All probes are raw SMTP transcripts against `127.0.0.1:5525` (container port 25) unless
noted; full transcripts in `evidence-flow2-smtp.json`.

### RUN 2.1 plain inbound, UTF-8 subject + 8-bit body
```
220 mail.apexmail.ee ESMTP ApexMail MTA
EHLO → 250-SIZE 26214400 / 250-STARTTLS / 250-8BITMIME / 250-PIPELINING /
       250-ENHANCEDSTATUSCODES / 250 SMTPUTF8
MAIL FROM:<ext-pj6jsujc@external.dogfood2.example> SMTPUTF8 BODY=8BITMIME → 250 2.0.0 Ok
RCPT TO:<inbox-pj6jsujc@mp2-pj6jsujc.test> → 250 2.0.0 Ok
DATA → 354 … → 250 2.0.0 Ok id=inb_2465a16e2dbc4df68250a5
```
DB: `inbound_messages` `disposition=accept, spf=none, raw_size=396`; `inbound_recipients`
`delivered attempt=1`; `mail_messages uid=1` with the exact UTF-8 subject and body.
Verdict: **PASS**.

### RUN 2.2 DATA line caps
* 1000-octet line (RFC 5321 minimum) → `250 Ok id=inb_4d46fbf701ad4d9ebb76e8`. PASS.
* 2 MiB single line (1 MiB per-line cap) → `552 5.3.4 Message size exceeds fixed maximum
  message size`, body dropped, session remains synchronised (existing test
  `overlong_data_line_rejects_the_whole_message_with_552` pins this exact contract).
  Verdict: PASS for the refusal; the **wording** is imprecise for a line-cap refusal
  (the 25 MiB advertised SIZE was never exceeded) — OBS-2 (low).
* 26 MiB cumulative body (run 8.3) → `552 5.3.4`, **0** DB rows. PASS.

### RUN 2.3 recipient cap (100)
105 pre-provisioned real mailboxes; RCPT loop:
```
accepted=100, first refusal at #101: 452 4.5.3 Too many recipients
NOOP → 250     DATA → 250 2.0.0 Ok id=inb_08c9328ca8f7440cadbd1f
```
DB: 100 `inbound_recipients` rows created for that message. Verdict: **PASS**
(documented cap honoured with a typed transient refusal; the session and the accepted 99
extra recipients are unaffected). *The storage of this message then failed on the From
defect below — that is FINDING-1, not a cap failure.*

### RUN 2.4/2.5 missing/invalid HELO
```
MAIL FROM (no EHLO/HELO) → 503 5.5.1 Error: send HELO/EHLO first
HELO (no arg)            → 501 5.5.4 Invalid HELO/EHLO hostname
HELO bad_name_with_underscore → 501 5.5.4 Invalid HELO/EHLO hostname
```
Verdict: **PASS**.

### RUN 2.6 empty MAIL FROM `<>`
```
MAIL FROM:<> → 250 2.0.0 Ok
RCPT TO:<inbox-…> → 250 2.0.0 Ok
DATA → 250 2.0.0 Ok id=inb_7ef9466d0cb34a489c7161
```
DB: `inbound_messages` accept; `inbound_recipients.status=deferred`, error
`mailstore unavailable: … violates check constraint "chk_mail_messages_from_address"` —
repeat 3 → 5 attempts on the ladder, and the 100-recipient message above shows the same
failure ×100 (`deferred attempt=5`). See **FINDING-1**. Verdict: **DEFECT** (accepted-then-lost).

### RUN 2.7 RCPT to a nonexistent mailbox
`ghost-pj6jsujc@mp2-pj6jsujc.test` → `550 5.1.1 No such user here` (no accept-then-drop). PASS.

### STARTTLS submission (5587), python smtplib
```
EHLO → STARTTLS (self-signed accepted) → EHLO (AUTH advertised) →
AUTH PLAIN → 235 2.7.0 Authentication successful
DATA → 550 5.7.1 marketing consent required
```
The refusal is the documented send-admission gate: SMTP submissions carry the
server-owned category `marketing` (`submission_credential_category()` returns `None`;
see `submission.rs` "MINIMAL CREDENTIAL ATTRIBUTE (proposed)"), and the recipient had no
`consent_records` row. After inserting a marketing consent record, the same submission
(`From … Message-ID <flow5-…>`) reached the queue: `202` → `email_queue
477549e7-…|pending|0` → Mailpit delivery with the VERP Return-Path (Flow 5A). Verdict:
**PASS** (typed policy refusal explained; successful submission proven).

### mailto arm preserved by the inbound mirror (F-4 of the mailbot lane)
A `List-Unsubscribe: <mailto:unsubscribe@apexmail.ee?subject=unsub>` value on an inbound
message survives to `inbound_messages.headers` and classifies deterministically — pinned
by the mailbot lane's fix; my flows exercised the outbound header instead (Flow 4).

---

# Flow 3 — IMAP read over IMAPS 993

Full transcript `evidence-flow3-imap.json`.

```
* OK [CAPABILITY IMAP4rev1 NAMESPACE MOVE UIDPLUS IDLE LITERAL+ AUTH=PLAIN]
a1 LOGIN inbox-pj6jsujc@mp2-pj6jsujc.test … → a1 OK LOGIN succeeded
LIST → () "/" "INBOX"
SELECT INBOX → OK 2
FETCH 1 (BODY.PEEK[]) → 702 bytes; Received/Authentication-Results(spf=none dmarc=none)/
        From/To/Subject(UTF-8)/Message-ID + 8-bit body all intact
SEARCH ALL → 1 2        SEARCH SUBJECT "line probe" → 2
STATUS INBOX (UIDNEXT MESSAGES) → MESSAGES 2 UIDNEXT 3
STORE 1 +FLAGS (\Flagged \Seen) → 1 (FLAGS (\Seen \Flagged \Recent)); removal OK
UID STORE 2 +FLAGS (\Deleted); EXPUNGE → OK [2]; MESSAGES 1 UIDNEXT 3 (UID 2 never reused)
```
Failure arms:
* wrong password → `LOGIN failed: Invalid credentials` (typed, no crash). PASS
* unknown mailbox → same typed refusal. PASS
* `X-NOT-A-COMMAND` → `a2 BAD Unknown command`; `SELECT` (no arg) → `a2 BAD Mailbox name
  required`; `FETCH` without SELECT → `a2 BAD No mailbox selected`. PASS
* oversized literal `a1 LOGIN user {35651584}` (33 MiB > 32 MiB cap) → **socket closed with
  ZERO response bytes** (raw capture: `b'<EOF: server closed>'`; exactly-at-cap
  `{33554432}` gets `+ Ready for literal data`). No crash, but the refusal is untyped —
  **FINDING-3**.

Verdict: **DEFECT** (oversized-literal refusal is a bare EOF; everything else PASS).

---

# Flow 4 — outbound to Mailpit, verified on the wire

Message `9e8a62b5-…` sent via `POST /v1/messages` (transactional) from
`sender-pj6jsujc@mp2-pj6jsujc.test` to `flow4-sink-pj6jsujc@dogfood.test`
(HTML with an own-domain and a subdomain link, Reply-To, custom header).

Delivered raw (Mailpit `MimQPvRbVzCh8LkUDitxVp`, `evidence-flow4-outbound.json` +
`flow4-raw-*.eml`) carries:

* **`DKIM-Signature: v=1; a=rsa-sha256; s=am-2158b614c6d14e6b91234e1945743433;
  d=mp2-pj6jsujc.test; c=relaxed/relaxed; h=MIME-Version:Date:Message-ID:To:Subject:From`**
  — cryptographically verified **VALID** with `dkimpy` against the domain's
  `dkim_public_key` from the DB (`[4_dkim_signature_valid] True`). PASS (dogfood-1 F-1.1 is
  fixed and live).
* `List-Unsubscribe: <http://127.0.0.1:3001/u/…>` + `List-Unsubscribe-Post:
  List-Unsubscribe=One-Click` (RFC 8058 literal). PASS. (Only the https arm is emitted;
  there is no `mailto:` arm on outbound mail — see OBS-3.)
* **tracking rewritten** to the tracking host: two `/c/…` links + one `/o/…` pixel. PASS.
* `Reply-To: <helpdesk-…@mp2-pj6jsujc.test>` present (dogfood-1 F-1.2 fixed and live). PASS
  — but the submitted **display name is still dropped**: request `From: Dogfood2 Sender
  <sender-…>` delivered as `From: <sender-…>`; `email_queue.headers->>'from_name'` is NULL /
  `raw_headers` NULL and `messages.from_email` is the bare address. FINDING-6 (P3,
  api-server send path; dogfood-1 F-1.3 remains open).
* `Return-Path: <sender-…@mp2-pj6jsujc.test>` for this message (no VERP at that time — the
  worker's startup WARN said VERP is off; see Flow 5 for the VERP-enabled wire proof).
* queue row: `95cda82f-…|sent|attempt=0|attempts=0`, `smtp_message_id` NULL (OBS-4,
  dogfood-1 F-1.4 still open; the transport documents mail-send returns no DATA reply).
* worker logs: `"message":"Email transport backend selected","transport":"Smtp"`,
  `"transport_type=smtp: shared-pool route bound to the configured SMTP relay","host":"mailpit"`,
  `"SMTP connection verified","host":"mailpit"`.
* relay ledger: shared-route sends do not use `outbound_relay_ledger` by design; the
  dedicated-route agreement probe is below.

### Dedicated route → `outbound_relay_ledger` agreement (dogfood-1 F-6.1 fix)
Fixture dedicated IP (203.0.113.77, unbindable) → send to `flow4ledger-…@discard.email`:
```
worker: "outbound delivery deferred; retry scheduled" attempt=1 next=+300s
        reason "source IP 203.0.113.77 could not be bound and verified (refused before DATA):
        Cannot assign requested address (os error 99)"
worker: "outbound MTA holds the send — deferring until the relay terminalizes"
        route "dedicated(ded2dogfood… @ 203.0.113.77)"
email_queue:       d539c68d-… | pending | attempt=0 | metadata.requeue_reason=relay_delivery_pending
outbound_relay_ledger: email_queue:d539c68d-…:flow4ledger-…@discard.email | pending |
        attempt=1 | max_attempts=12 | err="source IP 203.0.113.77 could not be bound…"
outbound-mta /readyz: queue.pending=1, counters.claimed=1
```
Queue and relay agree (both non-terminal, the worker consumes no attempt and never
dead-letters while the relay holds the message). A permanent variant (recipient
`@dogfood.test`, no MX) terminalized **both** sides to `failed`/`bounced` with the same
reason. Verdict: **PASS** (dogfood-1 F-6.1 verified fixed on the live worker).

Verdict Flow 4: **PASS with findings** (display-name drop FINDING-6; `smtp_message_id` OBS-4).

---

# Flow 5 — bounces / FBL

### 5A. VERP Return-Path on the wire (after wiring the dev secret)
The dev compose never passed `VERP_HMAC_SECRET` (only `docker-compose.prod.yml` did), so the
worker's gate logged `"VERP_HMAC_SECRET is unset or shorter than 32 bytes: outbound mail
will carry NO VERP Return-Path"` and every DSN was non-authoritative (dogfood-1 F-4's
suppression half was unreachable). **Fixed** — `docker-compose.yml` now wires
`VERP_DOMAIN`/`VERP_HMAC_SECRET` (dev default ≥ 32 bytes) into **both** mta and worker,
pinned by the new test `config::tests::dev_deploy_artifacts_carry_the_verp_hmac_secret`.

After recreating mta+worker (`docker compose up -d --no-deps mta worker`), the same
submission delivered with:
```
Return-Path: <bounces+v2.eyJ2IjoidjIiLCJxIjoiNDc3NTQ5ZTct… y63PB@bounces.apexmail.ee>
decoded claims: {v:v2, q:477549e7-…(queue row), t:7myp1cnv9yscwr3z2i1fdkhiry,
                 r:flow5-bounce-pj6jsujc@dogfood.test, e:1794053845}
```
(`flow5-verp-delivered.eml`) Verdict: **PASS**.

### 5B. signed SES-style POST → `/v1/ses/notifications`
```
POST /v1/ses/notifications (SNS Notification, SignatureVersion 1, SigningCertURL
https://sns.eu-central-1.amazonaws.com/SimpleNotificationService-fake.pem)
→ 503 {"error":{"code":"SERVICE_UNAVAILABLE","message":"SNS notifications are not configured"}}
SNS_ALLOWED_TOPIC_ARNS (api-server env) = empty
```
UNREACHABLE-with-proof: the running api-server refuses every notification before parsing
(empty topic ARN list), and even configured, `validate_signing_cert_url` only accepts
`https://sns*.amazonaws.com/SimpleNotificationService-*.pem` — no local signature can ever
verify. FINDING-5 (P2, unchanged from dogfood-1 F-4.1).

### 5C. authoritative self-hosted bounce → suppression + replay
A realistic RFC 3464 DSN addressed to the minted VERP address, injected on the MTA bounce
listener (2525, `docker exec apexmail-mta-1 bash -c '… /dev/tcp/127.0.0.1/2525 …'`):
```
250 2.0.0 Ok id=44b190b8-3539-45a5-8888-543762a1f81a
bounce_events: 44b190b8-… | 477549e7-… | flow5-bounce-… | Hard | no-mailbox | 5.1.1 |
               verp_version=v2 | authoritative=t
suppressions:  sup_60b461b77b4b4d8495 | flow5-bounce-… | hard_bounce | mta | mta
REPLAY of the same DSN → suppression count stays 1, bounce_events count stays 1
(natural key + bounded replay), events rows unchanged
```
Verdict: **PASS** — the authoritative path now suppresses, idempotently. (Sales ledger:
`sales_outcomes`/`sales_sender_events` only receive rows for **sales-provenanced** mail —
`record_sales_outcome_if_linked` returns `Ok(None)` when `email_queue.sales_step_execution_id`
is NULL, which a console/direct send never carries. The MTA's authoritative bounce queues a
`message.bounced` webhook instead. This is the documented contract, not a defect; the
sales-provenance leg is covered by the sales lane's own dogfood.)

### 5D. ARF complaint on the FBL listener (2526)
```
250 2.0.0 Ok id=d9591a6e-9085-4a4d-8926-6f6092407887
complaint_events: … | abuse | authoritative=f |
  observation_detail="non-authoritative source 127.0.0.1; claimed message_id="
```
The FBL registry validates by PTR/FCrDNS of the source IP against a registered provider;
a loopback injector can never be authoritative, so no suppression is written. Verdict:
**UNREACHABLE-with-proof** for an authoritative ARF (no provider registration exists in
the stack); the observation row is written and correct.

---

# Flow 6 — webhooks out (tenant webhook → local sink)

Sink: python HTTP server in the worker's network namespace (`127.0.0.1:9099`, mode file
flips 200/500). Hook created through `POST /v1/webhooks`
(`m2mrawjj54htfi0u5ngtq6kest` / later `p90awnjr559nbmfbx70s5hpzbq`), events
`message.accepted, message.opened, message.clicked, recipient.unsubscribed`.
Note: `POST /v1/webhooks` first returned the named 403
`plan 'free' does not include 'webhooks_enabled'`; the plan was raised to `starter`
(fixture) — the entitlement gate is honest.

```
# real event: a REST send → message.accepted
worker → POST http://127.0.0.1:9099/hook  (bodies `{"data":{"messageId":…,"status":"accepted"}}`)
headers: x-apexmail-signature, x-apexmail-timestamp, x-apexmail-event,
         x-apexmail-webhook-id, x-apexmail-delivery-id
signature recomputed = "v1="+HMAC-SHA256(secret, "<ts>.<body>") → MATCH (verified for each)
webhook_queue → delivered (row removed after success; `webhook_deliveries` is the record)
```
* **sink 500 → retry ladder observed**: after a second send with the sink in 500 mode,
  `webhook_queue` row `whj_5c3c2ce351645ee7b4a9aa04821a72a7|message.accepted|pending|attempt=2|
  max_attempts=10|error_message="HTTP 500"`, with the sink receiving attempt 1 and 2.
* **sink fixed → next retry succeeds**: the sink was flipped back to 200 and the next retry
  (attempt 2, 12:06:02) recorded `status_code=200` in `webhook_deliveries`; the queue row was
  removed on success:
  ```
  select webhook_id,event_type,status_code,attempt,delivered_at from webhook_deliveries
    where webhook_id='p90awnjr559nbmfbx70s5hpzbq';
   p90awnjr… | message.accepted | 200 | 1 | 2026-10-08 12:05:26.928
   p90awnjr… | message.accepted | 200 | 2 | 2026-10-08 12:06:02.083
  ```
* **disable → no deliveries**: `PATCH /v1/webhooks/:id {status:"disabled"}` → 200. A real
  event afterwards produced **no sink request**. BUT it DID produce a `webhook_queue` row:
  ```
  select q.id,q.event_type,q.status,q.attempt,w.status,w.enabled … where hook=p90awnjr…
   whj_95b236261b5959c4b451e6cccbdcd237 | message.accepted | pending | 1 | disabled | t
   whj_bb8444f95f77509b99b03020adb15391 | message.accepted | pending | 1 | disabled | t
  ```
  The enqueue filter checked `enabled=true` while the processor's claim requires
  `enabled=true AND status='active'` — see **FINDING-2** (fixed in this round).

Verdict: **DEFECT then FIXED** (delivery, signature, ladder and recovery PASS; the
disabled-hook enqueue/pending-row leak is filed and fixed).

---

# Flow 7 — tracking round trip (click / open / unsubscribe)

Tokens taken from the delivered message `9e8a62b5-…`:
```
pixel GET → 200 image/gif (43 B); replay ×2 → still 1 opened row; Googlebot UA → 200, not
            recorded; HEAD → 200, no extra row
click own-domain  → 302 Location: https://mp2-pj6jsujc.test/landing?x=1   (recorded)
click SUBDOMAIN   → 302 Location: https://apexmail.ee                    (fallback; NOT recorded)
                     no `click_refused` event anywhere
Postgres events: sent, opened, clicked(link_id=lnk_8df07fc3f71c6566, link_url=https://mp2-…),
                 unsubscribed
ClickHouse events (same message): opened/clicked(link_id=lnk_8df07fc3f71c6566)/unsubscribed
analytics_queue: ZERO rows for these events
unsubscribe GET  → 200, side-effect free (0 suppressions)
unsubscribe POST "List-Unsubscribe=One-Click" → 200 {"success":true}
suppressions: sup_qj70q1w21b78aqurxhl6ki | flow4-sink-… | unsubscribe | one-click | source=NULL
POST replay → 200, still 1 row; body "List-Unsubscribe=No" → 400; tampered token → 400
unknown-tenant token: GET 200 (1133-byte page, no 500); POST 400 (36 bytes)
next send to the suppressed address → 400 "recipient is suppressed: …"
```
Interpretation (verified against the tree): the tree's `click.rs` **does** authorize
subdomain links by exact-boundary suffix match, records blocked clicks as an explicit
`click_refused` event and returns a 400 refusal page, and `processor.rs:write_events`
enqueues `analytics_queue` rows — but the running **tracking-service image is from
2026-10-05**, before those commits. Live behavior is the pre-fix behavior; the code is
fixed. FINDING-4 (P1 for the live stack / environment: rebuild required). The `link_id`
improvement (item 12) IS live because it rides the worker's payload + the codec.
Suppression `source` stays NULL (dogfood-1 P3) — OBS-5.

Verdict: **DEFECT on the live stack (stale image)**, tree already fixed; click/open/unsub
recording, dedupe, bot filtering, token integrity and the send gate are PASS.

---

# Flow 8 — concurrency / hostile

* **20 paced simultaneous inbounds** (0.15 s apart, distinct Message-IDs): **20/20**
  `250 2.0.0 Ok`, 20 `mail_messages` rows, 20 `inbound_messages`, **0 panics** in the MTA
  log, `uidnext` advanced 3→23. PASS.
* **re-delivered Message-ID**: same `Message-ID` sent twice → both SMTP transactions
  accepted (2 `inbound_messages`), but exactly **1** `mail_messages` row
  (`dedup_exempt=false`) — no second copy/draft. PASS.
* **oversized body**: 26 MiB → `552 5.3.4`, 0 rows. PASS.
* **caps**: line length (1 MiB) and recipients (100) hold (Flow 2.2/2.3). PASS.

---

# Findings (with repro + status)

### FINDING-1 — P1, `mailstore-core/src/service.rs` — accepted inbound mail with a missing/unparseable From is unstorable and silently lost
Ran: `MAIL FROM:<>` + `From: Mailer Daemon <>` (and a no-From message; and the 100-recipient
fan-out message) to a live mailbox. Observed: MTA answers `250 2.0.0 Ok`; every
`inbound_recipients` attempt defers with `mailstore unavailable: … new row for relation
"mail_messages_2026_q4" violates check constraint "chk_mail_messages_from_address"` (the
default sentinel was `unknown@localhost` — no dot in the domain — and `From: <>` yields an
empty address); the null reverse-path means no DSN can ever report the loss; 100 rows
deferred in one probe, reaching attempt 5 on the ladder. Expected: the message stores with
a placeholder From. **Fixed**: reserved `unknown@unknown.invalid` sentinel +
`is_storable_from_address` mirroring the CHECK. Regression tests
`unparseable_from_headers_yield_a_storable_placeholder`,
`storable_from_address_mirrors_the_db_check` and the DB-backed
`store_message_with_unparseable_from_is_not_lost_to_the_check_constraint`; the last fails
pre-fix with the exact production error (proof in "Fail-before proofs").

### FINDING-2 — P2, worker/MTA webhook enqueue — a disabled webhook keeps receiving queue rows it can never claim
Ran: `PATCH /v1/webhooks/:id {status:"disabled"}` then a real event; observed two
`webhook_queue` rows `pending` for the disabled hook (table excerpt above), never claimed
because the claim requires `status='active'`; re-enabling would fire the stale backlog at
once. Every enqueue writer filtered on `enabled` alone. **Fixed** in the owned paths
(`worker-processors/src/email/processor.rs`, `worker-processors/src/automations.rs`,
`mta/src/servers/util.rs`) by adding `AND status='active'` to mirror the claim contract.
Regression test `disabled_webhooks_do_not_receive_outcome_queue_rows` (2 rows pre-fix,
1 post-fix). Residual (filed, not owned): `tracking-service/src/processor.rs:2273` and
`unsubscribe.rs`, `api-server/src/routes/ses_notifications.rs` carry the same
`enabled = true` filter and need the same one-liner.

### FINDING-3 — P3, `imap-server/src/main.rs` — over-budget literal closes the socket with zero bytes (untyped refusal)
Ran: `a1 LOGIN user {35651584}` on IMAPS (33 MiB > 32 MiB cap). Observed: `b'<EOF: server
closed>'` — no `* BYE`, no tagged BAD. Expected: BYE before a server-initiated close
(the module's own documented contract; the timeout arm already does it). **Fixed**: both
read-error arms now write `* BYE` before closing. Tests:
`over_budget_literal_is_refused_with_a_bye_before_the_close` (new) and the updated
`oversized_literal_is_refused_without_reading_the_payload`; the new test fails pre-fix with
"connection closed before a full line arrived".

### FINDING-4 — P1 (live stack) / environment, tracking-service image predates its fixes
Ran: live click on `https://sub.mp2-pj6jsujc.test/…`. Observed: `302 → https://apexmail.ee`
(vendor fallback) with no `click_refused` event, and zero `analytics_queue` rows for the
opened/clicked/unsubscribed events. The tree's `tracking-service` has the suffix-match
authorization, the explicit refusal recording and the `analytics_queue` producer (items
10/11/12 of `fix-report-open-findings.md`) — the **running image is from 2026-10-05**.
Repro: `docker inspect apexmail-tracking-1 --format '{{.Created}}'` → `2026-10-05T14:21:24Z`.
Resolution (rule-compliant, no docker builds here): rebuild/recreate the tracking service
(`docker compose build tracking-service && docker compose up -d tracking-service`) and
re-run Flow 7. Not a code defect at HEAD.

### FINDING-5 — P2, SES notification ingest remains unexercisable locally
`POST /v1/ses/notifications` → `503 SNS notifications are not configured`
(`SNS_ALLOWED_TOPIC_ARNS` empty) and the signing-cert validator only accepts
`https://sns*.amazonaws.com/SimpleNotificationService-*.pem`, so no locally-signed payload
can pass. Unchanged from dogfood-1 F-4.1; the self-hosted VERP path now covers the
authoritative-bounce behavior instead (Flow 5C).

### FINDING-6 — P3, api-server send path drops the From display name
Ran: `POST /v1/messages` with `"from": "Dogfood2 Sender <sender-…>"`. Observed: delivered
`From: <sender-…>`; `email_queue.headers->>'from_name'` NULL, `raw_headers` NULL,
`messages.from_email` bare. Expected: F48's "named mailboxes survive the WHOLE request
contract". Open (dogfood-1 F-1.3, api-server not in this round's owned paths).

### OBS-2 (low) — the line-cap refusal reuses the message-size wording
A 2 MiB DATA line gets `552 5.3.4 Message size exceeds fixed maximum message size` although
the advertised 25 MiB SIZE was never exceeded; the transaction is refused and the session
stays synchronised (test-pinned). Filing only.

### OBS-3 (low) — outbound List-Unsubscribe has no `mailto:` arm
Only the RFC 8058 https one-click URL is emitted. RFC 2369 recommends a second `mailto:`
arm for clients without one-click support. Filing only.

### OBS-4 (low, dogfood-1 F-1.4) — `smtp_message_id` stays NULL on SMTP-mode sends
The transport documents that pinned mail-send 0.4.x returns only `Result<()>` for DATA, so
the relay's acceptance id cannot be recorded yet. Filing only.

### OBS-5 (low, dogfood-1 P3) — tracking-service suppressions have `source = NULL`
`sup_qj70q1w21b78aqurxhl6ki` (one-click) has no `source` while SES/MTA writers set
`'ses'`/`'mta'`. Filing only.

---

# Fixes landed (owned paths) + fail-before proofs

| fix | files | regression test | fail-before proof |
|---|---|---|---|
| FINDING-1 placeholder From | `crates/mailstore-core/src/service.rs` | `store_message_with_unparseable_from_is_not_lost_to_the_check_constraint` (+2 unit) | reverted functional hunks → `FAILED … violates check constraint "chk_mail_messages_from_address"` |
| FINDING-2 disabled-hook enqueue | `worker-processors/src/email/processor.rs`, `worker-processors/src/automations.rs`, `mta/src/servers/util.rs` | `disabled_webhooks_do_not_receive_outcome_queue_rows` | reverted filter → 2 rows incl. the disabled hook (`left: 2, right: 1`) |
| FINDING-3 BYE on read error | `crates/imap-server/src/main.rs` (+ updated `adversarial_tests.rs`) | `over_budget_literal_is_refused_with_a_bye_before_the_close` | reverted BYE → `connection closed before a full line arrived` |
| VERP reachable in dev | `docker-compose.yml` (mta + worker) | `config::tests::dev_deploy_artifacts_carry_the_verp_hmac_secret` (mta) | reverted compose hunks → `left: 0, right: 2` |

Suite runs after the fixes: `mailstore-core --lib` 69/69; `imap-server` 295/295 + binary
lifecycle; `mta --lib` 728/728; `worker-processors --lib webhook` 82/82; full
`worker-processors --lib` 720/721 — the single failure
(`email::processor::orchestration_tests::warmup_disabled_keeps_the_dedicated_route_without_consuming_quota`)
passes in isolation (`1 passed`) and is unrelated to the changed webhook SQL (shared-Redis
warmup-counter timing under the full parallel run). All fail-before runs were executed
against the reverted code and restored afterwards. (The shared tree also carries other
agents' in-flight edits; `mta --lib` was green only after they finished compiling.)

Note: the running containers were NOT rebuilt (`no docker builds`), so FINDING-1/-2/-3 are
verified at the crate/DB level (the mailstore test runs the live canonical migrations on the
same Postgres), not re-driven through the containers. The VERP wiring fix WAS driven live
(Flow 5) because it is config-only.

# Summary

| Flow | Verdict | Findings |
|---|---|---|
| 1 mailbox provisioning | PASS | — |
| 2 SMTP in (plain/STARTTLS, hostile) | DEFECT | FINDING-1 (P1, fixed); caps/HELO/8-bit/line probes PASS |
| 3 IMAP read + failure arms | DEFECT | FINDING-3 (P3, fixed); rest PASS |
| 4 outbound → Mailpit + ledger | PASS | FINDING-6 (P3 open); OBS-3/OBS-4; DKIM valid, Reply-To, tracking, VERP, ledger agreement |
| 5 bounces/FBL | PASS (self-hosted) / UNREACHABLE (SES, ARF) | FINDING-5 (P2 open); VERP + authoritative suppression + replay PASS |
| 6 webhooks out | DEFECT → FIXED | FINDING-2 (P2, fixed); delivery/signature/ladder/recovery PASS |
| 7 tracking round trip | DEFECT (stale image) | FINDING-4 (P1 env, tree already fixed); OBS-5 |
| 8 concurrency/hostile | PASS | — |

ZERO SKIPS: every probe in the brief was executed; the two unreachable arms (SES-signed
POST, authoritative ARF) carry the exact command, the exact observed refusal and the reason,
as required.

Fixture hygiene: the dedicated-IP fixture, its ledger/queue rows and the webhook test rows
were removed; unique suffix `pj6jsujc` marks every artifact this run created.
