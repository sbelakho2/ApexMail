# Ledger — LIVE dogfood, mail plane (2026-10-06)

Slice: SMTP submission → queue → worker → delivery; inbound → mailstore → IMAPS; tracking;
bounce/complaint ingestion; unsubscribe; outbound MTA retries/warmup.

Stack: docker compose up (api 127.0.0.1:8080, submission 5587 STARTTLS, IMAPS 993,
Mailpit 8025, tracking 3001).

Legend: RUN = command issued, PASS/FAIL = observed result vs honest expectation, BLOCKED = could
not run with the exact reason. Evidence pointer = file/section in dogfood-mail-plane.md.

| # | Flow | Status | Evidence pointer |
|---|------|--------|------------------|
| 1 | SMTP submission → queue → worker → Mailpit (+DKIM) | FAIL | report §Flow 1: delivered in ~2s (msg `maJ7fr24HmoTjQ4dKMqvQ5`, queue `fcc8d805-…` sent) but NO DKIM-Signature (F-1.1 P1); Reply-To dropped (F-1.2 P2); display name dropped (F-1.3 P3); `smtp_message_id` never set (F-1.4 P3). Injection probes clean; 10 MiB attachment OK; 20 MiB refused 552 as advertised. |
| 2 | Inbound → mailstore → IMAPS retrieval | PASS | report §Flow 2: `inb_f6caa45bb93642009137ad` delivered attempt 1 in 3s; IMAPS 993 FETCH UID 1 returns full UTF-8 headers/body; ghost mailbox / unknown domain / wrong password / CRLF-RCPT all cleanly refused. Environment note: host macOS Postfix answers 127.0.0.1:25, use 5525 (container port 25). |
| 3 | Tracking pixel + click redirect (+events) | FAIL | report §Flow 3: pixel 200 image/gif, replay/bot/HEAD dedupe correct; owned-domain click 302s to destination and lands in ClickHouse+Postgres events within ~1s. But ANY other host (incl. `sub.<own-domain>`, `example.com`) 302s to `https://apexmail.ee` and records NO click (F-3.1 P1 — no API to configure allowlist); `link_id` always `unknown` (F-3.2 P2). |
| 4 | Bounce / complaint ingestion (/v1/ses/notifications) | BLOCKED (partial) | report §Flow 4: SES POST → 503 `SNS notifications are not configured` (SNS_ALLOWED_TOPIC_ARNS empty; signature cert pinned to AWS → un-signable locally) so no suppression row is reachable (F-4.1 P2). Internal MTA paths exercised: DSN → `bounce_events` Hard/5.1.1 authoritative=false; ARF → `complaint_events` abuse authoritative=false (unregistered_source / no VERP secret) — bookkeeping PASS, suppression + `sales_outcomes` BLOCKED (exact reason: no authoritative source configured anywhere in the stack). F-4.2 P3: observation drops claimed recipient. |
| 5 | Unsubscribe → suppression → send-gate refusal | PASS | report §Flow 5: GET side-effect-free, one-click POST 200 → `sup_20vy0yy2j2qjfy2h22d2zd` (reason unsubscribe/one-click), exactly one `unsubscribed` event; SMTP DATA → `550 5.1.1 recipient address suppressed`, REST → 400 `recipient is suppressed`; replay idempotent, tampered/truncated tokens 400. P3: `source` NULL on the suppression row. |
| 6 | Outbound MTA retries / warmup / terminal bookkeeping | FAIL | report §Flow 6: relay driven via `outbound_relay_ledger` — transient connect timeout → `pending attempt=1 next=+300s`, then `attempt=2 next=+600s`; Null MX → `failed` + DSN with NULL reverse path that terminalized without a DSN-loop; `/readyz` counters accurate (PASS). Warmup daily cap → worker `metadata.requeue_reason=warmup_limit` (PASS). BUT live dedicated-route retry → queue row `failed` on "idempotency conflict / different delivery contract" while the ledger stayed `pending` (F-6.1 P1 split-brain); per-row `max_attempts` ignored, retried past 1 (F-6.2 P3). Fixtures cleaned up. |

Notes/LIVE log:
- 2026-10-06 21:1x — stack inspected: all mail-plane containers up (mta, worker, mailstore,
  imap-server, outbound-mta, tracking, mailpit). api-server restarted 10 min ago.
- 2026-10-06 21:18 — console login for pre-existing user `dogfood-send@dogfood.test` returns
  500 `failed to decrypt MFA secret` (MFA_SECRET_ENCRYPTION_KEY mismatch on pre-existing users).
  Not a mail-plane flow; fresh-tenancy signup path used instead.
- Fixture disclosure: to get a sender domain past the product's real DNS-based verification
  (no public DNS for .test domains), the domain row created through the product API is flipped to
  the verified/ready state via SQL. All mail-plane behavior after that is the running product's.
- 2026-10-06 21:5x — Flow 6 fixtures used to drive the relay (temporary `dedicated_ips` row,
  Redis warmup counter, `outbound_relay_ledger` drive rows) were removed after observation; the
  relay ledger is back to its pre-test contents. Findings report validated: 11 findings, each with
  Ran/Observed/Expected/Why it is a defect/Suggested fix.
