# LIVE DOGFOOD — C: the mail plane (SMTP in → Mailpit/IMAP → outbound), end to end

You are a live dogfooding agent. The stack is up on the CURRENT tree. Drive
REAL mail through it — the product, not its tests.

Live endpoints: MTA SMTP `127.0.0.1:5525` (plain) / `:5587` (submission,
STARTTLS self-signed) / `:5465` (implicit TLS); Mailpit SMTP
`127.0.0.1:1025`, HTTP `http://127.0.0.1:8025`; IMAPS `127.0.0.1:993`;
api-server `8080` (Host header picks the surface); tracking `3001`;
enterprise `3002`; ClickHouse `8123`.

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-mail-plane-2.md`
with per-flow evidence (SMTP transcripts, Mailpit captures, IMAP reads, DB
rows) and verdicts. Fix real defects in owned paths (mta, outbound-mta,
mailstore-core, imap-server, worker mail paths) with fail-before regression
tests; no docker builds.

## Method — real mail, real mailbox, real read
1. **Provision a live mailbox** for a real tenant/domain (console mailboxes
   surface or the provisioning API); confirm the account row + INBOX exist.
2. **SMTP inbound**: send real messages (python smtplib) over plain + STARTTLS
   submission; include hostile edges (8-bit subject, maximum line length,
   many recipients, missing/invalid HELO, empty MAIL FROM). Verify accept/
   refusal codes per the documented policy, storage rows (mailstore/
   mail_messages), and that the MTA logs stay clean (no panics).
3. **IMAP read**: IMAPS login with the provisioned credentials; LIST,
   SELECT INBOX, FETCH BODY[] of the message you sent (verify content),
   SEARCH, UIDNEXT monotonicity across an expunge, STORE flags; failure
   arms (bad auth, oversized literal). Nothing crashes; refusals typed.
4. **Outbound to the real world**: send from the console (direct or campaign)
   to a recipient that routes into Mailpit; on the wire verify:
   DKIM-Signature present and VALID for the domain key, List-Unsubscribe
   present (mailto arm reachable after F-4), tracking links rewritten to
   the tracking host, VERP Return-Path; the queue row terminal + the
   outbound relay ledger (outbound-mta) agree; worker logs show the
   transport used.
5. **Bounces/FBL**: POST a SIGNED SES-style bounce + complaint for a message
   you sent; verify bounce_events/complaint rows, suppression created,
   sales ledger hook fired, and a REPLAY does not double-apply.
6. **Webhooks out**: tenant webhook → local sink; delivery + signature
   verify; sink 500 → retry ladder observed in webhook_queue; sink fixed →
   next retry succeeds; disable → no deliveries.
7. **Tracking round trip**: click/open/unsubscribe from the delivered mail;
   events recorded (DB + analytics queue → ClickHouse), unsubscribe blocks
   the next send with the named refusal, one-click works without auth and
   never 500s (unknown-tenant token included).
8. **Concurrency/hostile**: 20 paced simultaneous inbounds; a re-delivered
   Message-ID creates no second draft; oversized body declines with the
   named note; caps (line length/recipients) hold.

## Rules
- Evidence per flow (raw transcript/log excerpt/DB select); NOT-VERIFIED if
  unreachable; fix or file with severity + repro; unique suffixes. No
  docker builds/compose.
- Host test env: TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0

## ZERO SKIPS (owner mandate)
Every probe listed above MUST be executed and evidenced — no sampling, no
"spot-check", no summarizing a section instead of running it. A probe that
cannot be reached is NOT skipped: it carries the exact command you ran, the
exact error observed, and the reason it is unreachable (then it is a finding
in itself). Partial coverage is a failed deliverable. Report per probe:
probe → command → observed result → DB/wire verification → verdict
(PASS / DEFECT / UNREACHABLE-with-proof).
