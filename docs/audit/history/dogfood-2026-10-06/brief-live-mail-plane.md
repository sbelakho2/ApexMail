# LIVE dogfood — mail plane (RUN the product, do not just read it)

You are dogfooding the RUNNING ApexMail stack, adversarially. Working dir:
/Users/sabelakhoua/IdeaProjects/ApexMail. The stack is up (docker compose). Key endpoints:
api 127.0.0.1:8080 (Host header selects the surface: app.apexmail.ee = customer console,
admin.apexmail.ee = control plane, apexmail.ee = marketing), SMTP submission 127.0.0.1:5587
(STARTTLS, self-signed) and 127.0.0.1:5525, IMAPS 127.0.0.1:993, Mailpit API/UI
http://127.0.0.1:8025 (all mail lands here), tracking 127.0.0.1:3001, mailstore gRPC internal.

## Your job: exercise the MAIL PLANE end to end and report what breaks
These flows are the product. RUN each one and capture the evidence (command + observed result):
1. **SMTP submission → queue → worker → Mailpit delivery.** Send via SMTP (python smtplib with
   STARTTLS on 5587, or curl the REST send) as a tenant; then prove the message is in Mailpit with
   correct From/To/Subject and DKIM-signature headers.
2. **Inbound delivery → mailstore → IMAP retrieval.** Deliver a message addressed to a mailbox
   (Mailpit is the sink for outbound; for inbound use the MTA's inbound path on port 25 or the
   mailstore gRPC per its README), then FETCH it over IMAPS (993) with the tenant's mailbox
   credentials and confirm body/headers survive.
3. **Tracking pixel + click redirect.** Send a campaign/message with tracking enabled, extract the
   pixel and click URLs from the delivered HTML, GET them, and confirm: (a) the pixel returns an
   image with the right headers, (b) the click 302s to the destination, (c) both land in ClickHouse
   / the events API within a minute.
4. **Bounce / complaint ingestion.** POST a realistic SES-compliant bounce and a complaint to
   /v1/ses/notifications the way the real notifier does (see the mta/worker code and the
   SNS_ALLOWED_TOPIC_ARNS + signature requirements; if the local stack cannot accept a signed
   payload, say so explicitly and test the internal handler path instead), then confirm the
   suppression row, the bounce bookkeeping and the sales feedback ledger the code claims.
5. **Unsubscribe.** Follow the unsubscribe link from a delivered message; confirm the suppression
   row appears and that a subsequent send to that address is refused by the send gate.
6. **Outbound MTA retries/warmup.** Drive a 4xx/5xx SMTP response at the relay (or read the retry
   ledger after Mailpit accepts) and confirm retry scheduling + backoff + terminal bookkeeping.

## Rules
- RUN things. A flow is only "dogfooded" when you have the command and its observed output.
- Adversarially: also try the nasty variants (header injection in a subject/recipient, 8-bit/UTF-8
  subject, 20 MB attachment, RCPT to a suppressed address, replay the same unsubscribe token).
- Do NOT edit code. Report.
- Write findings to docs/audit/dogfood-2026-10-06/dogfood-mail-plane.md as:
  ### <P0|P1|P2|P3> <file or endpoint> — <title>
  Ran: <exact command>   Observed: <exact output/status>   Expected: <honest behavior>
  Why it is a defect: …   Suggested fix: …
- Keep a live ledger at docs/audit/dogfood-2026-10-06/ledger-mail-plane.md: one line per flow
  (`RUN`/`PASS`/`FAIL`/`BLOCKED` + evidence pointer). BLOCKED requires the exact reason.
- Work through the six flows in order; if one blocks you, record BLOCKED with the reason and move on.
