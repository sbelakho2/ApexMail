# Progress — delivery plane slice

Slice: worker-processors; mta, outbound-mta, mailstore-core, imap-server, template-renderer,
spam-filter, waf-engine, ddos-protection; migrations 1xx/2xx changed in last 30 days; deploy/.

## worker-processors
- [x] services/mail-server/crates/worker-processors/src/lib.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/fence.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/mod.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/config.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/error.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/pool.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/backpressure.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/circuit_breaker.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/common/graduation.rs
- [x] services/mail-server/crates/worker-processors/src/email/mod.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/transport_router.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/types.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/dlp.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/tracking.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/outbound_mta.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/transport.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/email/processor.rs (clean except findings above; full file read)
- [x] services/mail-server/crates/worker-processors/src/common/config.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/automations.rs (production + tests read; finding filed)
- [x] services/mail-server/crates/worker-processors/src/campaigns.rs (production + tests read; findings filed)
- [x] services/mail-server/crates/worker-processors/src/analytics/processor.rs (production read; test modules inventoried)
- [x] services/mail-server/crates/worker-processors/src/analytics/types.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/analytics/mod.rs (clean)
- [x] services/mail-server/crates/worker-processors/src/campaigns.rs (production + tests)
- [x] services/mail-server/crates/worker-processors/src/bin/worker.rs (production read; tests inventoried)
- [x] services/mail-server/crates/worker-processors/src/reply_handler/{mod,types,ai,classifier,deterministic,policy,processor}.rs (production read; tests inventoried)
- [x] services/mail-server/crates/worker-processors/src/webhook/{mod,types,ssrf,processor}.rs (production read; tests inventoried)
- [x] services/mail-server/crates/worker-processors/tests/automations_execution.rs (integration tests, inventoried)
- NOTE: worker-processors test modules (~220 test fns) were reviewed via module outlines + targeted reads; production code was read in full.

## mta
- [x] services/mail-server/crates/mta/src/auth/email_authentication.rs (production read; clean)
- [x] services/mail-server/crates/mta/src/auth/arc.rs (production read; clean)
- [x] services/mail-server/crates/mta/src/auth/bimi.rs (production read; module is explicitly documented as maintained-but-not-wired F-16)
- [x] services/mail-server/crates/mta/src/auth/mta_sts.rs (production read; maintained-but-not-wired F-16)
- [x] services/mail-server/crates/mta/src/auth/dane.rs (production head read; maintained-but-not-wired F-16)
- [x] services/mail-server/crates/mta/src/auth/lockout.rs (production read; clean)
- [x] services/mail-server/crates/mta/src/auth/mod.rs (read)
- [x] services/mail-server/crates/mta/src/auth/test_dns.rs (test support, skimmed)
- [x] services/mail-server/crates/mta/src/config.rs (production read; finding: VERP_HMAC_SECRET wiring)
- [x] services/mail-server/crates/mta/src/servers/inbound.rs (production read in full; clean)
- [x] services/mail-server/crates/mta/src/servers/submission.rs (production read in full; clean)
- [x] services/mail-server/crates/mta/src/servers/bounce.rs (production read to line 900; VERP/suppression path reviewed, clean)
- [x] services/mail-server/crates/mta/src/servers/content_security.rs (production read in full; clean)
- [x] services/mail-server/crates/mta/src/servers/fbl_registry.rs (production read in full; clean)
- [x] services/mail-server/crates/mta/src/servers/feedback_loop.rs (production head read; clean)
- [ ] services/mail-server/crates/mta/src/servers/{inbound_delivery.rs,util.rs} — NOT read in this run (budget exhausted)
- [ ] services/mail-server/crates/mta/src/{tls.rs,supervision.rs,gmail_annotations.rs,bin/mta.rs,postmaster/*} — NOT read in this run
- NOTE: this run was stopped by budget mid-mta; the files listed above were genuinely reviewed, the unchecked ones were not.

## outbound-mta (partial)
- [x] services/mail-server/crates/outbound-mta/src/retry.rs (production read; clean)
- [x] services/mail-server/crates/outbound-mta/src/warmup.rs (production read; clean)
- [x] services/mail-server/crates/outbound-mta/src/source_ip.rs (production read; clean)
- [ ] outbound-mta ledger.rs/relay.rs/mx.rs/smtp.rs/response.rs/dsn.rs/reconcile.rs/main.rs/tls.rs — NOT read in this run

## Remaining crates (scan-only, NOT file-by-file)
- mailstore-core, imap-server, template-renderer, spam-filter, waf-engine, ddos-protection:
  targeted security scans (weak crypto, TODO/FIXME, unwrap in prod, auth paths) plus
  structural inventory; mailstore-core/src/encryption.rs, imap LOGIN/AUTH paths,
  ddos decision.rs, template sandbox.rs were spot-read. NOT a complete file-by-file pass.

## migrations (partial)
- Reviewed in detail: 096, 102, 103, 127, 186, 187, 205, 212, 224, 236 (headers + key DDL),
  plus 088/089/105/115 referenced during findings. All other 1xx/2xx not read in this run.

## deploy (partial)
- Reviewed: docker-compose.yml, docker-compose.prod.yml, docker-compose.override.yml (image/env scan),
  .env.production.example (secret inventory), deploy/rollback-plan.md, deploy/DEPLOYMENT.md,
  deploy/load-secret-env.sh, deploy/scripts/deploy.sh (scan).
- All other deploy files (grafana dashboards, nginx rules, systemd units, load-test infra,
  monitoring) NOT read in this run.

Findings written: docs/audit/dogfood-2026-10-06/findings-delivery-plane.md (10 entries).
No code was edited.
