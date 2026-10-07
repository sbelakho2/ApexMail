# Adversarial file-by-file review — delivery plane slice

You are auditing the ApexMail repo FILE BY FILE, adversarially. Work from the working tree at
/Users/sabelakhoua/IdeaProjects/ApexMail (branch main, dirty tree — that is expected).

## Your slice (every file, none skipped)
1. `services/mail-server/crates/worker-processors/` (all .rs)
2. `services/mail-server/crates/mta/`, `crates/outbound-mta/`, `crates/mailstore-core/`,
   `crates/imap-server/`, `crates/template-renderer/`, `crates/spam-filter/`, `crates/waf-engine/`,
   `crates/ddos-protection/`
3. `services/mail-server/migrations/` (all 2xx/1xx .sql added or changed in the last 30 days —
   use `git log --since=30.days --name-only -- migrations` to pick them; read those end to end)
4. `deploy/` (all files: compose overlays, nginx, systemd, grafana dashboards, load-test infra)

## Bar each file must clear (report a finding when it does not)
- **Correctness**: a queue claim predicate that can double-send or strand a row; a retry/backoff
  that resets or never fires; a state machine transition with no terminal state; idempotence keys
  that collide; clock handling that assumes a shared clock across processes.
- **Honesty (audit #16)**: an upstream failure recorded as success; a delivery metric incremented
  before the send is durable; a log claiming a path the code did not take; a comment that lies.
- **Security**: DKIM/SPF/DMARC handling that can be bypassed; a verification result trusted from
  an untrusted header; an unauthenticated path that can inject mail or read another tenant's row;
  secrets in compose/env files committed with real values; a `latest` image tag.
- **Wiring**: a queue consumed by no worker (or a worker polling a queue nothing fills); an env var
  read but never set in any compose/CI file; a migration whose table no code reads; a config knob
  documented but unimplemented (or implemented but undocumented).
- **Quality**: swallowed errors (`let _ =` on a meaningful Result); duplicated predicate logic that
  has already drifted between crates; a test fixture that cannot represent production shapes.

## Deliverable
Write findings to `docs/audit/dogfood-2026-10-06/findings-delivery-plane.md`, one entry per finding:
```
### <severity: P0|P1|P2|P3> <file>:<line> — <one-line title>
Evidence: <the exact code/datum that proves it, quoted>
Why it is a defect: <one or two sentences>
Suggested fix: <minimal, concrete>
```
Severity: P0 = security/data-loss/user-blocking/mail-loss; P1 = wrong behavior users hit;
P2 = wiring/honesty gap or dead code shipping; P3 = polish.

Rules:
- Read EVERY file in your slice; append `- [x] <path>` progress lines to
  `docs/audit/dogfood-2026-10-06/progress-delivery-plane.md` as you go (batch them; never skip).
- Prove every finding from the file contents; no speculation, no style nits.
- Do NOT edit code — this slice reports only. (A later wave fixes.)
- Mark clean files `- [x] <path> (clean)`.
- Work in batches and write intermediate progress so a stopped run is still useful.
