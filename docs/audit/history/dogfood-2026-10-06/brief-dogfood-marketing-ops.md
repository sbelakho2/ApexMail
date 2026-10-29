# LIVE DOGFOOD — F: marketing, public surfaces, and cross-cutting ops

You are a live dogfooding agent. The stack serves the CURRENT tree.
Marketing is host-routed at `marketing.localhost` (apexmail.ee), plus the
public no-auth surfaces. Drive the real pages/flows — the product, not its
tests.

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-marketing-ops.md`
with per-probe evidence and verdicts. Fix real defects in owned paths
(marketing templates/static, api-server public routes, tools) with
fail-before tests; no docker builds.

## 1. Marketing site, all pages live
- Walk every page (home, features, pricing, compare/*, docs incl. API/SDK/
  webhooks, use-cases, legal, status, locales /de /fr /es, 404) with a real
  browser-equivalent fetch; assert: 200s, correct titles, the pricing page's
  numbers EQUAL the canonical catalog (grep the rendered HTML), the
  calculator island computes the canonical PAYG/overage figures (drive it
  via its JS inputs or verify the pre-rendered values), and the security.txt
  is served at `/.well-known/security.txt` with the right contact/expiry.
- **Forms**: contact/sales/enterprise/abuse forms — submit real ones and
  verify where they land (Mailpit/DB per the documented route); hostile
  inputs (2MB, injection) refused cleanly; the cookie-consent island and
  i18n switch work; no page renders unstyled (the CSP fix) — spot-check
  computed styles on 2 pages.
- **Funnel**: marketing pricing → signup deep link (`?plan=pro`) → app
  signup prefilled → completes; the CTA invariant (no dead-end plans).

## 2. Cross-cutting ops (the whole stack)
- **Health + metrics**: probe `/health/live|ready|deep` on api-server and
  the sibling services' health/metrics endpoints (9090 api metrics,
  tracking 9092, etc.); scrape `/metrics` and spot-check that the series the
  dashboards document EXIST with the documented labels (the dead-metric
  class): api-server request/latency series, tracking series, redis_*.
- **Rate limits / CSRF / idempotency / sessions** live across surfaces
  (console + CP + public): 429s engage per the documented budgets without
  starving other tenants; CSRF missing/wrong refused; idempotency replays
  single-effect; session revocation takes effect immediately.
- **WAF/DDoS behavior (PACED)**: hostile payload probes through the open
  edges (SQLi/XSS/path traversal strings as data) → typed refusals, no 5xx,
  and the reputation counters move (the A-3 fix); do NOT flood — keep to
  documented-safe pacing and stop if the protector engages (record it as
  expected behavior, not a defect).
- **Log hygiene**: grep the running containers' logs for secrets (active
  API keys, passwords, tokens, DSNs) over the last hour of your traffic —
  any live secret in logs is a P1.
- **Backups dry-run**: `scripts/clickhouse-backup.sh --dry-run` (or the
  documented safe mode) and the postgres backup path from deploy scripts in
  dry mode — verify they FAIL LOUDLY on an unreachable target (the U-1/U-9
  class) without touching real artifacts.
- **SDKs against the live API** (quick re-verification): one send from each
  SDK language you can run locally (php/python/go/ruby/java per packages/)
  with the NEW template_id support → rendered mail in Mailpit.

## Rules
- Evidence per probe (command + output/excerpt); NOT-VERIFIED when
  unreachable; fix or file with severity + repro; unique suffixes. No
  docker builds. Host test env:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0

## ZERO SKIPS (owner mandate)
Every probe listed above MUST be executed and evidenced — no sampling, no
"spot-check", no summarizing a section instead of running it. A probe that
cannot be reached is NOT skipped: it carries the exact command you ran, the
exact error observed, and the reason it is unreachable (then it is a finding
in itself). Partial coverage is a failed deliverable. Report per probe:
probe → command → observed result → DB/wire verification → verdict
(PASS / DEFECT / UNREACHABLE-with-proof).
