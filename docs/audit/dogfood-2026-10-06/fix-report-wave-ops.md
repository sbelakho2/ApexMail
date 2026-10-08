# Fix report — wave-ops (DSR SLA/stats, sweep trigger, ops metrics, suppression note, SES dev)

> Date: 2026-10-08 · Repo: `/Users/sabelakhoua/IdeaProjects/ApexMail` (main @ 8e9c09cb + live wave)
> Scope: the remaining filed items from the live dogfood wave, per the work order:
> E-DSR-SLA, E-DSR-STATS, E-SWEEP-TRIGGER, F-OPS (a–d), E-SUPPRESSION-TXN (doc only),
> and the mail-plane SES/FBL items.
>
> Rules followed: no `docker build`/`docker compose up` was run (the coordinator owns the
> full-stack rebuild); KiwiCaptcha surfaces were not touched; host tests ran with
> `TEST_DATABASE_URL=postgresql://apexmail:…@127.0.0.1:5432/apexmail`,
> `TEST_REDIS_URL=redis://:…@127.0.0.1:16379/0`, ClickHouse `127.0.0.1:8123`.
> Fail-before proofs were executed against the reverted code and the code restored afterwards
> (verified: `diff -q docker-compose.yml /tmp/compose.final.yml` → identical).
>
> Environment note: the live containers for tracking/enterprise/api-server still carried the
> pre-fix images during this run (compliance/api-server were partially rebuilt by the
> coordinator mid-run), so the "after" halves for those three items were driven against the
> **current-tree host binaries** against the live Postgres/Redis/ClickHouse/containers — the
> same `[current-tree host]` convention the dogfood waves use. Every item below ends with the
> exact live-scrape command to run once the coordinator's rebuild lands.

---

## 1. E-DSR-SLA (P1) — statutory overdue is now a production surface

**Defect.** `GdprAutomation::is_statutorily_overdue` had zero production callers; the
compliance DSR queue tick never looked at due dates and `/gdpr/stats` had no overdue bucket,
so a backdated request stayed invisible (dogfood repro: backdate `statutory_due_at` to
`NOW() - 2 days` → nothing changed).

**Fix (files).**
* `services/mail-server/crates/compliance/src/gdpr_automation.rs` — new public
  `count_statutorily_overdue(tenant_id)` that loads the OPEN requests (`status NOT IN
  ('completed','rejected','expired','failed')`, the same predicate as the existing partial
  index `idx_dsr_statutory_due_open`) and counts them through THE canonical
  `is_statutorily_overdue` decision (extended deadline wins; terminal never overdue).
  `get_request_stats` now reports `"overdue"` through it — the production caller.
* `services/mail-server/crates/compliance/src/bin/server.rs` — the 30 s tick now calls
  `count_statutorily_overdue(None)` and logs a `warn!` when any breach is open (the sweep
  flags overdue requests).

**Test.** `gdpr_automation::db_tests::stats_report_partial_and_backdated_sla_breaches_as_overdue`
— seeds one backdated OPEN request, one in-window OPEN request and one terminal request with a
backdated deadline, then asserts `overdue == 1` (and `partial == 2`, `rejected == 0`).

**Fail-before proof** (old code + the test only, reverted functional hunks):
```
test gdpr_automation::db_tests::stats_report_partial_and_backdated_sla_breaches_as_overdue ... FAILED
assertion `left == right` failed: partial is its own bucket:
  {"completed":1,"pending_verification":0,"processing":0,"rejected":2,"tenant_id":"t-…","total":3,"verified":0}
  left: Null   right: Number(2)
```
**After:** `cargo test -p compliance --lib gdpr_automation::db_tests` → **11 passed, 0 failed**.

**Live proof** (current tree vs the deployed container, same backdated tenant fixture):

```
$ docker exec apexmail-postgres psql -U apexmail -d apexmail -c \
  "INSERT INTO data_subject_requests (…, status, received_at, statutory_due_at, expires_at) VALUES
   ('REQ-waveops-over', …, 'partial', NOW()-'40 days', NOW()-'2 days', NOW()+'30 days'),
   ('REQ-waveops-ok',   …, 'partial', NOW()-'3 days',  NOW()+'27 days',NOW()+'30 days')"

# deployed container (fail-before — the old mapping)
$ docker exec apexmail-compliance-1 … /gdpr/stats?tenant_id=t-waveops-1791484893
{"completed":0,"pending_verification":0,"processing":0,"rejected":2,"total":2,"verified":0}

# current-tree host binary, same live DB/Redis (after)
$ [current-tree] GET /gdpr/stats?tenant_id=t-waveops-1791484893
{"completed":0,"expired":0,"failed":0,"overdue":1,"partial":2,"pending_manual_review":0,
 "pending_verification":0,"processing":0,"rejected":0,"tenant_id":"t-waveops-…","total":2,"verified":0}

# the 30 s sweep tick flags the breach (host log)
GDPR DSR(s) past the statutory response deadline — SLA breach open overdue=2
```
Fixture rows deleted after the proof (`DELETE 2`; count 0). Live-scrape command after the
rebuild: `docker exec apexmail-compliance-1 sh -lc 'TOKEN=$(…COMPLIANCE_AUTH_TOKEN…); wget -qO- --header="Authorization: Bearer $TOKEN" "http://127.0.0.1:3011/gdpr/stats?tenant_id=<t>"'`.

**Residual:** the CP compliance overview (`gdpr_requests` mirror) already reported its own
`overdue` count derived by migration 172's SQL deadline policy; the two surfaces now agree in
semantics (open requests past the stored clock).

---

## 2. E-DSR-STATS — `partial` is no longer reported as `rejected`

**Defect.** `get_request_stats` bucketed `status IN ('rejected','failed','partial')` as one
`rejected` count, so a partially-completed erasure was reported to the tenant as rejected;
`expired`/`pending_manual_review` rows also vanished from every bucket and from `total`.

**Fix.** `gdpr_automation.rs::get_request_stats` now groups by status and returns explicit
buckets: `pending_verification`, `verified`, `processing` (processing+retrying), `completed`,
`rejected`, `failed`, `partial`, `expired`, `pending_manual_review`, plus `overdue`, with
`total` = sum of ALL rows (unknown statuses still counted so the aggregate can never lose
rows). Shape is a superset; no caller relied on the old conflation (grep: no other reader of
the `rejected` key).

**Proof.** Same test as §1 (asserts `partial == 2`, `rejected == 0`); fail-before quoted there.
The live deployed-vs-current-tree pair in §1 is the same evidence at the API level.

---

## 3. E-SWEEP-TRIGGER — on-demand overage sweep (ops entrypoint)

**Defect.** The overage sweep only ran on the daily loop whose first tick is the next UTC
midnight (`next_day_start`); no operator trigger existed.

**Fix (files).**
* `services/mail-server/crates/billing-service/src/maintenance.rs` — new public
  `sweep_overage_once(&AppState) -> Result<OverageSweepResult, String>`: runs the canonical
  `overage::sweep_period_overage`, logs the outcome and returns it. The nightly loop now calls
  the SAME function (one code path, one behavior).
* `services/mail-server/crates/billing-service/src/bin/server.rs` — new one-shot flag
  `--sweep-overage-only` (env `BILLING_SWEEP_OVERAGE_ONLY`), the `--reconcile-plans-only`
  pattern: builds db+redis state, runs the sweep, prints a one-line report, exits. Placed
  BEFORE the Stripe webhook-secret fail-fast so closing a period works even when the inbound
  transport secret is absent.

**Tests.**
* `maintenance::tests::the_on_demand_sweep_trigger_is_wired_to_the_canonical_sweep` (source
  pin: binary exposes the flag **and** the loop calls the same `sweep_overage_once`).
* `tests/coverage_adversarial.rs::sweep_overage_only_cli_runs_the_canonical_sweep_on_demand` —
  spawns the REAL `billing-service` binary with `--sweep-overage-only` against a private
  canonical DB clone and asserts exit 0 + the printed report.

**Fail-before proofs.**
```
# (a) reverted bin/server.rs, integration test:
$ cargo test -p billing-service --test coverage_adversarial sweep_overage_only_cli_runs…
test … FAILED
the one-shot sweep must exit 0
stderr: error: unexpected argument '--sweep-overage-only' found …   (exit 2)
# (b) the stale live binary, same message, same exit 2
```
**After:** test passes; `the_on_demand_sweep_trigger_is_wired_to_the_canonical_sweep` ok.

**Live command (non-mutating; the shared DB currently has 5 unbilled periods, so the proof run
short-circuits the billing side)**:
```
$ DATABASE_URL=postgresql://apexmail:…@127.0.0.1:5432/apexmail \
  REDIS_URL=redis://:…@127.0.0.1:16379/0 OVERAGE_INVOICING_ENABLED=false \
  ./target/debug/billing-service --sweep-overage-only
overage sweep: periods_checked=0 invoices_created=0 payg_invoices_created=0 wallet_paid=0
pending_dunning=0 skipped_no_address=0 skipped_no_overage=0 skipped_unknown_plan=0
failed_periods=0 aged_needs_review=0 pricing_needs_review=0 existing_invoice_mismatches=0
exit=0
```
The full invoicing path on live data was already exercised by the money-tracking dogfood's
canonical sweep (idempotent re-run: `periods_checked=0, invoices_created=0`).

---

## 4. F-OPS — the metrics items

### 4a. OPS-2 tracking metrics — bind per the documented scrape contract (P2)

**Defect.** The tracking metrics listener binds container loopback unless `METRICS_BIND_ADDR`
is set; no compose file set it, so the documented `tracking:9092` target was connection-refused
from every other container and the host port mapping answered "Empty reply from server".

**Fix.** `docker-compose.yml` (tracking env): `METRICS_BIND_ADDR:
${TRACKING_METRICS_BIND_ADDR:-0.0.0.0}` — all interfaces INSIDE the compose network; host
exposure stays `127.0.0.1`-only via the existing port mapping. The reader in
`tracking-service/src/main.rs` already honored the variable.

**Test.** `tracking_service::config::tests::dev_compose_binds_tracking_metrics_for_the_documented_scrape_target`
(compose invariant + main.rs reader pin).

**Fail-before (live, still reproducible against the old container):**
```
$ docker exec apexmail-worker-1 wget -S -O - http://tracking:9092/metrics
Connecting to tracking (tracking)|172.20.0.5|:9092... failed: Connection refused.
$ curl -sv http://127.0.0.1:9092/metrics        # host mapping
* Empty reply from server                        (curl exit 52)
```
**After (current-tree host binary run with `METRICS_BIND_ADDR=0.0.0.0`, port 19092 to avoid the
published 9092; scrape driven FROM another container):**
```
$ curl 'http://127.0.0.1:13999/c/ZZZZ…'          # drive one counter
$ docker exec apexmail-worker-1 wget -S -O - http://host.docker.internal:19092/metrics
  HTTP/1.1 200 OK
# TYPE apexmail_tracking_click_unknown_token_total counter
apexmail_tracking_click_unknown_token_total 1
```
A control instance started WITHOUT the variable (loopback default) was unreachable from the
same network vantage — the variable is exactly the fix.

**Live-scrape command after the coordinator's rebuild (the documented target itself):**
```
docker exec apexmail-worker-1 wget -S -O - http://tracking:9092/metrics | head -3
```

### 4b. OPS-3 enterprise `/metrics` 401 — authorize the documented scrape (P2)

**Defect.** The handler admits loopback or a bearer `METRICS_TOKEN` (H-3); the dev compose set
no token and `deploy/prometheus.yml` had no `authorization:` block → the documented
`enterprise:3008` job answered 401 from the network.

**Fix.**
* `docker-compose.yml` (enterprise env): `METRICS_TOKEN: ${ENTERPRISE_METRICS_TOKEN:-dev-enterprise-metrics-token-change-me}`.
* `deploy/prometheus.yml`: the `apexmail-enterprise` job carries
  `authorization: { type: Bearer, credentials_file: /etc/prometheus/monitoring/enterprise_metrics_token }`,
  and the compose prometheus service mounts
  `./deploy/monitoring/enterprise_metrics_token` (new committed dev credential file, value =
  the compose default) at that path.
* Constraint found while fixing: **Prometheus v2.55.1 (the pinned image) has no
  `--config.expand-env`** — an initial env-expansion wiring would have made the monitoring
  profile fail to start; the `credentials_file` form is version-safe and is what shipped. The
  test asserts the flag is absent from the prometheus command.

**Test.** `enterprise::config::tests::dev_deploy_artifacts_authorize_the_enterprise_metrics_scrape`
(service token line, mount, no-3.x-flag guard, prometheus authorization block, committed
credential matches the compose default).

**Fail-before (live, old stack):**
```
$ docker exec apexmail-worker-1 wget -S -O - http://enterprise:3008/metrics
  HTTP/1.1 401 Unauthorized
$ docker exec apexmail-enterprise-1 env | grep METRICS_TOKEN   → (unset)
```
Pin-test fail-before: with the credential mount removed →
`panicked … the prometheus service must mount the enterprise scrape credential file`.

**After (current-tree binary with the token, driven from another container):**
```
$ docker exec apexmail-worker-1 wget -qO- --header="Authorization: Bearer dev-enterprise-metrics-token-change-me" \
    http://host.docker.internal:13008/metrics
# TYPE apexmail_enterprise_info gauge
apexmail_enterprise_info 1
```
The 401/200/wrong-token matrix itself is pinned by the existing
`enterprise/tests/security_regression.rs` metrics test (loopback admission, bearer admission,
wrong token refused).

**Live-scrape command after the rebuild:**
```
docker exec apexmail-worker-1 wget -qO- \
  --header="Authorization: Bearer $(cat deploy/monitoring/enterprise_metrics_token)" \
  http://enterprise:3008/metrics | head -3
```

### 4c. OPS-4 `redis_*` unreachable — emitted by the always-on exposed exporter (P3)

**Defect.** The only emitter of the documented `redis_*` eviction gauges is the
observability service (`redis_monitor.rs`, `metrics` facade), which is profile-gated
`monitoring` and not part of the running stack; the alert rules additionally queried
redis-exporter names (`redis_memory_used_bytes{job="redis"}`) that nothing exports.

**Fix.**
* `observability-service/src/redis_monitor.rs` — new `spawn_eviction_monitor(pool,
  interval_secs)` helper wrapping the canonical `RedisKeyMonitor` loop (one implementation for
  both services).
* `api-server/src/bin/server.rs` — starts that monitor when the metrics port is enabled
  (interval `REDIS_MONITOR_INTERVAL_SECS`, default 60 s), so `redis_*` lands on the exposed
  `:9090` scrape target.
* `deploy/alerting-rules.yml` (`RedisMemoryPressure`) and
  `deploy/prometheus/alerts/infrastructure-alerts.yml` (`RedisMemoryCritical`) — retargeted to
  `redis_memory_utilization_ratio{job="apexmail-api"}` (the emitted ratio; 0.0 when maxmemory
  is unlimited), with comments explaining the dead names.

**Test.** `api_server::bin::tests::the_binary_exposes_redis_eviction_metrics_on_the_scrape_port`
(source pin). The monitor's own emission is covered by the 28 existing `redis_monitor` tests
(`cargo test -p observability-service --lib redis_monitor` → 28 passed).

**Live proof (current-tree host api-server, live Redis; scraped over the network from the
worker container too):**
```
$ curl -s http://127.0.0.1:19090/metrics | grep -E '^redis_'
redis_evicted_keys_total 0
redis_used_memory_bytes 2908896
redis_memory_utilization_ratio 0
redis_eviction_rate_per_minute 0
redis_maxmemory_bytes 0

$ docker exec apexmail-worker-1 wget -qO- http://host.docker.internal:19090/metrics | grep -c '^redis_'
5
```
Deployed api-server (`:9090`) had `0` such samples (fail-before, quoted in §4d's run).

**Live-scrape command after the rebuild:**
```
curl -s http://127.0.0.1:9090/metrics | grep '^redis_'
```

### 4d. OPS-5 `ddos_*` — ported to the exposed metrics facade (P2)

**Defect.** `ddos-protection/src/metrics.rs` registered into the `prometheus` crate's private
registry while the api-server exposes the `metrics`-facade recorder
(`metrics-exporter-prometheus`, :9090) → zero `ddos_*` samples despite live WAF/rate-limit
decisions.

**Fix.** `ddos-protection/src/metrics.rs` rewritten to emit through the `metrics` facade,
keeping the documented series names/labels (docs/security/Security_Systems.md § Prometheus
metrics) and the call-site API (`REQUESTS_TOTAL.as_ref().with_label_values(&[..]).inc()`, …)
via small `CounterVec`/`GaugeVec`/`HistogramVec` wrappers + `describe_*` help. `Cargo.toml`:
`prometheus` dependency replaced by `metrics` (workspace); `metrics-exporter-prometheus` added
as a dev-dependency. All 12 emission sites compile unchanged; `cargo test -p ddos-protection
--lib` → **97 passed**.

**Test.** `metrics::tests::ddos_counters_render_on_the_metrics_facade_exporter` — renders a
local facade recorder (the same exporter the api-server installs) and asserts
`ddos_requests_total{decision="blocked",layer="blocklist"} 1`, the `inc_by` accumulation, the
`ddos_blocked_ips{reason="local"}` gauge and the anomaly histogram.

**Fail-before proof** (old `prometheus`-registry backend + the new test):
```
test metrics::tests::ddos_counters_render_on_the_metrics_facade_exporter ... FAILED
the exposed exporter must render ddos_requests_total:
        ← render is EMPTY (the live OPS-5 defect, in a unit test)
```
**After:** same test ok; live fail-before on the deployed exporter was `curl -s
http://127.0.0.1:9090/metrics | grep -c '^ddos_' → 0`.

**Live proof (current-tree host api-server):**
```
$ curl -s http://127.0.0.1:19090/metrics | grep -c '^ddos_'          → 2 (pre-traffic)
$ for i in $(seq 1 12); do curl -s -o /dev/null http://127.0.0.1:18080/v1/auth/csrf; done
$ curl -s http://127.0.0.1:19090/metrics | grep -E '^ddos_'
ddos_requests_total{decision="allowed",layer="ok"} 13
ddos_requests_total{decision="evaluated",layer="all"} 13

$ docker exec apexmail-worker-1 wget -qO- http://host.docker.internal:19090/metrics | grep '^ddos_requests_total'
ddos_requests_total{decision="allowed",layer="ok"} 13
ddos_requests_total{decision="evaluated",layer="all"} 13
```
**Live-scrape command after the rebuild** (drive one request first so the middleware runs):
```
curl -s -o /dev/null http://127.0.0.1:8080/health/live
curl -s http://127.0.0.1:9090/metrics | grep -E '^ddos_'
```

---

## 5. E-SUPPRESSION-TXN — doc note only (no code change)

Per the work order the product contract is authoritative: *global suppression always applies*,
regardless of category. One paragraph was added to the tracking report, §3.2, aligning the
brief's expectation and citing the contract
(`services/mail-server/crates/apexmail-lib/src/email_headers.rs:164-170` — “Global suppression
always applies regardless”; `docs/api/endpoints/messages.md` § Errors — `ALL_RECIPIENTS_SUPPRESSED`
with no category carve-out for the public send contract). No production code was touched for
this item.

File: `docs/audit/dogfood-2026-10-06/dogfood-live-money-tracking.md` (blockquote “Resolution
note (E-SUPPRESSION-TXN, expectation alignment — no code change)”).

---

## 6. Mail plane — SES `/v1/ses/notifications` dev configuration + ARF note

### 6a. SES 503 / dev allowlist

**Defect (FINDING-5 / F-4.1).** The dev compose passed `SNS_ALLOWED_TOPIC_ARNS: ${…:-}` (empty)
→ every notification answered `503 "SNS notifications are not configured"`; and even with an
allow-list, the AWS-only `SigningCertURL` allowlist + fetch means no locally-signed payload can
pass, so the path was unexercisable in dev.

**Fix.**
* `docker-compose.yml` (api-server env): `SNS_ALLOWED_TOPIC_ARNS` now defaults to the local ARN
  `arn:aws:sns:eu-central-1:000000000000:apexmail-dev-ses-events`, and a new dev-only
  `SNS_DEV_SIGNING_KEY_PEM` is passed through.
* `api-server/src/routes/ses_notifications.rs`: new `dev_signing_key(environment, raw)` — an
  RSA public-key PEM (single-line `\n`-escaped, the repo's PEM env convention). When set and
  the environment is NOT production, signatures are verified against that LOCAL key and the
  AWS cert-URL allowlist/fetch is skipped (no fetch exists, so the SSRF guard has nothing to
  protect; the crypto is still enforced). In production the variable is IGNORED with an
  error log. The topic allow-list and timestamp freshness apply in dev too.
* Docs: `.env.example`, `docs/deployment/configuration.md`, `deploy/DEPLOYMENT.md`
  (§ “Exercising the path in development (no AWS)”), including the openssl recipe.

**Tests** (`ses_notifications.rs`): `dev_signing_key_is_ignored_in_production_and_never_empty`,
`dev_local_key_exercises_the_signed_notification_path` (local key + non-AWS cert URL → Ok;
tampered body → 403; other key → 403; foreign topic → 403),
`dev_compose_wires_the_sns_allowlist_and_signing_anchor`,
`handler_reads_the_dev_signing_key_through_the_production_gate`. Full module:
**40 passed, 0 failed**.

**Live proof (fail-before → after):**
```
# deployed api-server, pre-fix env (fail-before)
$ curl -s -X POST http://127.0.0.1:8080/v1/ses/notifications -H 'Content-Type: text/plain' --data @envelope.json
HTTP 503  {"error":{"code":"SERVICE_UNAVAILABLE","message":"SNS notifications are not configured"}}
$ docker exec apexmail-api-server-1 sh -lc 'env | grep ^SNS'   → SNS_ALLOWED_TOPIC_ARNS=

# current-tree host binary with the dev config (local RSA key + local topic ARN)
$ openssl genrsa -out sns_dev_key.pem 2048 ; (pub key → SNS_DEV_SIGNING_KEY_PEM)
$ POST (Signature = RSA-SHA256 over the SNS string-to-sign, SigningCertURL = http://127.0.0.1:9/…)
HTTP 200
$ POST same envelope with the Message tampered
HTTP 403  {"error":{"code":"FORBIDDEN","message":"Invalid SNS signature"}}
$ POST with a foreign TopicArn
HTTP 403  {"error":{"code":"FORBIDDEN","message":"Unknown SNS topic ARN"}}
```
No suppression or event row was written by the proof (Send event: `SELECT count(*) FROM
suppressions WHERE email='wave-ops-dev@dogfood.test'` → 0).

**Live command after the coordinator's rebuild** (with the dev key configured):
`curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/v1/ses/notifications -H 'Content-Type: text/plain' --data-binary @envelope.json` → `200` (503 before the fix).

### 6b. ARF FBL PTR — genuine dev-unreachable (recorded, not fixed)

An *authoritative* ARF/FBL complaint cannot be produced in any local stack: the FBL registry
validates the source by PTR/FCrDNS of the injecting IP against a registered provider mailbox,
and a loopback (or LAN) injector can never be authoritative. The dogfood proof line remains the
canonical statement:

```
complaint_events: … | abuse | authoritative=f |
  observation_detail="non-authoritative source 127.0.0.1; claimed message_id="
```

The observation row is written and correct; the suppression/sales legs require a provider
registration with real reverse DNS. Recorded in `deploy/DEPLOYMENT.md` (§ “Exercising the path
in development”) as UNREACHABLE-with-proof; the self-hosted VERP bounce path (dogfood Flow 5C)
covers the authoritative suppression behavior instead. No code change attempted — faking it
would be exactly the fabrication the finding forbids.

---

## 7. Changes (files) and validation summary

**Changed**
* `services/mail-server/crates/compliance/src/gdpr_automation.rs`,
  `…/compliance/src/bin/server.rs`
* `services/mail-server/crates/billing-service/src/{maintenance.rs,bin/server.rs}`,
  `…/billing-service/tests/coverage_adversarial.rs`
* `services/mail-server/crates/ddos-protection/src/metrics.rs`, `…/Cargo.toml`
* `services/mail-server/crates/observability-service/src/redis_monitor.rs`
* `services/mail-server/crates/api-server/src/bin/server.rs`,
  `…/api-server/src/routes/ses_notifications.rs`
* `services/mail-server/crates/tracking-service/src/config.rs` (test pin),
  `…/enterprise/src/config.rs` (test pin)
* `docker-compose.yml`, `deploy/prometheus.yml`, `deploy/alerting-rules.yml`,
  `deploy/prometheus/alerts/infrastructure-alerts.yml`,
  `deploy/monitoring/enterprise_metrics_token` (new dev credential)
* `.env.example`, `docs/deployment/configuration.md`, `deploy/DEPLOYMENT.md`,
  `docs/audit/dogfood-2026-10-06/dogfood-live-money-tracking.md`

**Validation runs (all green after the fail-before pairs)**
* `cargo test -p compliance --lib gdpr_automation::db_tests` → 11 passed (incl. the new
  SLA/stats test). Full `cargo test -p compliance --lib` → 627 passed / 22 failed, where every
  failure is in `risk_scoring::tests` / `routes::db_tests::cors_origin_configuration_arms`
  (modules this wave did not touch) and each passes in isolation — the known canonical-template
  clone contention under the full parallel run
* `cargo test -p billing-service --test coverage_adversarial sweep_overage_only_cli…` → ok;
  `cargo test -p billing-service --lib the_on_demand_sweep_trigger…` → ok
* `cargo test -p ddos-protection --lib` → 97 passed (incl. the facade-render regression)
* `cargo test -p observability-service --lib redis_monitor` → 28 passed
* `cargo test -p api-server --lib ses_notifications` → 40 passed;
  `cargo test -p api-server --bin api-server` → 4 passed (incl. the redis-monitor pin);
  `cargo test -p api-server --lib middleware::metrics` → 4 passed
* `cargo test -p tracking-service --lib config::tests::dev_compose_binds…` → ok;
  `cargo test -p enterprise --lib config::tests::dev_deploy_artifacts_authorize…` → ok
* `docker compose config -q` → exit 0; `python3 -c "yaml.safe_load('deploy/prometheus.yml')"`
  → parses, 21 jobs
* `sh tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` → exit 0 (“total 2786 at or
  below baseline 2827”)

**Not done (explicitly out of scope / coordinator-owned)**: no docker images were rebuilt, no
compose services were (re)started, KiwiCaptcha was untouched. The live after-proofs for
tracking/enterprise/api-server ran against current-tree host binaries; their container-level
live-scrape commands are listed per item and will pass once the coordinator's rebuild lands.
