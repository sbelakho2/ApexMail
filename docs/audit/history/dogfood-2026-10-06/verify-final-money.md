# Final live verification — Lane B: money, tracking, compliance, ops surfaces

Verifier: Lane B (final wave). Date: 2026-10-08 (evening UTC). Repo:
`/Users/sabelakhoua/IdeaProjects/ApexMail`, tree as left by the wave-G/capabilities fixes (HEAD `5dd40cc3`
plus the concurrent `web.rs` working-tree edit). No commit was made. **ZERO SKIPS**: B1..B9 all executed;
every command and its observed output is in the appendix. No KiwiCaptcha surface was touched, read, or
modified — the signup captcha flow was not used anywhere (all fixtures are direct SQL/product API writes).

Stack at verification: api-server `127.0.0.1:8080` (+`:9090` metrics), tracking `127.0.0.1:3001`
(metrics 9092 in-network), compliance `apexmail-compliance-1:3011` (internal), enterprise
`127.0.0.1:3002→3008`, worker/mta/outbound-mta live, Postgres `127.0.0.1:5432`, ClickHouse 8123,
Mailpit 8025. Docker context `colima-local`.

## Results

| Probe | What was probed | Exact command (inline) | Observed output / verdict | Evidence |
|---|---|---|---|---|
| **B1** | tracking metrics in-network scrape (the H fix) | `docker exec apexmail-api-server-1 wget -S -qO- http://tracking:9092/metrics`; `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/c/<unknown-token>`; re-scrape | HTTP 200 before with `apexmail_tracking_click_unknown_token_total 1`; unknown-token click → 404; re-scrape → counter **2** (HTTP 200, same from `worker-1`). **PASS** | appendix B1 |
| **B2** | DSR statutorily-overdue surface (`GET /gdpr/stats` → `overdue`) | `POST /gdpr/submit` (live compliance API); SQL backdate `statutory_due_at = NOW()-2d`; `GET /gdpr/stats?tenant_id=…`; SQL `status='completed'`; re-read | `overdue` 0 → **1** (backdated) → **0** (completed); per-status buckets correct; the running container's 5-min tick logs `WARN … SLA breach open overdue=1`. **PASS** | appendix B2 |
| **B3** | DSR/GDPR one-shot sweep CLI | `ls …/crates/compliance/src/main.rs`; `docker exec apexmail-compliance-1 /usr/local/bin/compliance-server --help`; live DB row + `docker logs` | **The reported CLI does not exist** (`src/main.rs` absent; running binary flags = `--port` only) → **FINDING F1**. The sweep that DOES exist (5-min expiry tick) processed a live overdue record: `pending_verification` → `expired`, log `Expired overdue GDPR requests count=1`, stats `expired=1 overdue=0`. **PASS with finding** | appendix B3 |
| **B4** | `/alerts/rules` CRUD + evaluation (former 501) | `POST/GET/PATCH/DELETE /v1/admin/alerts/rules` (Host `admin.localhost`, `x-api-key: local-dev-control-plane-api-key-32chars`); force usage via `metering_events`; watch worker sweep | create **201**, list **200**, get **200**, update **200** (`90/critical` persisted), delete **200 `{"deleted":true}`** (row gone); severity `bogus` → **400** named (not 500); live worker sweep `alerts_triggered=1` → `system_alerts` row `d23b8a2d-…` "Alert rule \"verify-b4-emails\" fired: emails at 3% of the plan limit (1000 / 30000)." + `last_triggered_at` set. **PASS** | appendix B4 |
| **B5** | metrics surfaces inventory | `curl :9090/metrics`; `curl -H "Authorization: Bearer $METRICS_TOKEN" :3002/metrics`; in-network python scrape of every declared target; `deploy/prometheus.yml` | api-server **200**, 9 documented families incl. `apexmail_http_request_duration_seconds` histogram + 570 `_bucket` series on the long-lived instance; enterprise bare **401**, wrong **401**, bearer **200** (`apexmail_enterprise_info 1`); ddos **2** series; redis **5** series; in-network declared app targets all **200** (api-server/tracking/enterprise/mta/worker/outbound-mta). **PASS** (monitoring-profile targets profile-gated, see F2) | appendix B5, `evidence-final-money/api-server-metrics-full-state.txt` |
| **B6** | dev SNS webhook (signed / unsigned / wrong ARN) | `python3 /tmp/sns_probe.py <ses-id> <rcpt> {complaint,unsigned,badarn}` against `POST /v1/ses/notifications` | **DEFECT found**: live dev stack had `SNS_DEV_SIGNING_KEY_PEM` empty → correctly-signed notification refused `400 "SigningCertURL must reference an AWS SNS certificate"` (fail-before). After configuring the documented dev anchor: signed **200**, complaint lands (`suppressions` `ses_complaint:abuse` + `events` `complained`); unsigned **403 Invalid SNS signature**; wrong ARN **403 Unknown SNS topic ARN**; negatives wrote nothing (counts 1/1 unchanged). **PASS after fix** | appendix B6, Defects D1 |
| **B7** | A/B experiment assignment (migration 248) | `python3 tools/dogfood-live-capabilities.py --only p2 --run-id vfb7`; then `python3 /tmp/b7_addendum.py` | P2.1–P2.9 **PASS** live (send 200, 200 recipients all phased with persisted `ab_bucket`, split test=104/holdout=96, md5 formula mismatches **0**, test_pct 52.0%); addendum: 200/200 buckets, recompute 0 mismatches, re-running the canonical `AB_SPLIT_SQL` → **UPDATE 0** and identical row fingerprint, two `GET /experiment` calls byte-identical. **PASS** | appendix B7, `evidence-final-money/b7-p2-harness.log` |
| **B8** | custom tracking domains (migration 247) | `POST/GET /v1/tracking-domains`, `/dns-records`, `/verify`, `DELETE`; click on `Host: track.<parent>` | create **201 pending** + named reason, list **200**, dns-records **200** (`CNAME track.<parent> → track.apexmail.ee`), verify-before-DNS **503 named (state unchanged)**, verify after resolver publish **200 verified**, owner click on the custom host **302 → the original URL**, foreign token **403** refusal page, pixel **200**, `DELETE` **204** then serving stops (**400**). **PASS** | appendix B8 |
| **B9** | send-time optimization weekday bug (wave G) | `python3 /tmp/b9_probe.py` (two campaigns: `Europe/Tallinn` + `America/New_York`) | Tallinn arm: 8 opens Wed 09:00 local → `scheduled_at 2026-10-14T06:00:00Z` = **Wednesday 09:00 local** (old DOW bucket would name Thursday); New York arm: 8 opens Mon 10:00 local → `2026-10-12T14:00:00Z` = **Monday 10:00 local** (old would name Tuesday). **PASS** | appendix B9 |

## Defects found

### D1 — dev-stack SNS signing anchor was not configured (the documented signed path was unexercisable) — FIXED

* **Probe**: B6. The brief states the dev stack sets `SNS_ALLOWED_TOPIC_ARNS` **and**
  `SNS_DEV_SIGNING_KEY_PEM`. Compose passes the latter through
  (`SNS_DEV_SIGNING_KEY_PEM: ${SNS_DEV_SIGNING_KEY_PEM:-}`) but `.env` carried no value, so the live
  api-server had `SNS_DEV_SIGNING_KEY_PEM=` (empty) and the AWS-only `SigningCertURL` allowlist stayed
  authoritative → no locally-signed notification could pass.
* **Fail-before** (exact):
  ```
  $ docker exec apexmail-api-server-1 sh -c 'printenv SNS_DEV_SIGNING_KEY_PEM | wc -c'   → 1   (empty)
  $ python3 /tmp/sns_probe.py "b6-ses-…@ses.local" "b6-failbefore@dogfood.test" complaint
  HTTP=400 body='{"error":{"code":"VALIDATION_ERROR","details":["SigningCertURL must reference an AWS SNS certificate"],…}}'
  ```
* **Fix**: configured the documented dev-only RSA public-key anchor in `.env` (generated with the exact
  `deploy/DEPLOYMENT.md` recipe; `.env` is gitignored — **no tracked file was modified**), then
  `docker compose up -d api-server` (context `colima-local`). The private key stayed in `/tmp`
  (`/tmp/sns_dev_key.pem`) and is not in the repo.
* **Fail-after** (exact):
  ```
  $ docker exec apexmail-api-server-1 sh -c 'printenv SNS_DEV_SIGNING_KEY_PEM | head -c 27' → -----BEGIN PUBLIC KEY-----
  $ python3 /tmp/sns_probe.py <attributed ses id> "b6-recipient@dogfood.test" complaint
  HTTP=200 body=''
  suppressions: sup_sx7girl5fteotp4vq19crj | vfb4155f681dc8ad49c3fd70f2 | b6-recipient@dogfood.test | ses_complaint:abuse | ses
  events:       evt_8b0479a2c59085c4efd5270aa5cfa76f | complained | b6-recipient@dogfood.test
  ```
  Negative arms after the fix: unsigned → **403 Invalid SNS signature**; wrong ARN → **403 Unknown SNS topic
  ARN**; both left the DB at exactly 1 suppression / 1 event and no rows for their recipients.

### F1 — the reported compliance one-shot sweep CLI does not exist (filed, P3)

* **Probe**: B3. `services/mail-server/crates/compliance/src/main.rs` does not exist (the binary is
  `src/bin/server.rs`), and the running binary advertises only `-p/--port`:
  ```
  Usage: compliance-server [OPTIONS]
  Options:
    -p, --port <PORT>  Override port (default from COMPLIANCE_PORT or 3011)
    -h, --help         Print help
  ```
  No `--sweep-once`/`--process-dsr-once`/equivalent exists in the crate or its git history, and the
  wave-G/alert-rules reports document no compliance flags (the analogous one-shot flag is the
  **billing-service** `--sweep-overage-only` from wave-ops, a different binary).
* **Severity P3 (operator convenience)**: no capability is missing — the compliance container's cron
  already processes overdue records continuously (30 s GDPR queue tick; 5 min expiry tick that expires
  verification-window-lapsed requests and warns on statutory breaches). Proven live during B3/B2:
  backdated row `4499277d-…` went `pending_verification → expired` on the 19:49:33 tick
  (`INFO … Expired overdue GDPR requests count=1`) and the SLA warn line fired
  (`WARN … SLA breach open overdue=1`). Filed, not fixed (the brief: absence of the flag is a finding).
  If an on-demand entrypoint is wanted, the wave-ops `--sweep-overage-only` pattern is the template.
* **ADDENDUM (fixed, 2026-10-08)**: the on-demand entrypoint was implemented after all, as the same
  wave-ops pattern the finding names: `compliance-server --sweep-once` (env
  `COMPLIANCE_SWEEP_ONCE`) now runs the exact cron jobs 1+3 path once — `dsr_queue_tick` +
  `dsr_expiry_tick`, extracted so the cron arms and the CLI share ONE code path — prints a
  machine-readable `dsr sweep: recovered=… processed=… expired_requests=… expired_tokens=…
  statutory_overdue=… failed_steps=…` line, exits 0, and exits non-zero when any step failed.
  Tests: the in-bin `dsr_sweep_ticks_process_overdue_state_and_report_counts` (seeded expiry rows,
  idempotent second run) and `crates/compliance/tests/sweep_once_cli.rs` (spawns the REAL binary
  `--sweep-once` against a private canonical DB clone, asserts the report line and the row flip —
  `CARGO_BIN_EXE_compliance-server`, 2/2 green). Live proof on the rebuilt container is recorded in
  the wave close-out.

### F2 — monitoring-profile scrape targets are not running in this stack (environment scope, not a wiring bug)

* **Probe**: B5. All **app-stack** declared targets in `deploy/prometheus.yml` resolve and serve 200
  in-network (api-server:9090, tracking:9092, enterprise:3008 with the bearer, mta:9090, worker:9093,
  outbound-mta:8093). The remaining declared targets (`observability:4400`, `postgres-exporter:9187`,
  `redis-exporter:9121`, `clickhouse-exporter:9116`, `node-exporter:9100`, `blackbox-exporter:9115`,
  `synthetic-monitor:9128`, `alertmanager:9093`) are behind compose `profiles: [monitoring]` together with
  Prometheus itself, so in this default-profile stack they answer DNS failure
  (`urlopen error [Errno -2] Name does not resolve`) — the declared host:port values match the compose
  service definitions (`OBSERVABILITY_PORT=4400`, `SYNTHETIC_LISTEN_ADDRESS=0.0.0.0:9128`, exporter default
  ports, alertmanager `9093`). No target 404s or refuses. The monitoring profile was deliberately not
  started (it would pull/start ~8 sidecars on a shared stack that had just suffered memory pressure —
  see E1). No fix required; recorded so the inventory is not read as "all jobs scrape today".

### E1 — environment incident: Postgres checkpointer SIGKILL → recovery (not a lane defect)

At 19:57:47 UTC the Postgres checkpointer was terminated (`checkpointer process (PID 323725) was
terminated by signal 9: Killed`), the server reinitialized and served `FATAL: the database system is in
recovery mode` for ~2.5 minutes; it recovered on its own at ~20:00 and every subsequent probe passed.
This killed the in-flight p2 harness run (exact error in the B7 appendix) after P2.9; B7's required
evidence was already captured, and the post-recovery addendum completed the deterministic/idempotence
proofs. Nothing in this lane's fixes touches Postgres configuration.

## ZERO SKIPS appendix (literal commands + literal output)

Method notes applying to all probes: DB reads are `docker exec apexmail-postgres psql -U apexmail -d
apexmail -c '…'`; compliance calls are issued from the api-server container (the compliance service is
internal); CP calls use `Host: admin.localhost` + `x-api-key: local-dev-control-plane-api-key-32chars`.

### B1 — tracking metrics in-network scrape

```
$ grep -n "METRICS_PORT\|METRICS_BIND_ADDR" docker-compose.yml
288:      METRICS_PORT: 9092
294:      METRICS_BIND_ADDR: ${TRACKING_METRICS_BIND_ADDR:-0.0.0.0}
311:      - "127.0.0.1:${TRACKING_METRICS_PORT:-9092}:9092"
$ docker exec apexmail-tracking-1 env | grep -i "METRICS\|PORT"
METRICS_BIND_ADDR=0.0.0.0
METRICS_ENABLED=true
METRICS_PORT=9092
TRACKING_PORT=3001

# (1) scrape BEFORE the driven click
$ docker exec apexmail-api-server-1 wget -S -qO- http://tracking:9092/metrics 2>&1 | head -20
# TYPE apexmail_tracking_click_unknown_token_total counter
apexmail_tracking_click_unknown_token_total 1

  HTTP/1.1 200 OK
  content-type: text/plain
  content-length: 106
  date: Thu, 08 Oct 2026 19:46:39 GMT
EXIT=0

# (2) drive a real unknown-token click through the live tracking service
$ TOKEN="verifier-b1-$(date +%s)-zzzzzzzzzzzzzzzzzzzzzzzz"
$ curl -s -o /dev/null -w 'HTTP_CODE=%{http_code}\n' "http://127.0.0.1:3001/c/$TOKEN"
HTTP_CODE=404

# (3) re-scrape → the counter moved
$ docker exec apexmail-api-server-1 wget -qO- http://tracking:9092/metrics
# TYPE apexmail_tracking_click_unknown_token_total counter
apexmail_tracking_click_unknown_token_total 2
EXIT=0
$ docker exec apexmail-api-server-1 wget -S -qO- http://tracking:9092/metrics 2>&1
# TYPE apexmail_tracking_click_unknown_token_total counter
apexmail_tracking_click_unknown_token_total 2
  HTTP/1.1 200 OK
  content-length: 106
$ docker exec apexmail-worker-1 wget -S -qO- http://tracking:9092/metrics 2>&1 | tail -6
  content-type: text/plain
  content-length: 106
  date: Thu, 08 Oct 2026 19:46:45 GMT
# TYPE apexmail_tracking_click_unknown_token_total counter
apexmail_tracking_click_unknown_token_total 2
```
Note: the counter was already registered at step 1 (value 1 — a prior probe in this wave had driven a
click), so the lazy-registration empty-body state was not observable without restarting the tracking
container mid-wave; the required sequence (200 scrape → live click → counter ≥1, here exactly +1) is
proven. The lazy registration itself is source-verified: the counter is created at request time via the
`metrics` facade (`tracking-service/src/routes/click.rs:113 metrics::counter!("apexmail_tracking_click_unknown_token_total")`),
so a fresh container has no series until the first refusal.

### B2 — DSR statutorily-overdue surface

```
$ docker exec apexmail-compliance-1 printenv COMPLIANCE_AUTH_TOKEN
dev-compliance-token-change-me
# without a tenant identity the route refuses with a NAMED 401 (method note)
$ python: GET http://compliance:3011/gdpr/stats -> 401 b'{"error":"a tenant identity is required: pass ?tenant_id= or the X-Tenant-Id header"}'
# with the tenant:
$ docker exec apexmail-api-server-1 sh -c "wget -qO- --content-on-error --header='Authorization: Bearer dev-compliance-token-change-me' 'http://compliance:3011/gdpr/stats?tenant_id=edx0ltwfgugh1gi2k3h8x5bgqe'"
{"data":{"completed":0,"expired":0,"failed":0,"overdue":1,"partial":2,"pending_manual_review":0,"pending_verification":0,"processing":0,"rejected":0,"tenant_id":"edx0ltwfgugh1gi2k3h8x5bgqe","total":2,"verified":0}}
SQL: SELECT id, tenant_id, status, statutory_due_at, extension_due_at, received_at FROM data_subject_requests WHERE tenant_id='edx0ltwfgugh1gi2k3h8x5bgqe' ORDER BY received_at;
 22346446-b4c7-4b57-a4bf-1fc0c0958532 | … | partial | 2026-10-06 12:20:47+00 |   | 2026-10-08 12:13:40+00
 7ef66d3e-cd06-45aa-97f7-ae9926d9ae4b | … | partial | 2026-11-08 12:18:18+00 |   | 2026-10-08 12:18:18+00

# fresh fixture tenant (26 chars), stats start at zero
TENANT=vfb21791488872  EMAIL=b2-overdue-1791488872@verify.test
$ wget -qO- … 'http://compliance:3011/gdpr/stats?tenant_id=vfb21791488872'
{"data":{…,"overdue":0,…,"total":0,"verified":0}}
$ wget -qO- --header='Content-Type: application/json' --post-data='{"tenant_id":"vfb21791488872","request_type":"access","email":"b2-overdue-1791488872@verify.test"}' http://compliance:3011/gdpr/submit
{"data":{"email":"b2-overdue-1791488872@verify.test","expires_at":"2026-11-07T19:47:52Z","id":"d85e6b39-ebab-42ad-a9c3-7e4511a0fea7","received_at":"2026-10-08T19:47:52Z","request_type":"access","status":"pending_verification","statutory_due_at":"2026-11-08T19:47:52Z","tenant_id":"vfb21791488872",…}}

# mark overdue past the statutory deadline (SQL, as the brief allows)
$ UPDATE data_subject_requests SET statutory_due_at = NOW() - interval '2 days' WHERE id='d85e6b39-…' RETURNING id, status, statutory_due_at;
 d85e6b39-ebab-42ad-a9c3-7e4511a0fea7 | pending_verification | 2026-10-06 19:47:55+00     (UPDATE 1)
$ GET /gdpr/stats?tenant_id=vfb21791488872
{"data":{…,"overdue":1,…,"pending_verification":1,"total":1,…}}          ← count INCREMENTED

# satisfy it (completed) → count DECREMENTS
$ UPDATE data_subject_requests SET status='completed', completed_at=NOW() WHERE id='d85e6b39-…' RETURNING id, status, completed_at;
 d85e6b39-ebab-42ad-a9c3-7e4511a0fea7 | completed | 2026-10-08 19:47:59+00     (UPDATE 1)
$ GET /gdpr/stats?tenant_id=vfb21791488872
{"data":{"completed":1,…,"overdue":0,…,"total":1,…}}                      ← count DECREMENTED

# the production caller also runs in the live container (5-minute tick)
$ docker logs --since 2026-10-08T19:48:00 apexmail-compliance-1 | grep -i "overdue\|SLA"
2026-10-08T19:49:33.179155Z WARN compliance_server: GDPR DSR(s) past the statutory response deadline — SLA breach open overdue=1
(earlier ticks at 19:39:36 and 19:44:34 logged the same warn)
```
Left behind: tenant `vfb21791488872` with 2 DSR rows (1 completed, 1 expired — see B3), disclosed fixtures.

### B3 — DSR / GDPR one-shot sweep CLI (finding) + the live sweep that exists

```
$ ls services/mail-server/crates/compliance/src/main.rs
ls: services/mail-server/crates/compliance/src/main.rs: No such file or directory   (exit 1)
$ grep -n "struct Cli" -A 12 services/mail-server/crates/compliance/src/bin/server.rs
65:struct Cli {
66-    /// Override port (default from COMPLIANCE_PORT or 3011)
67-    #[arg(short, long)]
68-    port: Option<u16>,
69-}
$ grep -rn "sweep_only\|sweep-once\|sweep_once\|--dsr\|dsr-sweep" services/mail-server/crates/compliance/src/bin/server.rs
services/mail-server/crates/compliance/src/bin/server.rs:355:  match outbox_flusher.flush_once().await {    (an internal call, not a CLI flag)
$ docker exec apexmail-compliance-1 /usr/local/bin/compliance-server --help
Usage: compliance-server [OPTIONS]

Options:
  -p, --port <PORT>  Override port (default from COMPLIANCE_PORT or 3011)
  -h, --help         Print help
```

The live sweep that DOES run (container cron) processing an overdue record end-to-end:

```
# before: a second DSR (id 4499277d-27ea-44e4-9350-b07b72d01f66) backdated past both clocks
$ UPDATE data_subject_requests SET expires_at = NOW() - interval '1 hour', statutory_due_at = NOW() - interval '2 days' WHERE id='4499277d-…' RETURNING id, status, expires_at, statutory_due_at;
 4499277d-27ea-44e4-9350-b07b72d01f66 | pending_verification | 2026-10-08 18:48:28+00 | 2026-10-06 19:48:28+00
$ GET /gdpr/stats?tenant_id=vfb21791488872
{"data":{"completed":1,…,"overdue":1,"pending_verification":1,"total":2,…}}
# the container's 5-minute expiry tick fired:
$ docker logs --since 2026-10-08T19:48:00 apexmail-compliance-1 | grep -i "expired\|overdue"
2026-10-08T19:49:33.176487Z INFO compliance::gdpr_automation: Expired overdue GDPR requests count=1
2026-10-08T19:49:33.176495Z INFO compliance_server: Expired overdue GDPR requests count=1
2026-10-08T19:49:33.179155Z WARN compliance_server: GDPR DSR(s) past the statutory response deadline — SLA breach open overdue=1
# after:
$ SELECT id, status, expires_at FROM data_subject_requests WHERE id='4499277d-…';
 4499277d-27ea-44e4-9350-b07b72d01f66 | expired | 2026-10-08 18:48:28+00
$ GET /gdpr/stats?tenant_id=vfb21791488872
{"data":{"completed":1,"expired":1,…,"overdue":0,…,"total":2,…}}
```

### B4 — alert rules CRUD + evaluation

```
TENANT=vfb4155f681dc8ad49c3fd70f2   (SQL-fixture tenant, disclosed)
$ POST /v1/admin/alerts/rules  {"tenantId":…,"name":"verify-b4-crud","metricType":"emails","thresholdPercent":50,"notificationChannel":"email","severity":"info"}
HTTP=201
{"id":"d6001251-713e-4434-8c79-bc77b39c809e","tenantId":"vfb4155f681dc8ad49c3fd70f2","name":"verify-b4-crud","metricType":"emails","thresholdPercent":50,"notificationChannel":"email","severity":"info","enabled":true,"lastTriggeredAt":null,"createdAt":"2026-10-08T19:51:03.088898+00:00"}
$ POST … {"severity":"bogus"}
HTTP=400
{"error":{"code":"BAD_REQUEST","message":"Unsupported severity \"bogus\"; expected one of info, warning, critical.",…}}
$ GET /v1/admin/alerts/rules?tenantId=…   → HTTP=200, both rules listed
$ GET /v1/admin/alerts/rules/d6001251-…   → HTTP=200 (single rule)
$ PATCH /v1/admin/alerts/rules/d6001251-… {"thresholdPercent":90,"severity":"critical"}
HTTP=200 … "thresholdPercent":90,…"severity":"critical"…
SQL: SELECT id,name,threshold_percent,severity,enabled FROM usage_alert_configs WHERE tenant_id='vfb4…';
 6de49138-b0c9-4f38-aa8b-b8fc286d872b | verify-b4-emails |                 1 | warning  | t
 d6001251-713e-4434-8c79-bc77b39c809e | verify-b4-crud   |                90 | critical | t
$ DELETE /v1/admin/alerts/rules/d6001251-…
HTTP=200 {"deleted":true,"id":"d6001251-713e-4434-8c79-bc77b39c809e"}
SQL: only verify-b4-emails remains.

# evaluation: a threshold-1 rule + forced usage; the RUNNING worker sweep consumes it
$ INSERT INTO metering_events (tenant_id,event_type,quantity,metadata) VALUES ('vfb4…','emails_sent',1000,'{"probe":"verify-final-money-b4"}') RETURNING id,…;
 2d9a3051-4205-4b24-96be-1837e96ddb49 | vfb4155f681dc8ad49c3fd70f2 | emails_sent | 1000
$ docker logs --since 2026-10-08T19:55:00 apexmail-worker-1 | grep -i "usage alert"
{"timestamp":"2026-10-08T19:55:17.990087Z","level":"INFO","fields":{"message":"processed usage alerts","tenants_checked":4,"alerts_triggered":1},"target":"billing_service::maintenance"}
$ SELECT id, alert_type, severity, component, source, fingerprint, message, created_at FROM system_alerts WHERE tenant_id='vfb4…';
 d23b8a2d-68c7-4ac0-8c01-f032d6058e6e | usage_alert | warning | usage | usage_alert | 6de49138-b0c9-4f38-aa8b-b8fc286d872b | Alert rule "verify-b4-emails" fired: emails at 3% of the plan limit (1000 / 30000). | 2026-10-08 19:55:17.987055+00
$ SELECT name, last_triggered_at FROM usage_alert_configs WHERE tenant_id='vfb4…';
 verify-b4-emails | 2026-10-08 19:55:17.989079+00
```
Left behind: tenant `vfb4155f681dc8ad49c3fd70f2` + rule `verify-b4-emails` + one fired incident, disclosed.

### B5 — metrics surfaces inventory

```
$ curl -s http://127.0.0.1:9090/metrics -o /tmp/api_metrics.txt -w 'HTTP=%{http_code}\n'   → HTTP=200
$ wc -l /tmp/api_metrics.txt → 714 ; grep -vc '^#' → 704 ; grep -c '_bucket' → 570
$ grep '^# TYPE' /tmp/api_metrics.txt | sort
# TYPE apexmail_http_request_duration_seconds histogram
# TYPE apexmail_http_requests_in_flight gauge
# TYPE apexmail_http_requests_total counter
# TYPE ddos_requests_total counter
# TYPE redis_evicted_keys_total counter
# TYPE redis_eviction_rate_per_minute gauge
# TYPE redis_maxmemory_bytes gauge
# TYPE redis_memory_utilization_ratio gauge
# TYPE redis_used_memory_bytes gauge
$ grep '^ddos' /tmp/api_metrics.txt
ddos_requests_total{decision="evaluated",layer="all"} 129
ddos_requests_total{decision="allowed",layer="ok"} 129
$ grep '^redis' /tmp/api_metrics.txt
redis_evicted_keys_total 0
redis_used_memory_bytes 2672920
redis_eviction_rate_per_minute 0
redis_maxmemory_bytes 268435456
redis_memory_utilization_ratio 0.00995740294456482
```
(The api-server was recreated twice later in this lane for B6/B8, so the registry reset; the fresh
post-recreate scrape still carries the same 9 families — 45 lines / 26 series / 15 buckets — saved as
`evidence-final-money/api-server-metrics.txt`; the long-lived instance's full-state scrape is
`evidence-final-money/api-server-metrics-full-state.txt`.)

```
$ docker exec apexmail-enterprise-1 printenv METRICS_TOKEN
dev-enterprise-metrics-token-change-me
$ curl -s -o /dev/null -w 'no-token=%{http_code}\n' http://127.0.0.1:3002/metrics            → no-token=401
$ curl -s -o /dev/null -w 'wrong-token=%{http_code}\n' -H 'Authorization: Bearer wrong' …    → wrong-token=401
$ curl -s -H "Authorization: Bearer $(cat deploy/monitoring/enterprise_metrics_token)" http://127.0.0.1:3002/metrics
# TYPE apexmail_enterprise_info gauge
apexmail_enterprise_info 1
                       (HTTP=200; committed credentials file == live token)

# in-network scrape of every declared target (python:3.12-alpine on apexmail_apexmail_backend):
api-server:9090/metrics       -> 200 series_lines=43  first=apexmail_http_requests_total{method="POST",path_pattern="/web/auth/login",status="303"} 5
tracking:9092/metrics         -> 200 series_lines=1   first=apexmail_tracking_click_unknown_token_total 2
enterprise:3008/metrics       -> 200 series_lines=1   first=apexmail_enterprise_info 1                      (with bearer)
mta:9090/metrics              -> 200 series_lines=16  first=mta_inbound_dsn_deferred 1819
worker:9093/metrics           -> 200 series_lines=24  first=apexmail_metering_events_pending_count 0
outbound-mta:8093/metrics     -> 200 series_lines=12  first=apexmail_outbound_mta_queue_pending 0
observability:4400/metrics    -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
postgres-exporter:9187/metrics-> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
redis-exporter:9121/metrics   -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
clickhouse-exporter:9116/…    -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
node-exporter:9100/metrics    -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
synthetic-monitor:9128/…      -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
blackbox-exporter:9115/…      -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
alertmanager:9093/-/ready     -> ERROR URLError: <urlopen error [Errno -2] Name does not resolve>
# (the second group is compose `profiles: [monitoring]` — including prometheus itself — see F2)

# the config lines behind the specific re-verified targets
deploy/prometheus.yml:
  - job_name: 'apexmail-tracking'  static_configs: targets: ['tracking:9092']  metrics_path: '/metrics'
  - job_name: 'apexmail-enterprise' … targets: ['enterprise:3008'] … authorization: { type: Bearer,
      credentials_file: /etc/prometheus/monitoring/enterprise_metrics_token }
```

### B6 — dev SNS webhook, signed / unsigned / wrong ARN

```
# fail-before (live container, dev key unset)
$ docker exec apexmail-api-server-1 sh -c 'printenv SNS_DEV_SIGNING_KEY_PEM | wc -c'  → 1
$ python3 /tmp/sns_probe.py "b6-ses-…@ses.local" "b6-failbefore@dogfood.test" complaint
HTTP=400 body='{"error":{"code":"VALIDATION_ERROR","details":["SigningCertURL must reference an AWS SNS certificate"],"message":"validation failed",…}}'

# fix: documented dev anchor in .env (gitignored) + recreate
$ openssl genrsa -out /tmp/sns_dev_key.pem 2048 ; openssl rsa -in /tmp/sns_dev_key.pem -pubout | awk '{printf "%s\\n",$0}'  → SNS_DEV_SIGNING_KEY_PEM in .env
$ docker compose up -d api-server
$ docker exec apexmail-api-server-1 sh -c 'printenv SNS_ALLOWED_TOPIC_ARNS; printenv SNS_DEV_SIGNING_KEY_PEM | head -c 27'
arn:aws:sns:eu-central-1:000000000000:apexmail-dev-ses-events
-----BEGIN PUBLIC KEY-----

# attributable fixture row (the SES-accepted message id SES SMTP would have stored)
$ INSERT INTO email_queue (from_address,to_addresses,"to",subject,status,tenant_id,smtp_message_id,sent_at,message_category)
  VALUES ('bounce@apexmail.ee',ARRAY['b6-recipient@dogfood.test'],'b6-recipient@dogfood.test','B6 SNS fixture','sent','vfb4…','b6-ses-vfb6-1791489254',NOW(),'marketing') RETURNING id,…;
 7b3a0709-858d-4c74-ac5e-fff22c49b71d | vfb4155f681dc8ad49c3fd70f2 | b6-ses-vfb6-1791489254 | b6-recipient@dogfood.test | sent

# SIGNED complaint (RSA-SHA256 over the canonical SNS string-to-sign, SignatureVersion=2)
$ python3 /tmp/sns_probe.py "b6-ses-vfb6-1791489254" "b6-recipient@dogfood.test" complaint
HTTP=200 body=''
$ SELECT id,tenant_id,email,reason,source,created_at FROM suppressions WHERE tenant_id='vfb4…';
 sup_sx7girl5fteotp4vq19crj | vfb4155f681dc8ad49c3fd70f2 | b6-recipient@dogfood.test | ses_complaint:abuse | ses | 2026-10-08 19:54:14.692854+00
$ SELECT id,event_type,recipient FROM events WHERE tenant_id='vfb4…';
 evt_8b0479a2c59085c4efd5270aa5cfa76f | complained | b6-recipient@dogfood.test

# UNSIGNED
$ python3 /tmp/sns_probe.py "b6-ses-vfb6-1791489254" "b6-unsigned@dogfood.test" unsigned "unsigned-arm-…"
HTTP=403 body='{"error":{"code":"FORBIDDEN","message":"Invalid SNS signature",…}}'
# WRONG ARN (signed, foreign TopicArn)
$ python3 /tmp/sns_probe.py "b6-ses-vfb6-1791489254" "b6-badarn@dogfood.test" badarn "badarn-arm-…"
HTTP=403 body='{"error":{"code":"FORBIDDEN","message":"Unknown SNS topic ARN",…}}'
# nothing landed:
$ SELECT count(*) FROM suppressions WHERE tenant_id='vfb4…'   → 1
$ SELECT count(*) FROM events WHERE tenant_id='vfb4…'          → 1
$ SELECT email FROM suppressions WHERE email IN ('b6-unsigned@…','b6-badarn@…') → (0 rows)
```
Harness: `evidence-final-money/b6-sns-probe.py` (signer/POSTer; `/tmp/sns_dev_key.pem` private half kept
out of the repo).

### B7 — A/B experiment assignment

Harness (live product endpoints; SQL fixtures for the audience — the committed, previously-run probe
harness):
```
$ python3 tools/dogfood-live-capabilities.py --only p2 --run-id vfb7
VERDICT PASS  P2.1 experiment campaign created  campaign=bb84221f-c54d-44e3-8df2-f6f7ce32417e
VERDICT PASS  P2.2 send accepted  status=200
VERDICT PASS  P2.3 every recipient phased with a persisted bucket  test=104 holdout=96 total=200
VERDICT PASS  P2.4 buckets match the md5(campaign:contact) formula exactly  mismatches=0 test_pct=52.0%
VERDICT PASS  P2.5 both arms populated  arms=['0', '1']
VERDICT PASS  P2.6 holdout receives nothing at split  holdout queue rows=0 holdout message refs=0
VERDICT PASS  P2.7 real worker sent the test sample  sent=104
VERDICT PASS  P2.8 GET experiment returns per-arm results  arms=[{arm 0: trials 50}, {arm 1: trials 54}]
VERDICT PASS  P2.9 opens from the real pixel landed in events  forced=50 distinct_open_events=49
CMD  wait for the 5-minute test windows of BOTH campaigns to elapse
Traceback (most recent call last):
  … RuntimeError: psql failed: psql: error: connection to server at "127.0.0.1", port 5432 failed:
     FATAL:  the database system is in recovery mode
```
(That abort is environment incident E1; the assignment evidence B7 needs was already captured. Post-
recovery addendum, `python3 /tmp/b7_addendum.py`):
```
== split (phase x arm) ==
test|0|50 ; test|1|54 ; winner|0|96        (holdout auto-promoted to arm 0 after the window closed)
200|200|0                                  (total | persisted ab_bucket | unphased)
== determinism recompute (md5 formula vs stored ab_bucket) ==
200|0                                      (total | mismatches)
== row-set fingerprint before second assignment run ==  0eb13c49540a4b5b0985e4be31c50a07
== second assignment call (AB_SPLIT_SQL re-run: only un-phased rows are touched) ==
second-run rows assigned: 'UPDATE 0'
fingerprint_after:  0eb13c49540a4b5b0985e4be31c50a07
== second call on the read surface: GET /experiment twice ==
call1: 200 {"test":104,"holdout":0,"winner":96,"unassigned":0,"total":200} arms [{arm0 trials 90 successes 40 rate 0.4444},{arm1 trials 64 successes 10 rate 0.15625}]
call2: 200 {"test":104,"holdout":0,"winner":96,"unassigned":0,"total":200} arms [identical]
```
Verifier note: the addendum's own final string assertion printed `IDEMPOTENT: FAIL` because it compared
psql's output to `""` while psql emitted the command tag `UPDATE 0`; the substantive checks — 0 rows
re-assigned and an identical row-set fingerprint — are the PASS. All rows persist in
`campaign_recipients` (`ab_bucket` = migration 248's column) for campaign
`bb84221f-c54d-44e3-8df2-f6f7ce32417e`.

### B8 — custom tracking domains

```
CREATE 201 {"id":"0534b5bb-…","domain":"track.vfb8-vfb8-a.dogfood.test","status":"pending",
            "status_reason":"publish the CNAME record to track.apexmail.ee, then verify","cname_target":"track.apexmail.ee"}
LIST   200 [ … the same row … ]
GET /dns-records 200 {"domain":"track.vfb8-vfb8-a.dogfood.test","records":[{"record_type":"CNAME","hostname":"track.vfb8-vfb8-a.dogfood.test","value":"track.apexmail.ee"}]}
POST /verify (before DNS) 503 {"error":{"code":"SERVICE_UNAVAILABLE","message":"DNS lookup for `track.vfb8-…` is temporarily unavailable; the tracking domain state is unchanged — retry shortly"}}
# publish the customer CNAME in the api-server resolver view (extra_hosts recreate, no image build):
POST /verify 200 {"…","status":"verified","verified_at":"2026-10-08T20:00:…","cname_target":"track.apexmail.ee"}
# click path on the custom host (curl, no redirect follow):
$ curl -s -o /dev/null -D - -H 'Host: track.vfb8-vfb8-a.dogfood.test' http://127.0.0.1:3001/c/<owner-token>
HTTP/1.1 302 Found
location: https://vfb8-vfb8-a.dogfood.test/b8-landing?i=1
# foreign tenant's token on the same host:
CLICK foreign … -> 403 '<!DOCTYPE html>…<title>Tracking doma…'      (refusal page)
# owner pixel on the custom host:
PIXEL owner on track.vfb8-… -> 200
# DELETE via API → serving stops immediately (no cache):
DELETE 204 "" ; PIXEL after delete -> 400 refusal page
```
(An earlier client-side line `CLICK owner … -> 0` was my Python client auto-following the 302 into the
non-resolvable customer domain; the no-follow curl above is the proof of the 302+Location.)

### B9 — send-time optimization weekday

```
$ python3 /tmp/b9_probe.py
[tallinn-wed] campaign create -> 201 campaign=3b8e1425-…   send -> 200 status=sending
[tallinn-wed] event_utc=2026-10-07T06:00:00+00:00 sql=2026-10-07 06:00:00| isodow=3| dow=3
[tallinn-wed] event_local=2026-10-07T09:00:00+03:00 (weekday=Wednesday)
[tallinn-wed] scheduled_at=2026-10-14T06:00:00Z local=2026-10-14T09:00:00+00:00 weekday=Wednesday hour=9
[tallinn-wed] OLD DOW-shifted bucket would name Thursday (index 3) vs correct Wednesday (index 2)
[tallinn-wed] VERDICT PASS: expected Wednesday 9:00 local, got Wednesday 9:00 local
[newyork-mon] campaign create -> 201 campaign=ee76a035-…   send -> 200 status=sending
[newyork-mon] event_utc=2026-10-05T14:00:00+00:00 sql=2026-10-05 14:00:00| isodow=1| dow=1
[newyork-mon] event_local=2026-10-05T10:00:00-04:00 (weekday=Monday)
[newyork-mon] scheduled_at=2026-10-12T14:00:00Z local=2026-10-12T10:00:00+00:00 weekday=Monday hour=10
[newyork-mon] OLD DOW-shifted bucket would name Tuesday (index 1) vs correct Monday (index 0)
[newyork-mon] VERDICT PASS: expected Monday 10:00 local, got Monday 10:00 local
```
Arithmetic shown: the engagement timestamps are shifted by the campaign `settings.timezone` offset
(+180 / −240) before the `EXTRACT(ISODOW …)` bucket (0=Monday = `DAY_PRIORS`), and
`next_occurrence_utc` converts the local wall clock back to UTC — both arms land on the events' local
weekday+hour, strictly future. The DOW-based (0=Sunday) bucket the wave-G fix replaced would have named
Thursday/Tuesday respectively (the fail-before off-by-one shape).

## Fixtures/state left behind (all disclosed)

* B2/B4/B6 built on SQL-fixture tenant `vfb21791488872` and `vfb4155f681dc8ad49c3fd70f2`; left rows:
  2 DSRs (1 completed, 1 expired), 1 alert rule + 1 `system_alerts` incident, 1 `email_queue` fixture row,
  1 suppression (`ses_complaint:abuse`), 1 `complained` event, 1 `metering_events` row.
* B7 harness tenants `kdrbywwep9tr462oflky4isckq` (+ CPD tenant) with the A/B campaign
  `bb84221f-c54d-44e3-8df2-f6f7ce32417e` (200 recipients) and the small campaign.
* B8 tenants `zl5mqtpstgojvf83kwfz0mwaag`/…, tracking-domain rows deleted at the end (the last one by the
  probe's own cleanup); B9 tenant `657gkd0cr524pfqesjc5pxv5ki` with 2 scheduled campaigns.
* `.env` (gitignored) gained `SNS_DEV_SIGNING_KEY_PEM="<dev public key>"` per deploy/DEPLOYMENT.md;
  `/tmp/sns_dev_key.pem` holds the private half outside the repo. No tracked file was modified by this
  lane. No commit made.

## Orchestrator summary (one paragraph)

Lane B executed all nine probes live with zero skips: **B1 PASS** (tracking `tracking:9092` in-network
scrape 200 and `apexmail_tracking_click_unknown_token_total` moved 1→2 on a real unknown-token click),
**B2 PASS** (`/gdpr/stats` `overdue` moved 0→1→0 with a submitted+backdated+then-completed DSR, and the
live container logs the SLA breach), **B3 PASS with finding** (the brief's compliance one-shot sweep CLI
does not exist — no `crates/compliance/src/main.rs`, `--help` offers only `--port`; the container's
5-minute expiry sweep was proven to process an overdue record with row-state + log evidence),
**B4 PASS** (alert-rules CRUD 201/200/200/200/200, CHECK-violating severity 400 not 500, and the running
worker sweep fired the rule into `system_alerts` with the rule's name/severity/fingerprint),
**B5 PASS** (api-server 9 documented families incl. 570 `_bucket` series on the long-lived instance,
enterprise bearer 200 with hostrouted series, 2 ddos + 5 redis series, all app-stack Prometheus targets
200 in-network; the remaining declared targets are `monitoring`-profile-gated — DNS-absent, no
404/refusal), **B6 DEFECT FOUND AND FIXED** (the dev stack had `SNS_DEV_SIGNING_KEY_PEM` empty so the
documented locally-signed SNS path was refused 400 — fail-before captured; configured the documented dev
RSA anchor in the gitignored `.env`, recreated api-server, and re-proved: signed complaint 200 with the
suppression+complained rows landing, unsigned 403, wrong ARN 403, nothing landing on the negatives),
**B7 PASS** (200 recipients all assigned a persisted `ab_bucket`, md5 determinism 0 mismatches, 104/96
split at the configured 0.5, second assignment run `UPDATE 0` with an identical fingerprint and two
identical `GET /experiment` calls; the harness abort at P2.10 was a Postgres checkpointer SIGKILL
environment incident, recovered, with B7's evidence taken before it and completed after),
**B8 PASS** (tracking-domain create/list/dns-records/verify-before-503/verify-200/delete-204, owner click
on the custom host 302 to the original URL, foreign token 403, delete stops serving), **B9 PASS** (events
Wednesday 09:00 Tallinn local → scheduled Wednesday 09:00 local; Monday 10:00 New York local → Monday
10:00 local, versus the old DOW bucket's Thursday/Tuesday). Defects: one fixed (B6 dev config, with
fail-before/fail-after), one filed P3 (B3 missing one-shot CLI), one environment incident (Postgres
SIGKILL/recovery, not a product defect), one scope note (B5 monitoring profile not started). Report:
`docs/audit/dogfood-2026-10-06/verify-final-money.md`; raw files under
`docs/audit/dogfood-2026-10-06/evidence-final-money/`. No commit; no KiwiCaptcha surface touched.
