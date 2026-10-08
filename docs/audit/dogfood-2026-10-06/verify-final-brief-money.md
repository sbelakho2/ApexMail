# Final verification brief — Lane B: money, tracking, compliance, ops surfaces

You are an extremely rigorous adversarial verifier. **ZERO SKIPS, EVER.** Every numbered probe below
must be EXECUTED and EVIDENCED with the exact command and its observed output/exit code. An
unreachable or failing probe is a FINDING with the exact command + exact error text — never a
silent skip, never "not applicable", never a plausible assertion from reading source alone (source
reading is *how you build the probe*, not the proof).

## Environment (live stack, already running)

- Repo: `/Users/sabelakhoua/IdeaProjects/ApexMail`. Docker context `colima-local` (on socket errors:
  `docker context use colima-local`).
- api-server `http://127.0.0.1:8080` (host routing: default = web app, `-H 'Host: admin.localhost'` =
  control plane). Tracking `http://127.0.0.1:3001`; tracking metrics in-network at `tracking:9092`.
- MTA SMTP 5525 (STARTTLS 5587), Mailpit HTTP 8025 / SMTP 1025, IMAPS 993.
- ClickHouse `127.0.0.1:8123` (user `apexmail`, password in `secrets/clickhouse_password.txt`;
  `default` is loopback-only inside the container and a host client cannot use it — read the secret
  file, do not guess). Postgres `127.0.0.1:5432` user `apexmail`, password per
  `secrets/postgres_password.txt` (`bebc8cefdc096e5247f8864e5c0edf78099df23058133321`), db
  `apexmail`. Dev Redis 6379; enterprise 3002 (metrics 3008, bearer `METRICS_TOKEN` — find it in
  `docker exec apexmail-enterprise-1 env | grep METRICS`).
- Read prior reports for recipes: `docs/audit/dogfood-2026-10-06/dogfood-live-money-tracking.md` and
  `dogfood-live-capabilities.md` (committed) — they contain working request shapes, auth recipes and
  the sales API quirk (`x-tenant-id` header + system tenant).

## Lane probes (all MUST be executed)

**B1 — tracking metrics in-network scrape (the H fix).**
The compose wiring: `METRICS_PORT: 9092`, `METRICS_BIND_ADDR: ${TRACKING_METRICS_BIND_ADDR:-0.0.0.0}`.
Facts already established (re-verify, do not trust): the exporter registers counters LAZILY, so a
fresh container scrapes an EMPTY body until the first event. Sequence to prove: (1) scrape
`docker exec apexmail-api-server-1 wget -qO- http://tracking:9092/metrics` → HTTP 200 (may be empty
body); (2) drive a real unknown-token click through the live tracking service
(`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/c/<made-up-token>`); (3) re-scrape →
must contain `apexmail_tracking_click_unknown_token_total` with value ≥ 1. Record every command +
raw output. If the counter does not appear, that is a DEFECT (find the wiring bug, fix it, rebuild
tracking, re-prove).

**B2 — DSR statutorily-overdue surface.**
`GET /gdpr/stats` (or the actual DSR stats route — discover it; the compliance service also has a
`/gdpr/*` API) must include the statutorily-overdue count (`count_statutorily_overdue()`). Prove it
moves with data: insert/mark a DSR request overdue past its statutory deadline via the API/SQL,
re-read stats, see the count increment; then satisfy it and see it decrement. Evidence: SQL + exact
requests + JSON bodies.

**B3 — DSR / GDPR one-shot sweep CLI.**
Find the compliance binary's sweep/one-shot CLI (see `crates/compliance/src/main.rs` and the wave-G
report `docs/audit/dogfood-2026-10-06/fix-wave-g.md` / alert-rules fixes for exact flags). Run it
against the live DB inside its container (or with the same env), and prove it processes an overdue
record (before/after row states + the CLI's log lines). If the flag/CLI does not exist as reported,
that is a finding.

**B4 — alert rules management (the former 501).**
`/alerts/rules` CRUD were implemented (migration 246 added name/severity + CHECK). Prove live:
create → list → update → delete via the API (exact requests), with a CHECK-violating severity
rejected 4xx (not 500). Then prove an evaluation path consumes the rule (trigger the metric
condition, observe the alert/notification row or log).

**B5 — metrics surfaces inventory (all scrapeable).**
- api-server `:9090/metrics` → count series (expect the documented set incl. `_bucket` histograms).
- enterprise `:3008/metrics` with the bearer token → ≥1 hostrouted series.
- ddos series (≥2) and redis series (≥5) as previously recorded; name them.
- `deploy/prometheus.yml`: every declared scrape target resolves — specifically `tracking:9092`
  must now be a truthful target (that was the H report's fix). Evidence: raw scrapes + the
  prometheus config lines.
- If any declared target 404s/refuses in-network, that is a DEFECT: fix the wiring, rebuild,
  re-prove.

**B6 — dev SNS webhook.**
Compose sets `SNS_ALLOWED_TOPIC_ARNS` (local ARN) + `SNS_DEV_SIGNING_KEY_PEM` for the dev stack.
Post a correctly-signed SNS notification to the bounce/complaint webhook → 200 and the event lands
(verify in DB/ClickHouse). Post an UNSIGNED or wrong-ARN notification → 4xx, nothing lands.
Evidence: exact curl bodies + DB rows.

**B7 — A/B experiment assignment (migration 248).**
Probe the experiment assignment surface end-to-end: an assignment request for a contact gets a
deterministic variant, persists in the assignment table, and a second call returns the SAME variant
(determinism), while the split across many contacts approximates the configured ratio. Evidence:
exact requests + SQL rows + the computed split.

**B8 — custom tracking domains (migration 247).**
CRUD a custom tracking domain via the API, then verify the tracking link renderer/click path uses it
(exact request that shows the domain in the generated link/host handling). Evidence: requests +
rendered output.

**B9 — send-time optimization weekday bug (wave G).**
The weekday-computation bug was fixed. Probe the send-time optimization endpoint with contacts in
different timezones/weekdays and prove the computed send time lands on the correct local weekday
(fail-before shape: weekday off-by-one). Evidence: request + computed time + the weekday arithmetic
shown.

## Fix protocol (when you find a real defect)

1. Capture **fail-before** evidence: exact command, exact wrong output.
2. FIX the code properly in the repo — real capability, no honest-error cop-out, no docs-removal.
3. `cargo fmt` on touched files; `cargo check -p <crate>` compiles.
4. If the live container must see the fix: `docker compose build <svc> && docker compose up -d <svc>`
   (context `colima-local`), then capture **fail-after** live evidence.
5. Do NOT `git commit` — leave the tree with your edits; the orchestrator commits.

**HARD CONSTRAINT: KiwiCaptcha is a separate project/repo. Do NOT touch any KiwiCaptcha surface
(packages/kiwicaptcha*, vendored copies, its tests/suites). Consume the latest version only.**

## Deliverable

Write `docs/audit/dogfood-2026-10-06/verify-final-money.md`:
- Results table: probe id | what was probed | exact command (inline) | observed output/verdict |
  evidence location.
- **ZERO SKIPS appendix**: every probe id B1..B9 with the literal command(s) run and literal output
  (trimmed but verbatim-critical parts). Anything not executed appears here with the exact error —
  that is a finding, not an omission.
- "Defects found" section with fail-before/fail-after pairs for anything fixed.
Final message to the orchestrator: one paragraph — probes run (n), passed, defects found, defects
fixed, anything left failing with its exact error.
