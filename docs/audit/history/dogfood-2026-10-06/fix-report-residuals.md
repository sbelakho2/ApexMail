# Fix report — residual fixes filed by the coverage-gap wave

Agent: `fix-residuals`. Date: 2026-10-07. Base revision: `0557e55d` +
working tree (sibling agents' changes present). Deliverable of
`docs/audit/dogfood-2026-10-06/brief-fix-residuals.md`.

**Ownership.** Only the files the brief names were edited:

| Item | Files edited |
|---|---|
| 1 | `apps/ai/training/new_customer_profiles.py`, `tools/validate_pricing_drift.py` (the check's home: "wire the check") |
| 2 | `deploy/grafana/dashboards/api-performance.json` |
| 3 | `docs/operations/monitoring.md` |
| 4 | `tools/ui_flash_extract.py` |
| 5 | `tools/contrast-audit/crop.mjs` |
| "Also" group | `tools/contrast-audit/gen-summary.py`, `deploy/grafana/dashboards/{database-performance,smtp-performance}.json`, `deploy/monitoring/dashboards/{api-server-overview,slo-compliance}.json` |

Not touched: `crates/ui-foundation/**`, `crates/api-server/src/routes/{ai_chat,web}.rs`,
`crates/worker-processors/src/reply_handler/**`, `crates/ai-service/**`,
`docs/eval/**`, `tools/{bots_perf_budget,bots_disclosure_suite}.py`.
No deploy, no docker/compose actions.

## Status table

| Item | Status | One-line evidence |
|---|---|---|
| 1 training profiles | **FIXED** | 19/19 drifts fixed; check runs in the DEFAULT gate with a 68-mutation self-test; `validate_pipeline.py` 66/66 green |
| 2 api-performance.json | **FIXED** | `endpoint` → `path_pattern` in query + groupBy; all job labels valid; can-fail probe fails on HEAD |
| 3 monitoring.md | **FIXED** | process_*/fictional tables replaced with shipped names; doc-check fails on HEAD (16 findings), passes now |
| 4 ui_flash_extract.py | **FIXED** | masking-based `production_split` + `--self-test`; HEAD loses the `use`/mangles a string on the fixture, new keeps 628/628 chars; flash + form gates green |
| 5 crop.mjs | **FIXED** | `fileURLToPath`; space-path probe: HEAD `ERR_HTTP_RESPONSE_CODE_FAILURE`, new saves the crop; `gate.sh` PASS |
| group: contrast support lib | **READ + VERDICTS** | `png.mjs` clean (decode proof), `gen-summary.py` clean after removing a duplicate log line, `crop.mjs` fixed |
| group: remaining dashboards | **READ + 9 dead refs + 1 dead legend FIXED** | screen: HEAD 9 dead `apexmail_*` refs, now 0; 6 dead panels + 1 legend in 4 files retargeted |

---

## Item 1 · AI-training profiles carry pre-2026-09-08 prices/limits — FIXED

Files: `apps/ai/training/new_customer_profiles.py`,
`tools/validate_pricing_drift.py`.

**Where the opt-in mode lives.** `tools/validate_pricing_drift.py`
(`validate_training_profiles`, gated by `--check-training-profiles` in `main`).

**Before (reproduced).**

```
$ python3 tools/validate_pricing_drift.py --check-training-profiles; echo $?
training profile free_hitting_limits_v2 (Free) email_limit drift: expected '3,000', got '30,000'
training profile starter_healthy_v2 (Developer) plan_price drift: expected '29', got '25'
... (19 drift lines: 2 Free limits, 3 Developer prices, 3 Pro prices,
     3 Growth prices, 3 Business prices, 3 Enterprise prices) ...
1
```

**Fix.**

* `EXTENDED_PROFILES` now states the canonical catalog facts. Values fixed
  (source of truth `services/mail-server/crates/platform-catalog/src/lib.rs`
  `PLANS`; `billing-service/src/plans.rs` seeds and delegates to it):
  * Free `email_limit` 30,000 → **3,000**, `api_call_limit` 300,000 → **30,000**
    (both profiles); the Free launch allowance stays documented in the module
    docstring (3,000/mo + one-time 30,000 in the first 30 days).
  * Free profile `api_calls` 45,000 → **28,500** and `open_issues`
    "285/30,000 (95% used)" → "2,850/3,000 (95% used)" so the scenario is
    self-consistent with the canonical cap (an account with no overage cannot
    have used 45,000 of a 30,000 quota; the old line's percentage was also
    wrong under both catalogs).
  * Developer `plan_price` 25 → **29** (×3); Pro 65 → **89** + `team_limit`
    5 → **10**; Growth 150 → **229** + `team_limit` 10 → **25**; Business
    350 → **699** + `team_limit` 25 → **50**; Enterprise 3000 → **1750**
    (×3). `team_limit`s were stale limits the old checker never read; the
    checker now pins them.
* The check is wired into the **default** invocation (same gate CI runs at
  `ci/stages/validate.sh:676` and `scripts/consistency-test.sh:98`); it
  compares every field a profile states (`plan_price`, `email_limit`,
  `api_call_limit`, `team_limit`, with `-1` ⇒ `Unlimited`). The old flag is
  retained as a no-op for compatibility.
* The check is self-proving: `training_profiles_self_test` mutates each field
  of each profile on every invocation and requires exact detection
  (68 mutations across 17 profiles).

**Can-fail proof (mutation on the live file, then restored).**

```
# mutate Developer price 29→25 and Growth team_limit 25→10 in place:
$ python3 tools/validate_pricing_drift.py; echo $?
training profile starter_healthy_v2 (Developer) plan_price drift: expected '29', got '25'
training profile growth_bounce_spike_v2 (Growth) team_limit drift: expected '25', got '10'
1
$ cp /tmp/profiles-ok.py apps/ai/training/new_customer_profiles.py
$ python3 tools/validate_pricing_drift.py && echo OK
pricing drift validation passed
OK
```

**Post-fix state.**

```
$ python3 tools/validate_pricing_drift.py; echo $?                 # exit 0
pricing drift validation passed
$ python3 tools/validate_pricing_drift.py --self-test; echo $?     # exit 0
mirror self-test: Free emails=30_000 mutation detected by 1 error(s); historical stale table detected by 18 per-field error(s)
training-profile self-test: 68 field mutations across 17 profiles detected
pricing-drift self-test passed (mirror and training-profile mutations are detected)
```

**`validate_pipeline.py` did not break** (the brief's constraint):

```
before: RESULTS: 66 passed, 0 failed        (exit 0)
after:  RESULTS: 66 passed, 0 failed        (exit 0)
```

Adjacent: `python3 tools/check_knowledge_consistency.py` → exit 0
(`PASS knowledge-consistency: catalog, billing, ai knowledge/verifier, sales KB and docs agree`).

## Item 2 · `deploy/grafana/dashboards/api-performance.json` endpoint label — FIXED

F-2's latent class was present exactly once (panel id 16, "Top 10 Erroring
Endpoints"): the query grouped `by (endpoint)` and the `groupBy`
transformation keyed on the field `endpoint`, while the api-server middleware
emits `path_pattern` (`crates/api-server/src/middleware/metrics.rs:54`) —
a permanently empty panel.

Fix: `by (endpoint)` → `by (path_pattern)`; the transformation's field key
`"endpoint"` → `"path_pattern"`. Panel title unchanged (path patterns are the
route-level endpoints).

**Can-fail proof** (`/tmp/verify-api-perf.py`: asserts the panel groups by
`path_pattern`, the transformation keys on `path_pattern`, the emitter really
emits that label, and every `job="…"` in the file exists in
`deploy/prometheus.yml`):

```
--- against HEAD (git show HEAD:deploy/grafana/dashboards/api-performance.json)
FAIL: expr still groups/selects the dead `endpoint` label
      expr does not group by `path_pattern`
      groupBy transformation still references `endpoint`
      groupBy transformation does not reference `path_pattern`      (exit 1)
--- against the fixed working tree
panels=1 jobs_used=['apexmail-api'] undefined_jobs=[]
PASS: path_pattern label + all job labels valid                      (exit 0)
```

**Job-label confirmation** (brief requirement): a screen over all 18
dashboards × `deploy/prometheus.yml` job names reports
`undefined job labels: NONE` (api-performance uses only `apexmail-api`,
which maps to `static_configs: targets: ['api-server:9090']`).

## Item 3 · `docs/operations/monitoring.md` documented metrics that do not exist — FIXED

F-3 named the `process_*` table; reading the whole section showed the same
defect in three more tables. None of these names exist anywhere in the Rust
sources: `process_cpu_seconds_total`, `process_resident_memory_bytes`,
`process_open_fds`, `process_start_time_seconds`, `tracking_opens_total`,
`tracking_clicks_total`, `tracking_unsubscribes_total`,
`tracking_request_duration_seconds`, `tracking_db_query_duration_seconds`,
`tracking_redis_operation_duration`, `db_pool_connections_total`,
`db_pool_connections_waiting`, `redis_connection_status`,
`redis_commands_total`.

Fix: the Prometheus Metrics section now documents the shipped series only
(job levels from `deploy/prometheus.yml`):

* API server (`apexmail-api`): `apexmail_http_requests_total`,
  `apexmail_http_request_duration_seconds`, `apexmail_http_requests_in_flight`
  (labels `method`, `path_pattern`, `status`) with the explicit note that no
  `endpoint` label exists.
* Tracking (`apexmail-tracking`): the six real `apexmail_tracking_*` series
  from `tracking-service/src/processor.rs` + `routes/{click,pixel}.rs`.
* System/process: a paragraph stating the services export **no** `process_*`
  series (metrics-exporter-prometheus 0.16.2 has no process collector; no
  `metrics-process` dep) and pointing resource panels at node-exporter
  (`job="node"`: `node_cpu_seconds_total`,
  `node_memory_{MemTotal,MemAvailable}_bytes`, `node_filefd_allocated`,
  `node_boot_time_seconds`) — the same retarget U-14 applied to the panels.
* Redis (`apexmail-observability`): the six real `redis_*` series from
  `observability-service/src/redis_monitor.rs`, plus a pointer to the
  redis-exporter `redis` job.
* Database (`postgres`): exporter `pg_*` only; the paragraph states
  `db_query_duration_seconds` is registered in the `prometheus` crate's
  default registry, which no service serves, so it must not be panneled.

Adjacent verified corrections in the same file (all proved against
`routes/health.rs`): the endpoint table now lists `GET /health`,
`/health/live`, `/health/ready`, `/health/deep` (there is no `/ready`), the
readiness checks include the required-console-schema probe, and the
"Available Dashboards" counts/descriptions match the actual panels
(3/4/4/4 for tracking-overview/system-resources/database/redis).

**Can-fail proof** (`/tmp/verify-monitoring-doc.py`: no `process_*` table
rows, none of the 14 fictional names, every documented `apexmail_*` metric
must exist in the Rust sources, `/health/ready` present and `/ready` absent):

```
--- against HEAD: FAIL, 16 findings
      process_cpu_seconds_total still presented as a shipped metric (table row)
      ... fictional metric tracking_opens_total still documented ...
      still documents GET /ready (real path: /health/ready)
--- against the fixed working tree
PASS: every documented metric exists; fictional names and process_* table rows gone  (exit 0)
```

Docs ratchet after the rewrite: `sh tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt`
→ exit 0.

## Item 4 · `tools/ui_flash_extract.py::production_split()` over-cut — FIXED

F-4's repro: a `#[cfg(test)]` token inside a comment/string passed the old
depth scan (comment interiors were recorded at the same depth as code) and
each such token triggered a cut. On a 206-char fixture the old function
produced 113 chars and swallowed following production text.

**Fix.** `production_split` now detects top-level `#[cfg(test)]` items on
MASKED text (`_mask_comments_and_strings`, built from the module's own
`comment_spans`/`rust_string_literals`) and blanks exactly those items via
`_item_end` brace matching. Comments stay in the returned text (line numbers
are preserved); the now-dead `_depth_prefix` helper (whose depth model caused
the bug) was removed. A permanent `--self-test` was added.

**Fixture proof (can-fail).** The self-test fixture carries a token inside a
line comment and a token inside a string literal, then a real top-level
`#[cfg(test)] use … as alias_for_tests;`, then post-alias and post-module
flash call sites. Running the same fixture through HEAD's function (loaded
from `git show`) and the new one:

```
fixture chars: 628
OLD (HEAD): 358 chars | production `use` kept: False | string literal intact: False
NEW:        628 chars | production `use` kept: True  | string literal intact: True
```

```
$ python3 tools/ui_flash_extract.py --self-test; echo $?
ui_flash_extract self-test passed: post-alias and post-module flash copy survive the cfg(test) split; tokens in comments/strings do not cut
0
```

The self-test also asserts the fixture is can-fail by construction (a naive
first-token split must lose production), that exactly 3 production flash
call sites survive, and that a nested (depth > 0) `#[cfg(test)]` attribute is
left alone.

**Real-tree behavior is unchanged** (as expected — the crates carry no
comment/string token): flash sites extracted from the repo = **187** with the
HEAD extractor and **187** with the fixed one; `web.rs`'s production region is
now the whole file with only the real test items blanked.

**Gates (committed fixtures).**

| Gate | Command | Result |
|---|---|---|
| flash copy | `python3 tools/check_flash_copy.py` | exit 0, 187 call sites, `flash copy: all green` |
| form hygiene (committed baselines) | `python3 tools/check_ui_form_hygiene.py` | exit 0, 174/242 controls |
| form hygiene (COMMITTED contrast fixtures) | `python3 tools/check_ui_form_hygiene.py /tmp/committed-contrast/tools/contrast-audit/fixtures` | exit 0, 184/277 controls |
| dead links (COMMITTED contrast fixtures) | `python3 tools/check_ui_links.py /tmp/committed-contrast/tools/contrast-audit/fixtures` | exit 0, 6,355 targets |
| terminology | `python3 tools/check_ui_terminology.py` | exit 0 |
| routes self-test | `python3 tools/ui_routes.py --self-test` | exit 0 |
| catalog consumer | `python3 tools/extract_ui_strings.py` | exit 0 |

The committed-fixture runs use `git archive HEAD tools/contrast-audit/fixtures`
extracted to a temp dir, because the working-tree fixtures are being
regenerated by live siblings (F-6). Running `extract_ui_strings.py` rewrote
the generated `docs/development/ui-strings-catalog.json` from the sibling-
modified `leptos_views.rs`; that artifact was **reverted** (not part of this
brief) and is byte-identical to HEAD again.

## Item 5 · `tools/contrast-audit/crop.mjs` pathname decode — FIXED

`path.dirname(new URL(import.meta.url).pathname)` leaves percent-escapes
encoded, so a checkout path with a space (or non-ASCII) makes every root
derived from it 404. Fix: `path.dirname(fileURLToPath(import.meta.url))`
(`node:url` decodes the path).

**Can-fail proof (end-to-end, from a spaced path).** A copy of the tool at
`/tmp/Apex Mail/tools/contrast-audit/` (fixtures → committed archive,
`node_modules` → repo) with HEAD's version as `crop-head.mjs`:

```
$ node crop-head.mjs web /dashboard light .apex-console-shell /tmp/crop-head.png
page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE at http://127.0.0.1:62519/f/web-dashboard.html
    (fixture server rooted at the encoded path; no crop written)

$ node crop.mjs web /dashboard light .apex-console-shell /tmp/crop-fixed.png
saved /tmp/crop-fixed.png {"x":0,"y":0,"width":1328,"height":1112.546875}
    (valid 1280x900 PNG, 82 KB, real fixture content)
```

**`gate.sh` stays green** (run after the fix):

```
[self-test] PASS — 12/12 checks
[gate] PASS — AA failures: 0 across 0 runs (99 pages, 278 runs, 164.8s)
exit 0
tools/contrast-audit/reports/gate-execution.json: status "executed",
revision 0557e55d, recordedAt 2026-10-07T22:12:26Z
```

## "Not reached" group verdicts (coverage ledger)

### `tools/contrast-audit` support lib

* **`lib/png.mjs`** — read in full (107 lines). Verdict **clean**: signature
  check, chunk walk (`12 + len`), IHDR field offsets, all five filter
  algorithms (Sub/Up/Average/Paeth), color types 0/2/3/4/6 with palette+tRNS,
  and `pngPixel` clamping are correct. Executed proof: decoded the crop above
  (1280×900 RGBA, 4,608,000 bytes, 36 distinct sampled R values, clamping
  OK).
* **`gen-summary.py`** — read in full (153 lines). Verdict **clean** with one
  cosmetic defect fixed: the summary line was printed twice (`:152-153`);
  now once. Still runs against the existing `reports/violations.json`
  (exit 0, `summary.md written: 95 lines`). No gate consumes its stdout.
* **`crop.mjs`** — see Item 5.

### Remaining Grafana / monitoring dashboards (13 + 3 not previously read)

All 18 dashboards were read (panels, queries, transformations). After the
Item 2 fix I re-screened every `apexmail_*` metric against the Rust sources
and every `job="…"` against `deploy/prometheus.yml`:

```
HEAD:  deploy/grafana/dashboards/database-performance.json  apexmail_db_query_duration_seconds_bucket
       deploy/grafana/dashboards/smtp-performance.json      apexmail_smtp_{bounces,deferrals,rejections}_total,
                                                            apexmail_smtp_delivery_duration_seconds_bucket
       deploy/monitoring/dashboards/slo-compliance.json     apexmail_emails_{sent,delivered_within_5m}_total,
                                                            apexmail_auth_{success,attempts}_total      → 9 dead refs
FIXED: DEAD_COUNT 0; undefined job labels: NONE; all 18 files parse as JSON
```

Fixed this wave (all latent/unrenderable, none of them a live signal):

| File | Dead item | Fix |
|---|---|---|
| `deploy/grafana/dashboards/database-performance.json` | hidden p99 target on `apexmail_db_query_duration_seconds` (nothing exports it — the `prometheus`-registry series is unserved) | target removed; panel description records the gap |
| `deploy/grafana/dashboards/smtp-performance.json` | 3 hidden targets `apexmail_smtp_{bounces,deferrals,rejections}_total` + 2 hidden `apexmail_smtp_delivery_duration_seconds` targets | retargeted to real shipped series: `apexmail_outbound_mta_permanently_failed_total` / `_retry_scheduled_total` (hand-written exposition, job `apexmail-outbound-mta`), `mta_smtp_reject` (job `apexmail-mta`; dotted key sanitized by metrics-exporter-prometheus 0.16.2, verified in the vendored crate source), and `mta_smtp_session_duration_bucket` (ms, no `*1000`); legends + panel descriptions state exactly what each series is |
| `deploy/monitoring/dashboards/api-server-overview.json` | panel 8 legend `{{endpoint}}` on a query with no such label | legend → `{{status}} {{method}} {{path_pattern}}` (the query, which the U-14 fix already retargeted, is unchanged) |
| `deploy/monitoring/dashboards/slo-compliance.json` | 6 visible panels: email "delivered within 5 min" ×3 + auth success ×3 (all dead) | retargeted to real proxies with honest titles/descriptions: relay acceptance ratio `accepted/(accepted+permanently_failed)` from the outbound-relay counters (`Email Relay Acceptance Ratio …`), and the 2xx share of `/v1/auth/*` api-server requests (`API Auth Request Success Share …`); row titles updated; descriptions state the proxy nature (the SLA's "valid credential attempts" metric is not instrumented; rejected credentials count as failures in the proxy) |

Everything else in the group referenced real series (repo-emitted
`apexmail_*`, the `apexmail:api_availability|api_latency_slo:ratio_30d`
recording rules in `deploy/alerting-rules.yml`, standard `node_*`/`pg_*`/
`redis_*`/`probe_*` exporter families, and the redis-exporter `redis_key_size`
enabled by `REDIS_EXPORTER_CHECK_KEYS`). No further defects found.

## Filed findings (precise, not fixed — outside the brief's named files)

**R-1 — the same pathname bug exists in three more `tools/contrast-audit`
scripts** (the group's gate itself among them):
`audit.mjs:25`, `layout-audit.mjs:32`, `bots-ui-dogfood.mjs:34` all use
`path.dirname(new URL(import.meta.url).pathname)`. On a checkout path with a
space, `gate.sh`'s audit server would root at the encoded path (all fixtures
404) exactly as the crop probe showed. One-line `fileURLToPath` fixes;
deliberately not edited because the brief names only `crop.mjs` in this group.

**R-2 — `docs/sla.md:177-178`** claims "All SLA-relevant metrics are exposed
via the `/metrics` endpoint with a `slo` label". No service sets a `slo`
label anywhere (`grep -rn '"slo"' crates/` → none), and §2.4's "Auth success
rate ≥ 99.9% of valid credential attempts" has no backing counter at all
(which is why the monitoring dashboard's auth panels could only be retargeted
to an HTTP-share proxy). `docs/sla.md` is outside this brief's named files.

## Gate evidence (all green, final run)

| Gate | Command | Result |
|---|---|---|
| pricing drift (default, now incl. training profiles) | `python3 tools/validate_pricing_drift.py` | exit 0 |
| pricing-drift self-test | `… --self-test` | exit 0 (mirror + 68 training-profile mutations) |
| training pipeline validator | `cd apps/ai/training && python3 validate_pipeline.py` | exit 0, 66 passed 0 failed |
| knowledge consistency | `python3 tools/check_knowledge_consistency.py` | exit 0, PASS |
| flash copy | `python3 tools/check_flash_copy.py` | exit 0 (187 sites) |
| ui_flash_extract self-test | `python3 tools/ui_flash_extract.py --self-test` | exit 0 |
| form hygiene (committed baselines) | `python3 tools/check_ui_form_hygiene.py` | exit 0 (174/242) |
| form hygiene (committed contrast fixtures) | `… /tmp/committed-contrast/tools/contrast-audit/fixtures` | exit 0 (184/277) |
| dead links (committed contrast fixtures) | `python3 tools/check_ui_links.py …` | exit 0 (6,355 targets) |
| terminology | `python3 tools/check_ui_terminology.py` | exit 0 |
| routes self-test | `python3 tools/ui_routes.py --self-test` | exit 0 |
| contrast gate | `sh tools/contrast-audit/gate.sh` | exit 0, PASS (278 runs, 164.8 s) |
| docs-lint ratchet | `sh tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` | exit 0 |
| dashboard dead-ref screen | `python3 /tmp/screen-dashboards.py` | exit 0, DEAD_COUNT 0 |
| monitoring-doc check | `python3 /tmp/verify-monitoring-doc.py` | exit 0 |

The three checkers used as can-fail evidence (`screen-dashboards.py`,
`verify-monitoring-doc.py`, `verify-api-perf.py`) are one-off probe scripts
kept in `/tmp`; they exit 1 against HEAD's versions and 0 against the fixed
tree, as quoted above.

## Residual risks

1. The retargeted SMTP/SLO panels use the outbound relay's counters, which
   are process-local and reset on restart; `rate()` handles that, but the
   proxies are not the SLA's own series (which do not exist). Instrumenting
   the real SLO counters is a code change outside this brief.
2. `mta_smtp_reject` / `mta_smtp_session_duration` depend on the MTA exporter
   naming (dots → underscores, no `_total` suffix) verified against the
   vendored `metrics-exporter-prometheus-0.16.2` source; if the exporter is
   ever swapped, those two hidden targets need re-checking (they are hidden,
   so no visible panel regresses).
3. R-1/R-2 remain open as filed findings.

---

# Follow-up pass — landing the two filed leftovers (R-1, R-2)

Same brief family, 2026-10-07 (second pass). Files touched: `tools/contrast-audit/audit.mjs`,
`tools/contrast-audit/layout-audit.mjs`, `tools/contrast-audit/bots-ui-dogfood.mjs`,
`docs/sla.md`. Nothing else.

## R-1 · `URL.pathname` decode in the three remaining contrast-audit scripts — FIXED

`audit.mjs:25`, `layout-audit.mjs:32` and `bots-ui-dogfood.mjs:34` carried the
same latent bug as `crop.mjs`: `path.dirname(new URL(import.meta.url).pathname)`
leaves percent-escapes encoded, so any checkout path containing a space (or
non-ASCII) roots the fixture server at a directory that does not exist. Each
now imports `fileURLToPath` from `node:url` and resolves
`path.dirname(fileURLToPath(import.meta.url))` (decode-only change; the
UI agent's in-flight use of `bots-ui-dogfood.mjs` is unaffected, and a
space-free path resolves to the byte-identical directory).

**Can-fail proof (space-containing path, committed fixtures).** A copy of the
tool at `/tmp/Apex Mail/tools/contrast-audit/` (fixtures → `git archive HEAD`
extract, `node_modules`/`lib`/`apps` symlinked) with the pre-change scripts as
`*-head.mjs`:

| Script | Pre-change run (same spaced path) | Fixed run |
|---|---|---|
| `audit.mjs` (`AUDIT_ONLY=web:/login`) | `ENOENT … '/private/tmp/Apex%20Mail/…/fixtures/manifest.json'`, exit 1 | self-test 12/12 + 3 real page runs (`ok web /login [light|dark|dark-class]`), exit 0 |
| `layout-audit.mjs` (`AUDIT_ONLY=web:/login`, `AUDIT_LAYOUT_REPORT_ONLY=1`) | same encoded-path `ENOENT`, exit 2 | 5 runs, `Done: 0 layout findings …`, exit 0 |
| `bots-ui-dogfood.mjs fixtures` | same encoded-path `ENOENT` at the manifest read, exit 1 | 12 captures (2 fixtures × 2 themes × 3 widths), `report.json` written, exit 0 |

The `bots-ui-dogfood` "pre-change" variant is a reconstruction of its
pre-edit import block (the file is untracked, so there is no HEAD revision);
the reconstruction is limited to the import/ROOT lines this pass changed.

**Gates (re-run this pass, in the real repo).**

* `sh tools/contrast-audit/gate.sh` → **PASS**: `[gate] PASS — AA failures: 0
  across 0 runs (99 pages, 278 runs, 209.1s)`, exit 0; execution record
  `status: executed`, `recordedAt: 2026-10-07T22:39:30Z`.
* `sh tools/contrast-audit/layout-gate.sh` → exit 1 with **10 pre-existing
  findings** (control-plane `/sales` and `/cp/sales` mobile:
  `text-spills-box` + `escapes-card`; `/cp/demos` mobile:
  `doc-horizontal-overflow`). These are not caused by this change: with
  HEAD's `layout-audit.mjs` swapped back in (temporary probe file, removed
  afterwards) the same three routes produce the identical findings
  (`/sales`: 4 findings `{text-spills-box:2, escapes-card:2}`; `/cp/sales`:
  same; `/cp/demos`: 2 `{doc-horizontal-overflow:2}`). The working-tree
  fixtures are mid-recapture by the UI lane; the decode-only change is
  behavior-neutral on a space-free path by construction.

## R-2 · `docs/sla.md` false `slo` label and unbacked auth SLO — FIXED

The modelling follows the `monitoring.md` correction.

* **§2.4 Authentication** keeps the contractual target but now states how the
  number is produced: the 2xx share of API requests under `/v1/auth/`
  (`apexmail_http_requests_total` on the `apexmail-api` job,
  `path_pattern=~"/v1/auth/.*"`), noting that rejected credentials count as
  failures so the share is a lower bound, that no counter scoped to valid
  credential attempts exists, and that SMTP AUTH failures are observable as
  `mta.auth.failure` on the `apexmail-mta` job.
* **§5.3 Monitoring Tools** no longer claims "All SLA-relevant metrics are
  exposed via the `/metrics` endpoint with a `slo` label" (no service sets a
  `slo` label). It now names the scrape jobs file, the api-server request and
  latency series, the outbound-relay counters
  (`apexmail_outbound_mta_{accepted,permanently_failed,retry_scheduled}_total`),
  and the two recording rules `apexmail:api_availability:ratio_30d` /
  `apexmail:api_latency_slo:ratio_30d` in `deploy/alerting-rules.yml`.

**Can-fail proof** (`/tmp/verify-sla-doc.py`: no `slo`-label claim, every
named `apexmail_*` metric must exist in the Rust sources, recording rules must
exist in `deploy/alerting-rules.yml`, the auth measurement note must be
present):

```
--- against HEAD: FAIL, 14 findings
      still claims a global `slo` label
      still claims all SLA metrics are on /metrics
      shipped signal apexmail_http_requests_total not documented  (+10 more)
      auth SLO has no honest measurement note
--- against the fixed working tree
PASS: no slo-label claim; shipped metrics/rules named; auth SLO measurement stated
exit 0
```

**docs-lint stays green**: first pass read 11 vs the per-file row of 10
(one new duplicate sentence: the standalone bold `**Measurement.**` normalized
to a duplicate bare word `measurement`). The label was folded into prose and
the ratchet is green again:

```
sh tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt
  → exit 0; TOTAL: 2787 violations across 224 files
    (baseline 2827; every scanned file at or below its per-file row)
```

## Follow-up gate evidence

| Gate | Command | Result |
|---|---|---|
| contrast gate | `sh tools/contrast-audit/gate.sh` | exit 0, PASS (278 runs) |
| layout gate | `sh tools/contrast-audit/layout-gate.sh` | exit 1 — 10 pre-existing findings, identical under HEAD's script (proven above) |
| docs-lint ratchet | `sh tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` | exit 0 (2787 ≤ 2827) |
| sla.md doc check | `python3 /tmp/verify-sla-doc.py` | exit 0 (HEAD: exit 1, 14 findings) |
| mjs syntax | `node --check` on the three scripts | ok |

Residual: the layout-gate findings belong to the UI lane's mobile fixtures
(`/sales`, `/cp/sales`, `/cp/demos`); they are reproducible with the
pre-change script, so this pass leaves them to the owning agent.
