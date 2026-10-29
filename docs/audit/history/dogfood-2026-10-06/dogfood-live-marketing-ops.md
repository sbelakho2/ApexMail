# LIVE DOGFOOD — F: marketing, public surfaces, cross-cutting ops

> Date: 2026-10-08 · Repo: `/Users/sabelakhoua/IdeaProjects/ApexMail` (main @ 97301948)
> Stack: live compose (`marketing.localhost:8080` → api-server SSR marketing surface;
> Mailpit `:8025`; tracking `:3001`/`:9092`; ClickHouse `:8123`/`:9000`).
> Method: real HTTP/browser drives against the running product, verified against the
> canonical catalog, Postgres, Redis, ClickHouse, and container logs. Every probe below was
> executed; per-probe evidence is quoted. Fixes are source-level in owned paths with
> fail-before proofs (see §Fixes). Per the brief, **no docker builds** were run — the running
> image therefore still exhibits the pre-fix live behaviour quoted below until the next image
> build; every fix is proven by tests/gates against the tree.

## Verdict summary

| # | Probe | Verdict |
|---|-------|---------|
| 1 | Marketing page walk (177 pages, titles, pricing vs canonical) | **DEFECT (P1) → FIXED** — 63 built locale pages 404'd live |
| 2 | Calculator island + `/.well-known/security.txt` | **DEFECT (P1) → FIXED** — security.txt + PGP keys 404'd; calculator PASS |
| 3 | Forms, hostile inputs, consent island, i18n, styled pages | **DEFECTs (P1/P3) → FIXED** — styles.css shipped 0600 (unstyled site); consent policy link escaped locale; rest PASS |
| 4 | Funnel pricing → `?plan=pro` → completion | **PASS** |
| 5 | Health + metrics across services | **DEFECTs (P1/P2) → FIXED/FILED** — api latency series was a Summary (dead `_bucket` alerts/panels); tracking/enterprise scrape targets dead; `redis_*` unreachable |
| 6 | Rate limits / CSRF / idempotency / sessions | **PASS** (one DDoS-protector engagement recorded as expected) |
| 7 | WAF/DDoS paced hostile payloads + A-3 counters | **PASS for behaviour; FINDING (P2)** — `ddos_*` Prometheus series are dead (registry mismatch) |
| 8 | Log hygiene | **PASS** — no live secrets in 1h of logs |
| 9 | Backups dry-run / fail-loud | **DEFECT (P2) → FIXED** (clickhouse port + missing dry-run; postgres dry-run added); fail-loud verified |
| 10 | SDKs with `template_id` → Mailpit | **PASS** (php/python/go/ruby/java) |

## Findings

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| MK-1 | 63 built locale pages (`/de /fr /es` pricing, pricing/calculator, compare/\*, solutions/\*, contact/\*, enterprise, inbox-placement, anti-spam, secure-email-for-regulated-saas) had no `marketing_static_document` arm → live 404s | P1 | FIXED + gate + test |
| MK-2 | `apps/marketing-zola/public/css/styles.css` shipped mode 0600 root-owned; the api-server (uid 10001) cannot read it → `/css/styles.css` 404s on every page → **entire marketing site rendered unstyled** | P1 | FIXED + mode invariant test + Dockerfile/dev-start hardening |
| MK-3 | `/.well-known/security.txt` (RFC 9116) and its `Encryption:` targets `/pgp-key.asc` / `/pgp-key.txt` existed in the build output but were unrouted → 404 on every SSR host | P1 | FIXED + tests |
| MK-4 | Cookie-consent banner's "Cookie Policy" link was hardcoded `/cookies/` → de/fr/es pages linked the English page | P3 | FIXED + gate + regenerated site |
| OPS-1 | `apexmail_http_request_duration_seconds` exported as Prometheus **summary** (no `_bucket`), while `deploy/alerting-rules.yml` + `deploy/grafana/dashboards/api-performance.json` query `..._bucket` with `histogram_quantile()` → every latency alert/panel mathematically dead | P1 | FIXED + tests |
| OPS-2 | tracking metrics listener binds 127.0.0.1 in-container (`METRICS_BIND_ADDR` unset in any compose file) → documented scrape target `tracking:9092` **connection refused** from other containers, host port mapping returns an empty reply | P2 | FILED (compose is another partition's file; repro below) |
| OPS-3 | enterprise `/metrics` serves 200 only from its own loopback; from the network it is 401 and `deploy/prometheus.yml` has no `authorization:` → `apexmail-enterprise` job dead | P2 | FILED (repro below) |
| OPS-4 | `observability` service (documented source of `redis_*` eviction gauges) is profile-gated `monitoring`, the image is not built locally, no `prometheus/grafana/redis-exporter` containers run → `redis_*` series UNREACHABLE in this stack | P3 | UNREACHABLE-with-proof |
| OPS-5 | `ddos_*` series (`ddos_requests_total`, `ddos_blocked_ips`, …) register in the **prometheus-crate** registry while the api-server exposes the **metrics-facade** recorder → zero `ddos_*` samples on `:9090/metrics` despite live WAF/rate-limit decisions; A-3's `record_*` counters have no observable surface | P2 | FILED (repro below) |
| OPS-6 | `scripts/clickhouse-backup.sh` documented `CLICKHOUSE_PORT` default 8123 — the HTTP port; `clickhouse-client` needs 9000 (native). Default-env backup died with `Connection reset by peer`; no `--dry-run` existed | P2 | FIXED |
| OPS-7 | `deploy/hardening/scripts/postgres-backup-encrypt.sh` had no safe mode (ran the full daily backup immediately) | P3 | FIXED (`--dry-run` added, live+unreachable verified) |
| OPS-8 | 3 live 5xx on `POST /v1/admin/billing/abuse/reports/:id/{resolve,review}` (other agent's traffic; not from the hostile probes below) | P2 | FILED (owned by the control-plane/money partition) |

---

## 1. Marketing site, all pages live

### 1.1 Page walk — every built page

```console
$ find apps/marketing-zola/public -name index.html | sed 's|apps/marketing-zola/public||; s|/index.html$||' | sort > pages.txt   # 177 pages
$ while read -r p; do
    curl -s -o body.html -w "%{http_code}|%{size_download}|%{content_type}" "http://marketing.localhost:8080${p}"
    title=$(grep -o '<title>[^<]*</title>' body.html | head -1)
    printf '%s|%s|%s\n' "$p" "$out" "$title" >> walk.txt
  done < pages.txt
$ awk -F'|' '{print $2}' walk.txt | sort | uniq -c
 114 200
  63 404
```

**All 63 non-200s are built locale pages with `Page not found | ApexMail`** — e.g.
`/de/pricing`, `/de/pricing/calculator`, `/de/compare/*`, `/de/solutions/*`,
`/de/contact/{sales,enterprise,security}`, `/es/...`, `/fr/...`.

Root cause (grep of the tree): the built pages exist, and `ui-foundation`'s
`marketing_static_document` whitelist had no arm for them although the function's own doc
comment claims "every `public/**/index.html` is whitelisted here … so no built page 404s":

```console
$ grep -c '"$p" => Some(include_str!' services/mail-server/crates/ui-foundation/src/axum_router.rs   # per path
/de/pricing                   0
/de/pricing/calculator        0
/de/solutions                 0
...
$ while read -r p; do grep -qF "\"$p\" => Some(include_str!" .../axum_router.rs || echo "$p"; done < pages.txt | wc -l
63
```

The unit test that was supposed to guard this (`every_built_marketing_document_is_served_with_and_without_slash`)
used a **handwritten** `BUILT` list that omitted exactly those 63 paths — so it passed while
the live site 404'd. **Fixed** (§Fixes F1).

### 1.2 Titles

Multiline-aware comparison of the title of every one of the 177 built docs against the live
response:

```console
pages=177 status!=200: 63 title_diffs: 63    # every diff is a 404 (built title vs "Page not found")
# all 114 served pages: titles byte-identical to the built output
```

### 1.3 Pricing numbers EQUAL the canonical catalog

Canonical source: `crates/platform-catalog/src/lib.rs` (`PLANS`, `PAYG_TIERS_EUR_PER_EMAIL`,
`FREE_LAUNCH_ALLOWANCE`) — itself pinned by `tools/validate_pricing_drift.py`
(ran: `pricing drift validation passed`, exit 0).

Structured check against the **rendered live HTML** (`/pricing`):

```console
Free               price €0       present=True  vol '3,000 emails/month' present=True
Developer          price €29      present=True  vol '50,000 emails/month' present=True
Pro                price €89      present=True  vol '150,000 emails/month' present=True
Growth             price €229     present=True  vol '500,000 emails/month' present=True
Business           price €699     present=True  vol '2,000,000 emails/month' present=True
Enterprise Cloud   price €1,750   present=True  vol '5M emails/month' present=True
annual (10×) pairs on the island: €290/yr, €890/yr, €2,290/yr, €6,990/yr, €17,500/yr — all present
```

### 1.4 Calculator island computes canonical PAYG/overage figures

The zero-JS calculator (`/pricing/calculator`) posts to the api-server. Driven live:

```console
$ curl -s -X POST http://127.0.0.1:8080/explorer/calculate \
    -d "volume=150000&peak_daily=7500&domains=2&team_users=3&dedicated_ips=0&billing_cycle=monthly"
Plan — Pro | €89.00 | Included emails / month 150,000 | Monthly total €89.00 | Annual alternative €890.00
$ ... -d "volume=200000&...&dedicated_ips=2&billing_cycle=annual"
Plan — Growth €229.00 | Dedicated IPs (1× €49 + 1× €69) €118.00 | Monthly equivalent €347.00 | Annual total (2 months free) €3470.00
$ ... -d "volume=3000000&...&billing_cycle=monthly"
Plan — Scale €699.00 | Included 2,000,000 | Overage €350.00 (= 1M × 35 millicents) | Monthly total €1049.00
```

All figures match the canonical catalog (Pro 8900¢/89000¢; Growth 22900¢; Business 69900¢ +
35 millicents/email overage; dedicated-IP ladder €49 first / €69 additional).
The generated island snapshot (`templates/partials/generated/pricing-calculator-island.html`)
states `Developer €0.80, Pro €0.60, Growth/Business €0.35 per 1,000` (= 80/60/35 millicents) —
canonical; `validate_pricing_drift.py` covers it. **PASS.**

### 1.5 `/.well-known/security.txt` — DEFECT

```console
$ curl -s -D- http://marketing.localhost:8080/.well-known/security.txt | head -1
HTTP/1.1 404 Not Found            # same on Host: apexmail.ee
$ curl -s -o /dev/null -w '%{http_code}\n' http://marketing.localhost:8080/pgp-key.asc
404                                # and /pgp-key.txt, while the files exist in the build output
$ docker exec apexmail-api-server-1 cat /app/apps/marketing-zola/public/.well-known/security.txt
Contact: mailto:security@apexmail.ee
Expires: 2027-10-06T00:00:00Z
...
Encryption: https://apexmail.ee/pgp-key.asc
```

The file exists in the shipped public dir; api-server's `marketing_assets` router simply never
routed it (nor the PGP keys). **Fixed** (§Fixes F2). Contact/expiry values verified correct in
the served artifact source.

---

## 2. Forms, consent, i18n, styling

### 2.1 Real form submissions land in the documented store (DB)

Documented route: `POST /v1/contact/{sales,enterprise,security}` → one transaction writing
`sales_accounts → sales_contacts → sales_contact_points → sales_leads` + a
`first_response_requests` row (no auth; PRG redirect to the marketing host).

```console
$ curl -s -D- -X POST http://127.0.0.1:8080/v1/contact/sales \
    -d "company=Dogfood-1791459265" -d "work_email=dogfood-1791459265@example.com" ... -d "apexmail_consent=on"
HTTP/1.1 303 See Other
location: https://apexmail.ee/contact/sales?submitted=true#enquiry-submitted
x-ratelimit-limit: 20
```

Postgres verification (unique suffix `1791459265`):

```console
$ psql -c "SELECT id, contact_email, company_name, domain, source, account_id, contact_id, notes FROM sales_leads WHERE contact_email='dogfood-…@example.com'"
 lead_0o3l68mneih7dwbq2l683ojeoc | dogfood-…@example.com | Dogfood-1791459265 | example.com | marketing-sales-form | 13f5d0e7-… | a9c9eb0d-… | Volume/Provider/Deployment preference/Compliance needs(GDPR, SOC2)/Timeline/Security review/Additional context
$ psql -c "SELECT … FROM sales_contacts WHERE legacy_lead_email=…"     # canonical contact row present
$ psql -c "SELECT * FROM sales_contact_points WHERE value LIKE …"      # email point, verification='unverified', confidence 0.3, source marketing-sales-form
$ psql -c "SELECT kind, subject_ref FROM first_response_requests WHERE payload->>'email'=…"
 contact_form | a9c9eb0d-6f67-48c3-b47f-fec4e5b43e2a
```

Enterprise + security forms: 303 with locale-aware redirect (`page_language=de` →
`https://apexmail.ee/de/contact/enterprise?submitted=true#enquiry-submitted`) and two more
`marketing-enterprise-form` / `marketing-security-form` lead rows + first-response rows.
Abuse has no form by design — the contact hub and policies direct to `mailto:abuse@apexmail.ee`
(verified in `/contact`, `/anti-spam`, `/acceptable-use` content). **PASS.**

### 2.2 Hostile inputs

```console
2MB body  -> 303 location: …?error=validation#enquiry-error     (no row written, no 5xx)
3MB body  -> 303 validation refusal
8MB body  -> 303 validation refusal
$ psql -t -c "SELECT count(*) FROM sales_leads WHERE company_name LIKE 'Big-A%'"
0
invalid email -> 303 ?error=validation
SQLi/XSS/traversal strings in company/name/context -> 303 submitted=true; stored as DATA, parameterized SQL intact
$ psql -c "SELECT notes FROM sales_leads WHERE contact_email='sqli-…'"  → "Additional context: <img src=x onerror=alert(1)>"
```

Refused cleanly, no 5xx, no execution. Note (not a defect claim): the public contact routes
have **no `DefaultBodyLimit`** (the only limit is on `/v1/messages`), so oversized bodies are
fully buffered before field-length validation; the DDoS middleware is the only front gate. Filed
as an observation for the api-server hardening partition.

### 2.3 Cookie-consent island (real browser)

Headless Chromium (local Playwright, `chrome-headless-shell` 1243) drove the banner link with
the api host remapped and the production same-site hop emulated (the local
`marketing.localhost → api.apexmail.ee` hop is cross-site and is correctly refused by the
anti-forgery guard):

```console
consent before: pending
click "Nur notwendige" → 302 Set-Cookie: apexmail_consent=necessary; Domain=.apexmail.ee; …; SameSite=Lax; HttpOnly
landing after click:  https://apexmail.ee/de/security/  data-consent-state="recorded"
reload with cookie:  recorded
cross-site GET (Sec-Fetch-Site: cross-site) → 302, NO Set-Cookie   (forged consent refused)
return_to=https://evil.example/… → Location: /                     (open redirect refused)
```

**PASS.**

### 2.4 i18n switch

`/de/` serves `lang=de` with German title/h1 ("Die E-Mail-API Kontrolle."), `/de/security` German
content, hreflang alternates emitted for en/de/es/fr/x-default; localized internal links stay
in-language (`/de/...`). **DEFECT found in the consent island**: its "Cookie-Richtlinie" link
was hardcoded `/cookies/`, so de/fr/es pages linked the English policy page while translated
pages exist:

```console
$ for l in de fr es; do grep -o 'href=[^ >]*cookies[^ >]*' public/$l/security/index.html; done
href=/cookies/  href=/de/cookies/     (before fix: the consent banner link was the non-prefixed one)
```

**Fixed** (§Fixes F3; regenerated site now emits `href=/de/cookies/`, `/fr/cookies/`, `/es/cookies/`,
EN keeps `/cookies/`).

### 2.5 No page renders unstyled — computed styles (6 pages)

Live browser computed styles (home, /pricing, /features, /contact/sales, /de/, /de/security):

```json
"sheets": [ {"/css/styles.css…", rules: "blocked"}, {"/css/no-js.css…", rules: 72}, {"giallo.css (cross-origin)", "blocked"} ],
"h1":   { "font": "Times", "color": "rgb(0,0,0)", "size": "32px" },
"body": { "font": "Times", "color": "rgb(0,0,0)" },
"btn":  { "font": "Times", "color": "rgb(0,0,238)", "bg": "rgba(0,0,0,0)" }   // default UA link
```

`/css/styles.css` → **404** on every page (all 179 built HTML files reference it) while
`/css/no-js.css` → 200. Root cause:

```console
$ docker exec apexmail-api-server-1 ls -la /app/apps/marketing-zola/public/css/
-rw------- 1 root root 87669 … styles.css            # mode 0600, owner root
-rw-r--r-- 1 root root 71688 … input.css
$ docker exec apexmail-api-server-1 id
uid=10001(apexmail)
$ docker exec apexmail-api-server-1 head -c1 /app/apps/marketing-zola/public/css/styles.css
head: cannot open '…/styles.css' for reading: Permission denied
```

A umask-077 tailwind build produced a 0600 artifact; the image COPY preserves modes and the
runtime user cannot read it. **Fixed** (§Fixes F4).

### 2.6 Funnel

```console
pricing CTAs:  /signup (Free, and bottom CTA), /signup?plan=starter, ?plan=pro, ?plan=growth, ?plan=scale;
               Enterprise Cloud → Contact sales (no dead-end plan)
$ curl -s "http://127.0.0.1:8080/signup?plan=pro"
  <input type="hidden" name="plan" value="pro" />   +  data-signup-plan-intent="pro"
  "You selected Pro. Your workspace starts on Free; activate Pro after email verification through secure billing setup."
POST /web/auth/signup (csrf + plan=pro, unique email) → 303 location: /verify-email?email=funnel-…
  set-cookie: apexmail_flash=…("Account created. Check your email for a verification link.")
$ psql -c "SELECT id, tenant_id, email, name, email_verified, role FROM users WHERE email=…"
 f64775aa-… | gg0tedwh656i5j4o8lwmf4o28d | funnel-… | Funnel Probe | f | owner
$ psql -c "SELECT plan FROM tenants WHERE id=…"    → free        (as the page states)
Mailpit: "Verify your ApexMail account" → funnel-…@…   (verification mail delivered)
```

CTA invariant across the whole built site: every `signup?plan=` value is one of
`{starter,pro,growth,scale}` (no non-public plan refs). Note: the plan intent is intentionally
not persisted by the JSON/SSR signup (`let _ = plan; // onboarding preference only`), consistent
with the page copy. **PASS.**

---

## 3. Cross-cutting ops

### 3.1 Health

```console
$ for p in /health /health/live /health/ready /health/deep; do curl -s http://127.0.0.1:8080$p; done
/health        200 {"status":"ok"}
/health/live   200 {"status":"ok"}
/health/ready  200 {"db":"connected","redis":"connected","schema":"complete","status":"ok"}
/health/deep   200 {"status":"ok","db":{…},"redis":{…}}
```

Siblings (probed from inside the compose network, as a real scrape would):

```console
tracking:3001/health        200 {"service":"tracking","status":"healthy"}
enterprise:3008/health      200 {"service":"enterprise","status":"ok"}
compliance:3011/health      200 {"status":"ok"}
ha:4300/health              200 {"status":"ok"}
ai-service:3012/health      200 {…capabilities…}
sales-autopilot:3010/health 200 {"database":"up","service":"sales-autopilot","status":"healthy"}
outbound-mta:8093/healthz   (job scrapes /metrics; see below)
```

During a burst of my own probe traffic the four api-server health endpoints returned
`429 DDOS_RATE_LIMITED` (typed JSON, `retry-after: 1`); under normal pacing they are 200.
Recorded as expected protector behaviour (the compose healthcheck is a TCP probe and never
trips it).

### 3.2 Metrics — documented series and labels

**api-server `:9090/metrics`** — series exist with documented labels
(`method`, `path_pattern`, `status`), e.g.
`apexmail_http_requests_total{method="GET",path_pattern="/health/live",status="200"} 2`.
**DEFECT (OPS-1)**: the duration series was exported as a **summary**
(`# TYPE apexmail_http_request_duration_seconds summary`), with **0 `_bucket` samples**, while
every latency alert/panel queries `_bucket`:

```console
$ grep -rn "apexmail_http_request_duration_seconds" deploy/alerting-rules.yml deploy/prometheus/alerts/api-alerts.yml deploy/grafana/dashboards/api-performance.json | head
deploy/alerting-rules.yml:152: sum(increase(apexmail_http_request_duration_seconds_bucket{job="apexmail-api",le="1"}[30d])) / …
deploy/alerting-rules.yml:189: histogram_quantile(0.95, rate(apexmail_http_request_duration_seconds_bucket{job="apexmail-api"}[5m])) > 1
deploy/grafana/dashboards/api-performance.json:225: "histogram_quantile(0.95, sum(rate(apexmail_http_request_duration_seconds_bucket{…}[5m])) by (le)) * 1000"
```

Root cause: `metrics-exporter-prometheus` renders histograms as summaries unless
`set_buckets_for_metric` is configured; `bin/server.rs` installed the recorder unconfigured.
**Fixed** (§Fixes F5).

**tracking `:9092/metrics`** — listener binds container loopback (no `METRICS_BIND_ADDR` in any
compose file):

```console
$ curl -sv http://127.0.0.1:9092/metrics          # host port → empty reply from server
$ docker exec apexmail-worker-1 wget -S -O - http://tracking:9092/metrics
Resolving tracking (tracking)... 172.20.0.5
Connecting to tracking (tracking)|172.20.0.5|:9092... failed: Connection refused.
$ docker exec apexmail-tracking-1 wget -qO- http://127.0.0.1:9092/metrics | head -3
# TYPE apexmail_tracking_click_redirects_blocked_total counter
```

Documented scrape target `tracking:9092` (deploy/prometheus.yml) is **dead** (OPS-2, filed).
Series that DO exist once events flow: I minted a signed tracking token (codec AES-128-GCM,
`TRACKING_SECRET_KEY`) and drove `/o/<token>` and `/c/<token>` with a browser UA:

```console
apexmail_tracking_clickhouse_events_total{outcome="inserted"} 2
apexmail_tracking_dedup_total{event_type="click",outcome="new"} 1
apexmail_tracking_dedup_total{event_type="open",outcome="new"} 1
apexmail_tracking_click_redirects_blocked_total 1
$ curl 'clickhouse:8123' "SELECT event_type, tenant_id, count() FROM apexmail.events WHERE tenant_id='dogfood-tenant' GROUP BY …"
opened  dogfood-tenant  1
clicked dogfood-tenant  1
```

(`clickhouse_failures_total`, `dead_letter_total`, `open_recorder_dropped_total` are
lazy/registration-on-first-use counters; their emission sites exist and none of the
corresponding conditions occurred in this window.)

**enterprise `:3008/metrics`**:

```console
$ docker exec apexmail-enterprise-1 wget -qO- http://127.0.0.1:3008/metrics | head -2     # loopback
# TYPE apexmail_enterprise_info gauge
apexmail_enterprise_info 1
$ docker exec apexmail-worker-1 wget -S -O - http://enterprise:3008/metrics              # network
HTTP/1.1 401 Unauthorized   … Username/Password Authentication Failed.
```

The handler requires loopback or a bearer `METRICS_TOKEN`; `deploy/prometheus.yml` has no
`authorization:` and compose sets no token → dead job (OPS-3, filed).

**mta/worker/outbound-mta**: reachable with documented series
(`mta_spf_cache_hit`, `apexmail_processor_alive`, `apexmail_outbound_mta_queue_pending`, …).

**`redis_*`** — documented under job `apexmail-observability` (+ the redis-exporter job), but:

```console
$ docker ps --format '{{.Names}}' | grep -Ei "observability|redis-exporter|prometheus|grafana|node-exporter"   # (empty)
$ docker images | grep -i observability                                                                        # (empty)
$ docker-compose.yml: observability has `profiles: [monitoring]`                                               # opt-in, not active
```

**UNREACHABLE-with-proof** (OPS-4): the series cannot be scraped in this stack; the monitoring
profile (and its image build) is required.

### 3.3 Rate limits / CSRF / idempotency / sessions

**Public surface (20 req/60s/IP+path).** With the window aligned:

```console
/v1/auth/csrf ×22 → 200 200 … 200 (20×) then 429 429
429 body {"error":{"code":"RATE_LIMIT_EXCEEDED",…}} Retry-After: <window end>
same IP, different path (/health/live)        → 200     # buckets are per path
different Redis bucket keys (apexmail:ratelimit:…): per IP+path, and per credential
```

**Console SSR surface** (`/web/auth/login`, browser form post; aligned window):

```console
codes: [200×20, 429×4]   # 21st request refused; 429 is the branded HTML page for browser paths
```

**Control plane** (`POST /web/cp/login`, Host cp.localhost):

```console
codes: [200×13, 429×11]  # remainder of the shared per-IP+path window; engages at the documented 20
```

**Authenticated tenant budget** observed live with an API key (Free tier 10 rps × 60s):

```console
x-ratelimit-limit: 600   x-ratelimit-remaining: 598 → 597 → 596      (per-tenant Redis key)
```

Buckets are per tenant (`apexmail:ratelimit:<tenant_id>:<window>`) and per credential
(`…:public:ip:<ip>:user:<ak|session hash>:<path>`), so exhaustion of one tenant/IP/path cannot
starve another. Exhaustion of the authenticated bucket was not forced by flooding: a burst
tripped the DDoS protector first (below), and the brief forbids flooding.

**Protector engagement (recorded, expected):** during the paced rate-limit bursts the open edge
returned `429 DDOS_RATE_LIMITED` (retry-after 1s) and once `403 DDOS_BLOCKED`; recovered on its
own. Not a defect.

**CSRF (missing/wrong refused; no side effects):**

```console
POST /v1/auth/signup (no X-CSRF-Token)  → 403 {"code":"FORBIDDEN","message":"missing X-CSRF-Token header"}
POST /v1/auth/login  (bogus token)      → 403 {"code":"FORBIDDEN","message":"invalid CSRF token"}
POST /web/auth/signup (no _csrf)        → 303 /signup (flash error);   users row for the address: 0
POST /web/auth/signup (mismatched)      → 303 /signup;                 users row: 0
POST /v1/auth/logout (no token)         → 403
```

**Idempotency (single effect on replay):**

```console
POST /v1/messages, Idempotency-Key: ops-idem-1791460495 ×2 (same body)
  both → 202 data.id=1552a44b-6405-4b66-a57d-df7f75dd390f   (identical)
  email_queue rows for the subject: 1 · status=sent · Mailpit messages: 1
same key, different body → 409 {"code":"CONFLICT","message":"idempotency-key was already used with a different request body"}
```

**Sessions (revocation immediate):**

```console
GET /dashboard with am_session            → 200 Dashboard — ApexMail
POST /v1/auth/logout (CSRF)               → 204
GET /dashboard with the SAME cookie       → 303 location: /login?next=%2Fdashboard
POST /v1/auth/logout without CSRF         → 403
```

### 3.4 WAF/DDoS — paced hostile payloads

Paced (~1.2 s apart), as data, through the open edges; **no 5xx on any probe path**:

```console
POST /v1/contact/sales  (SQLi/XSS/traversal in company/name/context) → 303 ×6 (validation redirects)
GET  /pricing?q=<SQLi|<script>|../../etc/passwd>                     → 200 ×3 (data ignored)
POST /explorer/calculate volume='1;DROP TABLE users;--'              → 422 ×2 (typed form refusal)
WAF log: "WAF screening verdict","decision":"WAF monitor","score":3,"rules":"[932050]"  ×42   (monitor mode)
5xx on my paths: 0        (hostile payloads)
```

3 × 500 exist in the same window on `POST /v1/admin/billing/abuse/reports/:id/{resolve,review}`
(another partition's traffic — OPS-8 filed).

**A-3 reputation counters:** the wiring is present in source
(`note_reputation_request` on every evaluated request; `note_reputation_outcome(Blocked|RateLimited|ChallengeFailed)`
on refusals — ddos-protection/src/lib.rs:328,335,377,384,418,523,882) and the protector's
cleanup telemetry shows live reputation entries (`"DDoS protection cleanup complete",…,"reputation_entries":1`
while traffic flows; 0 when idle). However there is **no observable live surface for the
counters**: the `ddos_*` Prometheus series are registered in the prometheus-crate registry
(`ddos-protection/src/metrics.rs` uses `register_int_counter_vec!`), which the api-server's
metrics-facade exporter (`:9090/metrics`) does not render — 0 `ddos_*` samples despite 42 WAF
decisions and the 429/403 refusals (OPS-5, filed). The detailed `debug!` outcome lines are
suppressed at `RUST_LOG=info`.

### 3.5 Log hygiene

Scanned every running container's logs (`docker logs --since 1h`) for 41 live secret values
collected from `.env` + `secrets/` and for secret shapes (`am_live_…`, `am_test_…`,
`postgres://…@`, `redis://…@`, JWTs, `"password":"…"`):

```console
candidate secrets: 41
HITS: none
SHAPE HITS: none
```

**PASS** — no live secret (including the API keys minted during this audit) appears in logs.

### 3.6 Backups — dry-run / fail-loud

**ClickHouse (before fix):**

```console
$ scripts/clickhouse-backup.sh --dry-run
Usage: … [backup|--list|--restore <dir>]      # no dry-run mode existed; unknown flag refused (exit 1)
$ CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=1 …  scripts/clickhouse-backup.sh   # inside the image with the client
ERROR: ClickHouse table listing failed (exit 210) — refusing to report a backup:
Code: 210. DB::NetException: Connection refused (127.0.0.1:1). (NETWORK_ERROR)
# no backup dir left behind
$ CLICKHOUSE_PORT=8123 …                        # the DOCUMENTED default
ERROR: … Connection reset by peer (127.0.0.1:8123)   # 8123 is HTTP; clickhouse-client needs native 9000
```

**After fix:** default port 9000, `--dry-run` added. Verified inside the running ClickHouse
container: `--dry-run` lists 10 tables, "Dry run complete: 10 tables would be backed up;
nothing was written." (0 files created); unreachable target still fails loudly with the
NETWORK_ERROR; a real backup to a temp dir produced a manifest + per-table schema/native pairs
(10 tables verified, 112K) and was not placed anywhere near real artifacts.

**Postgres (before fix):** no dry mode (the script runs `perform_backup` immediately), and on an
unreachable target it did fail loudly:

```console
$ POSTGRES_HOST=unreachable.invalid … sh deploy/hardening/scripts/postgres-backup-encrypt.sh
[backup-encrypt] starting backup of apexmail@unreachable.invalid
[backup-encrypt] ERROR: pg_dump failed (exit 1); stderr follows:
  pg_dump: error: could not translate host name "unreachable.invalid" …
exit=1 ; artifact files in BACKUP_DIR: 0
```

**After fix:** `--dry-run|-n` added (schema-only dump to a temp file, removed; no ciphertext, no
retention cleanup). Live: "Dry run complete: apexmail@127.0.0.1 reachable; nothing was written."
(0 artifacts). Unreachable: exit 1 with the pg_dump stderr.

### 3.7 SDKs against the live API with `template_id`

Template created in the live tenant (`POST /v1/templates`, then rendered per language):

```json
{"id":"os8ysad253bt9ocp039v7vqaig","subject":"SDK template 1791461257 for {{first_name}}",
 "html_body":"<h1>Hello {{first_name}}!</h1><p>Rendered by the ops SDK probe {{order_id}}.</p>", …}
```

One send per language, each `template_id` + `template_data`, recipient with a seeded marketing
consent record (the F4 send gate requires it for the default marketing category):

| SDK | call | API result | Mailpit rendered |
|-----|------|-----------|------------------|
| php | `$c->emails->send([...])` | queued `f40dbf8a-…` | subject `SDK template … for PHP`; body `Hello PHP! Rendered by the ops SDK probe SDK-PHP-…` |
| python | `c.emails.send(...)` | queued `3f5614d0-…` | `… for Python`; `Hello Python! … SDK-PY-…` |
| go | `client.Emails.Send(ctx, &SendEmailRequest{...})` | queued `0ed8b17d-…` | `… for Go`; `Hello Go! … SDK-GO-…` |
| ruby | `c.emails.send_email(...)` | queued `29b859b3-…` | `… for Ruby`; `Hello Ruby! … SDK-RB-…` |
| java | `client.emails().send(Map.of(...))` | queued `7472d8ab-…` | `… for Java`; `Hello Java! … SDK-JV-…` |

Local-environment notes (working as designed, not defects): the Python SDK needs `httpx` +
`pydantic`; the Go/Ruby/Java SDKs enforce HTTPS for non-localhost base URLs, so the local http
stack was fronted by a self-signed TLS terminator (`127.0.0.1:9443`, SAN=127.0.0.1) with the CA
injected per SDK (Go `HTTPClient` RootCAs, Ruby `SSL_CERT_FILE`, Java custom `HttpClient`);
PHP/Python allow `http://127.0.0.1` natively.

---

## Fixes (owned paths) with fail-before proofs

### F1 — locale whitelist (MK-1)
* `services/mail-server/crates/ui-foundation/src/axum_router.rs`: added the 63 missing
  `marketing_static_document` arms (179 arms now = 177 built pages + `/api-console`, `/aup`).
* The guard test was rewritten to **derive the expectation from the built output**
  (`std::fs` walk of `APX_MARKETING_PUBLIC_DIR`, 100+ page floor) instead of a handwritten list.
* Proof: `cargo test -p ui-foundation --lib every_built_marketing_document_is_served_with_and_without_slash` → **ok**;
  full `cargo test -p ui-foundation --lib` → **475 passed, 0 failed**.
* Fail-before: live walk showed the 63 404s; `tools/check_marketing_serving.py --root <HEAD-content fixture>`
  lists all 63 as un-whitelisted (below).

### F2 — security.txt + PGP keys (MK-3)
* `services/mail-server/crates/api-server/src/app.rs`: routed `/.well-known/security.txt`,
  `/pgp-key.asc`, `/pgp-key.txt` via `ServeFile`; added them to the cacheable tier.
* Tests: the asset test now asserts `200 OK` for `/css/styles.css` and for all three new routes.
* Proof: `cargo test -p api-server --lib marketing_static_assets_are_cacheable_but_pages_are_not` → **ok**.

### F3 — consent policy link locale (MK-4)
* `apps/marketing-zola/templates/partials/cookie-consent.html`: `href="{{ lp }}{{ …policy_path }}"`.
* `zola --root apps/marketing-zola build` regenerated the shipped HTML: `/de/cookies/`,
  `/fr/cookies/`, `/es/cookies/`, EN unchanged `/cookies/`.

### F4 — unreadable stylesheet (MK-2)
* `chmod 644` on `apps/marketing-zola/{public,static}/css/styles.css` (the live 0600 copy).
* `services/mail-server/Dockerfile`: `RUN chmod -R a+rX /app/apps/marketing-zola/public` after the
  copy, so a bad local umask can never ship a partially unreadable export.
* `tools/dev-start.sh`: `chmod 644 "$css_output"` right after the tailwind build.
* Test: the api-server asset test now fails on any root artifact without group/other read bits.
* Proof (fail-before): with styles.css temporarily 0600 the test fails with the exact production
  diagnosis — `…css/styles.css is mode 600; the api-server image runs as uid 10001 and cannot read it
  (live /css/styles.css 404s)`; restored to 644 it passes.

### F5 — api-server latency histogram buckets (OPS-1)
* `api-server/src/middleware/metrics.rs`: `REQUEST_DURATION_BUCKETS` +
  `configure_request_duration_buckets()`; `bin/server.rs` installs the recorder through it.
* Tests: `request_duration_is_exported_as_a_histogram_with_buckets` (renders a local recorder,
  asserts `# TYPE … histogram` + `_bucket` + `le` labels) and
  `server_binary_configures_the_request_duration_buckets` (pins the production wiring).
* Proof: `cargo test -p api-server --lib middleware::metrics::` → **4 passed**; `cargo test -p api-server --lib app::tests::` → **67 passed**.

### F6/F7 — backup scripts (OPS-6/7)
* `scripts/clickhouse-backup.sh`: default `CLICKHOUSE_PORT=9000` (native; 8123 is HTTP), new
  `--dry-run|-n` safe mode that proves connectivity/listing and writes nothing; documented.
* `deploy/hardening/scripts/postgres-backup-encrypt.sh`: new `--dry-run|-n` (schema-only dump to a
  removed temp file, no ciphertext/cleanup), exit 1 with pg_dump stderr on unreachable targets.
* Proof: `sh -n` on both; dry-run live/unreachable runs quoted in §3.6; real ClickHouse backup
  verified (10 tables) writing only to a temp dir.

### F8 — regression gate + hook
* New `tools/check_marketing_serving.py` (house style, `--self-test`): every built page is
  whitelisted, every required root artifact is world-readable, security.txt/PGP routes exist,
  the consent link is locale-prefixed, and the Dockerfile normalizes modes.
* `--self-test`: "all four checks can fail (mutants caught)".
* Fail-before/after pair: run against a fixture built from the pre-fix `HEAD` content for the
  four touched files (+ the 0600 stylesheet) → **exit 1** with all 63 pages + mode + 3 routes +
  Dockerfile + consent link; run against the fixed tree → **`marketing serving gate passed`**.
* Wired into `.pre-commit-config.yaml` (`marketing-serving-gate`, runs on marketing/api-server
  changes).

### Files changed by this audit
`services/mail-server/crates/ui-foundation/src/axum_router.rs`,
`services/mail-server/crates/api-server/src/{app.rs,bin/server.rs,middleware/metrics.rs}`,
`apps/marketing-zola/templates/partials/cookie-consent.html` (+ regenerated gitignored `public/`),
`services/mail-server/Dockerfile`, `tools/dev-start.sh`, `tools/check_marketing_serving.py` (new),
`scripts/clickhouse-backup.sh`, `deploy/hardening/scripts/postgres-backup-encrypt.sh`,
`.pre-commit-config.yaml`.
(The concurrent `docker-compose.yml`, `billing-service/plans.rs`, `enterprise/*` working-tree
changes belong to sibling agents; this audit did not touch them.)

## Filed findings — exact repro commands

* **OPS-2 tracking metrics (P2):**
  `docker exec apexmail-worker-1 wget -S -O - http://tracking:9092/metrics` → `Connection refused`
  (listener on container loopback; `METRICS_BIND_ADDR` unset). Fix: set `METRICS_BIND_ADDR: 0.0.0.0`
  for the tracking service in both compose files (infra partition).
* **OPS-3 enterprise metrics (P2):**
  `docker exec apexmail-worker-1 wget -S -O - http://enterprise:3008/metrics` → `401 Unauthorized`;
  handler admits loopback or bearer `METRICS_TOKEN`; `deploy/prometheus.yml` has no `authorization:`.
* **OPS-4 redis_\* (P3, UNREACHABLE):**
  `docker ps | grep -Ei "observability|redis-exporter"` → empty; observability is `profiles: [monitoring]`
  and its image is not built locally.
* **OPS-5 ddos metrics (P2):**
  `curl -s http://127.0.0.1:9090/metrics | grep -c '^ddos_'` → `0` after 42 WAF monitor verdicts
  and rate-limit refusals; `ddos-protection/src/metrics.rs` uses the prometheus-crate registry.
  Fix direction: port the ddos metrics to the `metrics` facade (or bridge registries).
* **OPS-8 admin abuse 500s (P2):**
  `POST /v1/admin/billing/abuse/reports/c408723c-…/resolve|review` → 500 (×3 in the last 6 min,
  `duration_ms` 2–3). Observed in `docker logs apexmail-api-server-1`; owned by the money/control-plane
  partition.
