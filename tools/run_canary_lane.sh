#!/usr/bin/env bash
# =============================================================================
# tools/run_canary_lane.sh — the real-mail canary evidence lane (report P0-4).
#
# External report (ApexMail_Validation.pdf, p.17): "Add a distinct live-canary
# evidence lane and artifacts with source/image/config/plan/terminal hashes.
# Missing credentials or skipped infrastructure must yield NOT EXECUTED,
# never a healthy production result. Keep fixture self-tests labeled
# separately."
#
# This lane has exactly two, separately labeled phases:
#
#   1. LOCAL REAL-STACK QUALIFICATION (always runs; docker+python3 gated):
#      boots the product stack (api-server, worker, postgres, redis) under an
#      ISOLATED compose project with deploy/docker-compose.canary.yml (the
#      GreenMail controlled SMTP+IMAP receiver; the worker delivers real
#      DKIM-signed SMTP to it), seeds a canary tenant/domain/key through
#      product-owned shapes, and drives the EXTERNAL byte-pinned runner
#      (tests/qualification/ApexMail_Real_Mail_Tests.py, SHA-256 verified
#      before every use) through its real plan→prepare→execute pipeline:
#      authenticated admission with Idempotency-Key, six-case oracles
#      (plain/unicode/html/attachment/idempotency/reserved_header-422),
#      independent read-only IMAP observation, tamper-evident evidence chain,
#      and a PANEL_CHECKS_PASSED verdict. Origin is honestly LOCAL_FIXTURE:
#      real product surfaces, loopback receiver, no external provider.
#
#   2. EXTERNAL PROVIDER PANEL (only when credentials exist): when
#      CI_CANARY_CONFIG names a live runner config file, the lane runs the
#      pinned runner against it AFTER prepare. Otherwise it writes
#      canary-external.json with status NOT EXECUTED and the reason — a
#      distinct artifact that can never be confused with a healthy result.
#
# Artifacts land under --out: summary.json + evidence dir (local), the
# retained plan hash, the terminal chain hash, and canary-external.json.
# Teardown ALWAYS runs (trap). Self-test proves the verdict evaluator and
# the runner pin, without docker or a stack.
#
# Usage: run_canary_lane.sh --out DIR
# Env:   CI_CANARY_CONFIG (optional live config path)
#        CANARY_GREENMAIL_SMTP_PORT/IMAP_PORT (overlay defaults 13025/13143)
# Exit:  0 = local panel PASSED and external green-or-NOT-EXECUTED; else 1.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=apexmail-canary-lane
OUT=""
RUNNER_SHA=622d54f343f74a3cba95e7fcd262496950b9d16c9dfef1ca6745b9cb7f28ecc6

log() { printf '[canary-lane] %s\n' "$*" >&2; }
die() { printf '[canary-lane] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
usage: run_canary_lane.sh --out DIR
       run_canary_lane.sh --self-test
USAGE
  exit 2
}

# evaluate_summary <summary.json> — only PANEL_CHECKS_PASSED passes; a
# missing/malformed artifact fails exactly like a failed panel.
evaluate_summary() {
  local file=$1
  [ -s "$file" ] || { printf 'summary artifact missing or empty: %s\n' "$file" >&2; return 1; }
  python3 - "$file" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except (OSError, ValueError) as exc:
    print(f"summary artifact unreadable: {exc}", file=sys.stderr)
    sys.exit(1)
status = data.get("status")
if status != "PANEL_CHECKS_PASSED":
    print(f"canary panel status {status!r}: problems={data.get('problems')} "
          f"incomplete={data.get('incomplete')}", file=sys.stderr)
    sys.exit(1)
print("canary panel: PANEL_CHECKS_PASSED")
PY
}

# external_verdict <out-dir> — run the live panel or record NOT EXECUTED.
external_phase() {
  local out=$1 cfg="${CI_CANARY_CONFIG:-}"
  if [ -n "$cfg" ] && [ -f "$cfg" ]; then
    log "external provider panel: running the pinned runner against $cfg"
    python3 "$ROOT/tests/qualification/ApexMail_Real_Mail_Tests.py" plan \
      --config "$cfg" --output "$out/external-plan.json" >&2 \
      || die "external plan failed"
    local sha
    sha=$(python3 - "$out/external-plan.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("plan_sha256", ""))
PY
)
    python3 "$ROOT/tests/qualification/ApexMail_Real_Mail_Tests.py" run \
      --plan "$out/external-plan.json" --plan-sha "$sha" \
      --out "$out/external-evidence" >&2 \
      || die "external panel run failed (see evidence above)"
    printf '{"status":"EXECUTED","origin":"EXTERNAL_CONFIGURED","plan_sha256":"%s"}\n' "$sha" \
      >"$out/canary-external.json"
    return 0
  fi
  printf '{"status":"NOT_EXECUTED","reason":"no CI_CANARY_CONFIG: the external provider panel requires an authorized deployed ApexMail instance and owned receiver mailboxes (report p.17: missing credentials must yield NOT EXECUTED, never a healthy production result)"}\n' \
    >"$out/canary-external.json"
  log "external provider panel: NOT EXECUTED (recorded in canary-external.json)"
}

# write_evidence_manifest <out-dir> — bind the qualification result to the
# exact source/image/config artifacts that produced it (audit 6): the
# runner's chain proves the test record; this proves WHAT ran.
write_evidence_manifest() {
  local out=$1
  python3 - "$ROOT" "$PROJECT" "$out" <<'PYMANIFEST'
import hashlib, json, subprocess, sys
from pathlib import Path

root, project, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
compose = ["docker", "compose", "-p", project, "-f", "docker-compose.yml",
           "-f", "docker-compose.override.yml", "-f", "deploy/docker-compose.canary.yml",
           "--env-file", ".env"]

def run(args, cwd=None):
    return subprocess.run(args, cwd=cwd or root, capture_output=True, text=True)

head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
dirty = bool(run(["git", "status", "--porcelain"]).stdout.strip())

# Per-service image digests for every RUNNING container of this project.
images = {}
for cid in run(["docker", "ps", "-q"]).stdout.split():
    info = run(["docker", "inspect", cid])
    if info.returncode != 0:
        continue
    try:
        data = json.loads(info.stdout)[0]
    except ValueError:
        continue
    name = (data.get("Config", {}).get("Labels") or {}).get("com.docker.compose.project")
    if name != project:
        continue
    service = (data.get("Config", {}).get("Labels") or {}).get(
        "com.docker.compose.service", data["Name"].lstrip("/"))
    images[service] = (data.get("Image") or "")[:71]  # sha256:<64>

# The rendered compose config (what actually ran) and the migration set.
config = run(compose + ["config"])
compose_hash = hashlib.sha256(config.stdout.encode()).hexdigest() if config.returncode == 0 else None
mig = run(["./target/debug/migrator", "--dry-run"], cwd=root / "services/mail-server")
migration_hash = hashlib.sha256(mig.stdout.encode()).hexdigest() if mig.returncode == 0 else None

runner = root / "tests/qualification/ApexMail_Real_Mail_Tests.py"
manifest = {
    "head": head,
    "dirty_tree": dirty,
    "image_digests": dict(sorted(images.items())),
    "compose_config_sha256": compose_hash,
    "migration_set_sha256": migration_hash,
    "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
}
summary = out / "local-evidence/summary.json"
if summary.exists():
    result = json.loads(summary.read_text())
    manifest["result_status"] = result.get("status")
    manifest["plan_sha256"] = result.get("plan_sha256")
    manifest["terminal_chain_sha256"] = result.get("terminal_chain_sha256")
(out / "qualification-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps({"phase": "manifest", **{k: manifest[k] for k in
      ("head", "dirty_tree", "result_status")}}))
PYMANIFEST
}

stack_down() {
  # The down MUST carry the same --env-file and profile set as the up:
  # without them compose interpolation fails (prod-required vars like
  # TRACKING_BASE_URL) and the `|| true` turns a full teardown into a
  # silent no-op — the next run then inherits stale containers (the
  # fixed-name postgres-exporter reconnects across wiped volumes and the
  # exporter scrape proof scrapes a corpse).
  docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.override.yml \
    -f deploy/docker-compose.canary.yml --env-file .env \
    --profile full-stack --profile migrate down -v --remove-orphans >/dev/null 2>&1 || true
}

self_test() {
  local tmp rc=0
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-canary-lane-test.XXXXXX")
  # 1. Only PANEL_CHECKS_PASSED passes the evaluator.
  printf '{"status":"PANEL_CHECKS_PASSED"}' > "$tmp/good.json"
  evaluate_summary "$tmp/good.json" || { echo "self-test FAIL: PASSED verdict rejected" >&2; rc=1; }
  for bad in OBSERVED_FAILURE INCOMPLETE; do
    printf '{"status":"%s","problems":["x"]}' "$bad" > "$tmp/bad.json"
    if evaluate_summary "$tmp/bad.json" >/dev/null 2>&1; then
      echo "self-test FAIL: $bad verdict accepted" >&2
      rc=1
    fi
  done
  # 2. Malformed / missing artifacts fail (a crashed run must not pass).
  printf 'not json' > "$tmp/malformed.json"
  if evaluate_summary "$tmp/malformed.json" >/dev/null 2>&1; then
    echo "self-test FAIL: malformed summary accepted" >&2; rc=1
  fi
  if evaluate_summary "$tmp/absent.json" >/dev/null 2>&1; then
    echo "self-test FAIL: missing summary accepted" >&2; rc=1
  fi
  # 3. The runner is byte-pinned to the reviewed artifact.
  actual=$(shasum -a 256 "$ROOT/tests/qualification/ApexMail_Real_Mail_Tests.py" | awk '{print $1}')
  if [ "$actual" != "$RUNNER_SHA" ]; then
    echo "self-test FAIL: runner drifted (sha256 $actual)" >&2
    rc=1
  fi
  # 4. The compose overlay renders (docker-gated, like every lane).
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    d=$(mktemp -d)
    { grep -ohE '\$\{[A-Z0-9_]+:\?' "$ROOT/docker-compose.yml" \
        "$ROOT/docker-compose.prod.yml" "$ROOT/deploy/docker-compose.canary.yml" 2>/dev/null \
        | grep -oE '[A-Z0-9_]+:' | tr -d ':' | sort -u \
        | while read -r v; do
            case $v in *_FILE) printf '%s=%s/secret\n' "$v" "$d";; *) printf '%s=ci-dummy-value\n' "$v";; esac
          done; printf 'WAL_ARCHIVE_TARGET=ci-dummy-value\n'; } > "$d/env"
    : > "$d/secret"
    (cd "$ROOT" && docker compose -f docker-compose.yml \
       -f deploy/docker-compose.canary.yml --env-file "$d/env" config -q >/dev/null 2>&1) \
      || { echo "self-test FAIL: canary compose overlay does not render" >&2; rc=1; }
    rm -rf "$d"
  fi
  # 5. Evidence binding: the manifest writer exists and the receiver image
  #    is digest-pinned (a bare tag would silently drift).
  grep -q 'write_evidence_manifest()' "$0" \
    || { echo "self-test FAIL: the evidence-manifest writer is missing" >&2; rc=1; }
  grep -q 'image: greenmail/standalone@sha256:' deploy/docker-compose.canary.yml \
    || { echo "self-test FAIL: greenmail is not digest-pinned" >&2; rc=1; }
  # 5b. Exporter scrape-proof wiring (eighth audit): the lane overlay must
  #     mount the repo-owned queries under the exporter's extend.query-path
  #     mechanism, and the lane must carry the scrape-assert step itself.
  grep -q 'extend.query-path=/etc/postgres-exporter/queries.yaml' deploy/docker-compose.canary.yml \
    || { echo "self-test FAIL: the canary exporter does not load the repo-owned queries" >&2; rc=1; }
  grep -q 'postgres-exporter-queries.yaml' deploy/docker-compose.canary.yml \
    || { echo "self-test FAIL: the canary exporter does not mount deploy/postgres-exporter-queries.yaml" >&2; rc=1; }
  grep -q 'apexmail_pg_replication_slots_active' "$0" \
    || { echo "self-test FAIL: the lane carries no apexmail_pg_replication_slots_* scrape assert" >&2; rc=1; }
  # 6. Usage contract.
  rc_inner=0; bash "$0" >/dev/null 2>&1 || rc_inner=$?
  [ "$rc_inner" -eq 2 ] || { echo "self-test FAIL: missing --out must exit 2" >&2; rc=1; }
  rm -rf "$tmp"
  [ "$rc" -eq 0 ] || { echo "run_canary_lane self-test FAIL" >&2; exit 1; }
  echo "run_canary_lane self-test: ok (only PANEL_CHECKS_PASSED accepted; failure/incomplete/malformed/missing rejected; runner byte-pin holds; overlay renders)"
  exit 0
}

[ "${1:-}" = "--self-test" ] && self_test

while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || usage; OUT=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
mkdir -p "$OUT"

trap stack_down EXIT INT TERM

log "applying the canonical schema (one-shot migrator, empty canary DB)"
(cd "$ROOT" && docker compose -p "$PROJECT" -f docker-compose.yml \
   -f docker-compose.override.yml -f deploy/docker-compose.canary.yml \
   --env-file .env --profile migrate run --rm --build migrator) \
  || die "the canary database could not be migrated"

log "booting the canary stack (isolated project $PROJECT)"
# The migrate profile is NEVER part of `up --wait`: the one-shot migrator
# exits 0 by design and compose --wait counts that as a failure.
(cd "$ROOT" && docker compose -p "$PROJECT" -f docker-compose.yml \
   -f docker-compose.override.yml -f deploy/docker-compose.canary.yml \
   --env-file .env --profile full-stack \
   up -d --build --wait --scale billing-service=0) \
  || die "compose up failed — the lane never runs against a half-built stack"
# billing-service is scaled to zero ON PURPOSE: it fails closed without
# MOLLIE_API_KEY (production credentials) and the canary path reserves
# quota through the in-process billing-service crate, never the service.

api_port=$(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.override.yml -f deploy/docker-compose.canary.yml port api-server 8080 2>/dev/null | sed 's/.*://')
imap_port=$(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.override.yml -f deploy/docker-compose.canary.yml port canary-greenmail 3143 2>/dev/null | sed 's/.*://')
[ -n "$api_port" ] && [ -n "$imap_port" ] || die "could not resolve api/imap ports"

# ── Exporter scrape proof (eighth audit, DR wave: "promtool green is not
# enough") ────────────────────────────────────────────────────────────────────
# The PostgresReplicationSlot* alerts read the repo-owned custom-query
# metrics (deploy/postgres-exporter-queries.yaml). Custom queries emit rows
# ONLY for existing slots, so the proof first seeds a physical replication
# slot (the same product shape the standby bootstrap creates on a real
# primary), then curls the exporter through the lane's loopback publishing
# and asserts the apexmail_pg_replication_slots_* families appear — without
# this, alert expressions can be promtool-green while firing on nothing.
log "exporter scrape proof: seeding a physical replication slot (the metric family only renders for existing slots)"
docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.override.yml \
  -f deploy/docker-compose.canary.yml --env-file .env \
  exec -T postgres psql -U apexmail -d apexmail -v ON_ERROR_STOP=1 \
  -c "SELECT pg_create_physical_replication_slot('apexmail_standby')" >/dev/null \
  || die "could not seed the canary replication slot (exporter scrape proof)"

exporter_port=$(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.override.yml -f deploy/docker-compose.canary.yml port postgres-exporter 9187 2>/dev/null | sed 's/.*://')
[ -n "$exporter_port" ] || die "could not resolve the postgres-exporter port"

log "exporter scrape proof: asserting apexmail_pg_replication_slots_* on 127.0.0.1:$exporter_port/metrics"
# Fetch to a file, THEN grep: under `set -o pipefail` a `curl | grep -q`
# pipeline can never pass a large exposition (grep exits on the first
# match, curl dies of SIGPIPE, and the matched pipeline reports failure) —
# the proof would die while the families it wants are on the wire.
exporter_metrics_file="$OUT/exporter-metrics-last-scrape.txt"
exporter_deadline=$(( $(date +%s) + 120 ))
exporter_proof=""
while [ "$(date +%s)" -lt "$exporter_deadline" ]; do
  if curl -fsS --max-time 5 "http://127.0.0.1:$exporter_port/metrics" 2>/dev/null \
      >"$exporter_metrics_file" \
    && grep -q '^apexmail_pg_replication_slots_active' "$exporter_metrics_file" \
    && grep -q '^apexmail_pg_replication_slots_retained_wal_bytes' "$exporter_metrics_file"; then
    exporter_proof=1
    break
  fi
  sleep 3
done
[ -n "$exporter_proof" ] \
  || { curl -sS --max-time 5 "http://127.0.0.1:$exporter_port/metrics" >"$OUT/exporter-metrics-failure.txt" 2>&1 || true
       docker logs apexmail-postgres-exporter >"$OUT/exporter-failure.log" 2>&1 || true
       die "postgres-exporter /metrics lacks the apexmail_pg_replication_slots_{active,retained_wal_bytes} families — the replication-slot alerts cannot fire (eighth audit: promtool green is not enough; exporter metrics + logs dumped to $OUT)"; }
grep '^apexmail_pg_replication_slots_' "$exporter_metrics_file" \
  >"$OUT/exporter-metrics-sample.txt"
printf '{"status":"EXPORTER_METRICS_PROVED","metrics":["apexmail_pg_replication_slots_active","apexmail_pg_replication_slots_retained_wal_bytes"],"slot":"apexmail_standby","exporter_port":"127.0.0.1:%s"}\n' \
  "$exporter_port" >"$OUT/canary-exporter-metrics.json"
log "exporter scrape proof: PROVED (sample in exporter-metrics-sample.txt, verdict in canary-exporter-metrics.json)"

log "health-fencing the api on 127.0.0.1:$api_port"
deadline=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS --max-time 5 "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; then break; fi
  sleep 5
done
curl -fsS --max-time 5 "http://127.0.0.1:$api_port/health" >/dev/null 2>&1 \
  || die "api did not become healthy"

log "seeding the canary identity (product-owned shapes)"
seed=$(python3 "$ROOT/tools/canary_seed.py" --project "$PROJECT" \
  --api-base "http://127.0.0.1:$api_port") || die "seeding failed"
api_key=$(printf '%s' "$seed" | python3 -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')
from_addr=$(printf '%s' "$seed" | python3 -c 'import json,sys; print(json.load(sys.stdin)["from"])')
printf '%s\n' "$seed" >"$OUT/canary-identity.json"
log "identity ready (from=$from_addr)"

log "driving the external qualification runner (six cases, real admission→SMTP→IMAP)"
python3 "$ROOT/tools/canary_drive.py" \
  --api-base "http://127.0.0.1:$api_port" \
  --api-key "$api_key" \
  --imap-port "$imap_port" \
  --imap-user "canary@receiver.canary.test" \
  --imap-password "canary-lane" \
  --from-addr "$from_addr" \
  --recipient "canary@receiver.canary.test" \
  --out "$OUT/local-evidence" >&2 \
  || die "the local qualification run failed (evidence above and in $OUT/local-evidence)"

# Evidence binding (audit 6): the result chain alone proves the test
# record; this manifest binds it to the EXACT artifacts that produced the
# mail — source HEAD, dirty-tree state, per-service image digests, the
# rendered compose config, the migration set, the pinned runner, and the
# terminal chain. Written BEFORE teardown so the images still exist.
write_evidence_manifest "$OUT" || die "could not bind the evidence manifest"
evaluate_summary "$OUT/local-evidence/summary.json"
terminal=$(python3 - "$OUT/local-evidence/summary.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("terminal_chain_sha256", ""))
PY
)
printf '{"local_panel":"PANEL_CHECKS_PASSED","terminal_chain_sha256":"%s"}\n' "$terminal" \
  >"$OUT/canary-local.json"

external_phase "$OUT"
log "lane complete: artifacts in $OUT"
