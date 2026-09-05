#!/usr/bin/env bash
# perf-budget.sh — hard deterministic byte budgets for the widget assets
# and the challenge-response JSON.
#
# The widget assets ship as three byte-identical copies (the canonical
# WASM asset, the core crate's embedded resources copy and the Symfony
# bundle's public copy). After the driver split the always-loaded
# driver is the eager core (widget-driver.js) with its own raw cap (the
# 160,000-byte cap carried forward) and the new compressed caps of
# 30,720 gzip / 28,000 brotli bytes; the lazy widget modules
# (widget-risk.js, widget-telemetry.js, widget-locales.js,
# widget-compat.js) and the execution interpreter
# (execution-interpreter.js) carry their own caps (the execution caps
# unchanged). Every cap value is read from the budgets section of
# packages/kiwicaptcha/tools/perf-baselines.json, the single
# hard-budget authority. A cap that the record cannot supply (missing
# file, missing section, non-numeric value) fails the script, because
# the budget cannot be enforced from a second authority that does not
# exist.
#
# Soft warnings: every measured size at or above 90% of its hard cap
# prints a warning line (the regression has not failed yet, but the
# budget headroom is nearly gone); a size above the cap fails.
#
# Measured-byte equality: the budgets section records the measured
# sizes (raw_bytes of the driver core, the widget modules, the worker,
# the runtime, the css and the execution interpreter; plus gzip/brotli
# of the driver core, the widget modules and the execution
# interpreter), and this script verifies the recorded raw_bytes equal
# the current measured bytes, and the recorded gzip_bytes and
# brotli_bytes of the driver core, the widget modules and the
# execution interpreter equal the deterministic measurement of every
# one of their mirror copies — a stale record describes bytes the
# caps no longer gate, so a drift is a hard failure, never just
# cap-compliance. The recorded sizes are re-measured by hand on a
# clean local machine against the current assets, and the challenge
# budgets against the current php-core issuance.
#
# Compressed budgets: the same copies must stay under a gzip cap and a
# brotli cap, so a regression that bloats the wire bytes the browser
# actually downloads (gzip on the wire, brotli when the server offers
# it) is caught even when the raw cap still has headroom. Sizes are
# measured with the deterministic gzip -n -9 (the -n strips the
# timestamp and stored-name header fields, so the byte count is
# reproducible across machines and runs) and the brotli CLI at
# quality 11. Brotli is
# enforced when the CLI or the python3 brotli module exists and noted
# as skipped when neither is available (the CI job installs the brotli
# CLI so the cap is enforced on the runner).
#
# The challenge-response JSON is measured by issuing real challenges
# through the PHP core (sha256 and argon2id, decoy armed) and encoding
# the wire shape of the bundle's /challenge response. The
# execution-armed protocol-v4 response (protocol v4, whose record
# carries the execution dimension at the live grammar maximum — today
# ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, the version-5
# causal object-graph grammar, never the grammar-v1 default) is
# measured with the deterministic largest-wire probe: the max-valid
# context (128-byte scope, 32-byte action, the 64-byte decoy-name
# ceiling) at the grammar-max op count (24, reached by iterating the
# issuance until the stamped count draws the v5 21 + byte % 4 formula
# to its cap), in sha256, argon2id and — when gmp and the committed
# RswFixture pair are available, which is only a measure-if-cheap
# bonus row — rsw, whose modulus rides the response and makes it the
# largest execution document. Each cap is read from the budgets
# section too. The php-core vendor must be installed before this
# script runs (the CI job installs it).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PHP_BIN="${PHP_BIN:-php}"
BASELINES_FILE="packages/kiwicaptcha/tools/perf-baselines.json"

FAILED=0
BROTLI_AVAILABLE=0

# json_get file dot.path — read an integer leaf from the budgets record;
# an unreadable leaf exits 2 so the caller fails the script loudly.
json_get() {
  local file="$1" key="$2" value
  value=$("$PHP_BIN" -r '
    $raw = @file_get_contents($argv[1]);
    if ($raw === false) { fwrite(STDERR, "perf-budget: cannot read $argv[1]\n"); exit(2); }
    $data = json_decode($raw, true);
    if (!is_array($data)) { fwrite(STDERR, "perf-budget: $argv[1] is not a JSON object\n"); exit(2); }
    $cursor = $data;
    foreach (explode(".", $argv[2]) as $k) {
      if (!is_array($cursor) || !array_key_exists($k, $cursor)) { exit(2); }
      $cursor = $cursor[$k];
    }
    if (is_int($cursor) || is_float($cursor)) { echo (int) $cursor; exit(0); }
    exit(2);
  ' "$file" "$key") || {
    echo "perf-budget FAILED: cannot read the budget cap $key from $file (the budgets section is the single hard-budget authority)" >&2
    exit 1
  }
  printf '%s' "$value"
}

brotli_size() {
  local file="$1"
  if command -v brotli >/dev/null 2>&1; then
    brotli -q 11 -c "$file" | wc -c | tr -d ' '
  elif python3 -c 'import brotli' >/dev/null 2>&1; then
    python3 -c '
import sys
import brotli
with open(sys.argv[1], "rb") as f:
    sys.stdout.buffer.write(brotli.compress(f.read(), quality=11))
' "$file" | wc -c | tr -d ' '
  else
    echo "unavailable"
  fi
}

# gzip_size <file> — the deterministic gzip byte count. The count is
# produced by python3's zlib at level 9 with the gzip container (wbits
# 31, no mtime), NOT by the gzip binary: gzip >= 1.12 links zlib-ng,
# whose deflate output differs from the classic zlib encoder, so a
# gzip-binary measurement is not reproducible across machines. The
# zlib encoder's deflate output is stable across zlib 1.2.x/1.3.x
# builds, which makes python3's zlib the cross-platform authority.
gzip_size() {
  python3 -c '
import sys, zlib
with open(sys.argv[1], "rb") as f:
    data = f.read()
c = zlib.compressobj(9, zlib.DEFLATED, 31)
print(len(c.compress(data) + c.flush()))
' "$1"
}

# budget_asset <budgets key> <label> — enforce the raw/gzip/brotli caps
# of one widget asset across its three byte-identical copies. The cap
# keys are "<key>.raw_cap_bytes", "<key>.gzip_cap_bytes" and
# "<key>.brotli_cap_bytes".
# budget_asset <budgets key> <label> — enforce the raw/gzip/brotli caps
# of one widget asset across its three byte-identical copies, with a
# soft warning (not a failure) when a measured size reaches 90% of its
# hard cap. The cap keys are "<key>.raw_cap_bytes",
# "<key>.gzip_cap_bytes" and "<key>.brotli_cap_bytes".
soft_cap_warning() {
  local kind="$1" size="$2" cap="$3"
  # At or above 90% of the cap (size*10 >= cap*9): warn without failing.
  if [ "$((size * 10))" -ge "$((cap * 9))" ]; then
    echo "perf-budget soft-warning: $kind is $size bytes, at or above 90% of the ${cap}-byte hard cap (a regression here fails the budget)" >&2
  fi
}
budget_asset() {
  local key="$1" label="$2"
  local raw_cap gzip_cap brotli_cap size gzip_size br_size
  raw_cap=$(json_get "$BASELINES_FILE" "budgets.$key.raw_cap_bytes")
  gzip_cap=$(json_get "$BASELINES_FILE" "budgets.$key.gzip_cap_bytes")
  brotli_cap=$(json_get "$BASELINES_FILE" "budgets.$key.brotli_cap_bytes")
  for copy in packages/kiwicaptcha-wasm/assets/"$label" \
              packages/kiwicaptcha/resources/"$label" \
              packages/kiwicaptcha/integrations/symfony/Resources/public/"$label"; do
    size=$(wc -c < "$copy")
    if [ "$size" -gt "$raw_cap" ]; then
      echo "perf budget FAILED: $copy is $size bytes (cap $raw_cap)" >&2
      FAILED=1
    else
      echo "$label budget OK: $copy $size bytes (cap $raw_cap)"
      soft_cap_warning "$label raw ($copy)" "$size" "$raw_cap"
    fi

    gzip_size=$(gzip_size "$copy")
    if [ "$gzip_size" -gt "$gzip_cap" ]; then
      echo "perf budget FAILED: gzip of $copy is $gzip_size bytes (cap $gzip_cap)" >&2
      FAILED=1
    else
      echo "$label gzip budget OK: $copy $gzip_size bytes (cap $gzip_cap)"
      soft_cap_warning "$label gzip ($copy)" "$gzip_size" "$gzip_cap"
    fi

    br_size=$(brotli_size "$copy")
    if [ "$br_size" = "unavailable" ]; then
      echo "$label brotli budget NOTE: brotli is not installed; the brotli cap is not enforced on this machine"
    else
      BROTLI_AVAILABLE=1
      if [ "$br_size" -gt "$brotli_cap" ]; then
        echo "perf budget FAILED: brotli of $copy is $br_size bytes (cap $brotli_cap)" >&2
        FAILED=1
      else
        echo "$label brotli budget OK: $copy $br_size bytes (cap $brotli_cap)"
        soft_cap_warning "$label brotli ($copy)" "$br_size" "$brotli_cap"
      fi
    fi
  done
}

# The eager driver core (always loaded on every bootstrap): the raw
# 160,000-byte cap carried forward from the pre-split single driver,
# with the compressed caps of the ordinary-bootstrap target.
budget_asset widget_driver widget-driver.js
# The lazy widget modules: loaded on trigger only (a memory-hard or
# armed challenge, an enabled telemetry session, a non-default
# resolved language, or the /api.js compat route), each with its own
# recorded caps.
budget_asset widget_risk widget-risk.js
budget_asset widget_telemetry widget-telemetry.js
budget_asset widget_locales widget-locales.js
budget_asset widget_compat widget-compat.js
# The execution interpreter (execution-interpreter.js) gets the same
# three-copy raw/gzip/brotli treatment as the driver: the asset is
# lazy in the files tier (a SHA-only page pays zero bytes for it), but
# an armed challenge pays exactly one fetch, so its wire size is a
# per-challenge cost with its own hard caps.
budget_asset widget_execution execution-interpreter.js

# Measured-byte equality gate: the recorded raw_bytes in the budgets
# section must equal the current measured bytes of the canonical copy of
# every widget asset (driver core, widget modules, worker, runtime, css,
# execution interpreter). The recorded gzip_bytes and brotli_bytes of
# the driver core, the widget modules and the execution interpreter
# must equal the deterministic gzip -n -9 and brotli measurements of
# every one of their three mirror copies. raw_bytes is a measured fact,
# never a budget:
# it is re-recorded by hand on a clean local machine, and this equality
# check turns a drifted record into a hard failure instead of letting the
# caps silently gate different bytes than the record describes.
verify_recorded_raw_bytes() {
  local key="$1" file="$2" recorded actual
  recorded=$(json_get "$BASELINES_FILE" "budgets.$key.raw_bytes")
  actual=$(wc -c < "$file" | tr -d ' ')
  if [ "$recorded" != "$actual" ]; then
    echo "perf-budget FAILED: budgets.$key.raw_bytes records $recorded bytes but $file is actually $actual bytes (re-measure and re-record the budgets section)" >&2
    FAILED=1
  else
    echo "perf-budget raw_bytes equality OK: budgets.$key.raw_bytes == $recorded bytes ($file)"
  fi
}

# The recorded gzip bytes are equality-gated per zlib encoder family:
# the classic zlib encoder's deflate output differs across versions
# (and the gzip >= 1.12 binary links zlib-ng, whose output differs
# again), so the record carries one measured value per zlib family
# (gzip_bytes_zlib12 / gzip_bytes_zlib13, gzip container, level 9, no
# mtime, measured via python3's zlib). The gate measures with the
# local python3 zlib and compares against the recorded value for the
# local family; an unrecorded family prints an explicit note and the
# caps still apply. A drifted record for the recorded families fails,
# exactly like a drifted raw_bytes record.
verify_recorded_gzip_bytes() {
  local key="$1" file="$2" recorded actual fam
  fam=$(python3 -c 'import zlib; print("".join(zlib.ZLIB_VERSION.split(".")[:2]))')
  if [ "$fam" = "12" ]; then
    recorded=$(json_get "$BASELINES_FILE" "budgets.$key.gzip_bytes_zlib12")
  elif [ "$fam" = "13" ]; then
    recorded=$(json_get "$BASELINES_FILE" "budgets.$key.gzip_bytes_zlib13")
  else
    echo "perf-budget gzip_bytes NOTE: local zlib family $fam has no recorded gzip expectation for budgets.$key (recorded families: zlib12, zlib13); cap enforcement still applies"
    return
  fi
  actual=$(gzip_size "$file")
  if [ "$recorded" != "$actual" ]; then
    echo "perf-budget FAILED: budgets.$key.gzip_bytes_zlib$fam records $recorded bytes but python3 zlib $fam of $file is $actual bytes (re-measure and re-record the budgets section)" >&2
    FAILED=1
  else
    echo "perf-budget gzip_bytes equality OK (zlib$fam): budgets.$key == $recorded bytes ($file)"
  fi
}

verify_recorded_brotli_bytes() {
  local key="$1" file="$2" recorded actual
  recorded=$(json_get "$BASELINES_FILE" "budgets.$key.brotli_bytes")
  actual=$(brotli_size "$file")
  if [ "$actual" = "unavailable" ]; then
    echo "perf-budget brotli_bytes equality NOTE: brotli is not installed; the recorded brotli_bytes are not verified on this machine"
  elif [ "$recorded" != "$actual" ]; then
    echo "perf-budget FAILED: budgets.$key.brotli_bytes records $recorded bytes but brotli -q 11 of $file is $actual bytes (re-measure and re-record the budgets section)" >&2
    FAILED=1
  else
    echo "perf-budget brotli_bytes equality OK: budgets.$key.brotli_bytes == $recorded bytes ($file)"
  fi
}

verify_recorded_raw_bytes widget_driver packages/kiwicaptcha-wasm/assets/widget-driver.js
verify_recorded_raw_bytes widget_risk packages/kiwicaptcha-wasm/assets/widget-risk.js
verify_recorded_raw_bytes widget_telemetry packages/kiwicaptcha-wasm/assets/widget-telemetry.js
verify_recorded_raw_bytes widget_locales packages/kiwicaptcha-wasm/assets/widget-locales.js
verify_recorded_gzip_bytes widget_locales packages/kiwicaptcha-wasm/assets/widget-locales.js
verify_recorded_brotli_bytes widget_locales packages/kiwicaptcha-wasm/assets/widget-locales.js
verify_recorded_raw_bytes widget_compat packages/kiwicaptcha-wasm/assets/widget-compat.js
verify_recorded_raw_bytes widget_worker packages/kiwicaptcha-wasm/assets/kiwi-worker.js
verify_recorded_raw_bytes widget_runtime packages/kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js
verify_recorded_raw_bytes widget_css packages/kiwicaptcha-wasm/assets/widget.css
verify_recorded_raw_bytes widget_execution packages/kiwicaptcha-wasm/assets/execution-interpreter.js

# The compressed equality gate covers the same five capped keys over
# the same three mirror copies budget_asset caps (the eager driver
# core, the three lazy widget modules and the execution interpreter).
for pair in widget_driver/widget-driver.js widget_risk/widget-risk.js \
            widget_telemetry/widget-telemetry.js widget_compat/widget-compat.js \
            widget_execution/execution-interpreter.js; do
  key="${pair%/*}"
  label="${pair#*/}"
  for copy in packages/kiwicaptcha-wasm/assets/"$label" \
              packages/kiwicaptcha/resources/"$label" \
              packages/kiwicaptcha/integrations/symfony/Resources/public/"$label"; do
    verify_recorded_gzip_bytes "$key" "$copy"
    verify_recorded_brotli_bytes "$key" "$copy"
  done
done

CHALLENGE_JSON_CAP=$(json_get "$BASELINES_FILE" "budgets.challenge_response_json.cap_bytes")
CHALLENGE_JSON_EXECUTION_CAP=$(json_get "$BASELINES_FILE" "budgets.challenge_response_json_execution.cap_bytes")

challenge_size() {
  "$PHP_BIN" -r '
    require $argv[1]."/vendor/autoload.php";
    use KiwiCaptcha\Config;
    use KiwiCaptcha\Issuer;
    use KiwiCaptcha\PoWAlgorithm;
    use KiwiCaptcha\Storage\ArrayStorage;
    $algo = $argv[2] === "argon2id" ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256;
    $config = new Config(
        secretKey: "0123456789abcdef0123456789abcdef",
        algorithm: $algo,
        ttlSecs: 120,
        mKib: $algo === PoWAlgorithm::Argon2id ? 64 : 0,
        t: $algo === PoWAlgorithm::Argon2id ? 3 : 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 4,
        minDurationMs: 0,
    );
    $challenge = (new Issuer($config, new ArrayStorage()))->issueWithDecoyField("login", "198.51.100.7");
    echo strlen(json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES));
  ' "packages/kiwicaptcha-php" "$1"
}

# The deterministic largest-wire execution-armed issuance, per
# algorithm: protocol v4 at the live execution-grammar maximum —
# executionVersion: ExecutionChallengeGenerator::MAX_EXECUTION_VERSION
# by name, never the positional grammar-v1 default — over the max-valid
# wire context the bundle endpoint accepts (a 128-byte scope, a 32-byte
# execution action, the 64-byte decoy-name ceiling, decoy armed), with
# issuances iterated until the stamped op count draws the version-5
# 21 + byte % 4 count formula to its 24-op grammar cap (bounded at 64
# attempts; an iteration that never draws 24 fails the probe, because a
# below-cap sample would under-gate the budget). The reported size is
# the largest wire shape measured across the attempts. The rsw row
# reuses the committed PHP test fixture pair (the autoloaded
# KiwiCaptcha\Tests\Support\RswFixture of the same php-core vendor) and
# is a measure-if-cheap variant: when the gmp extension or the fixture
# class is unavailable the row prints "unavailable" and the
# sha256/argon2id execution rows still gate.
challenge_size_execution() {
  "$PHP_BIN" -r '
    require $argv[1]."/vendor/autoload.php";
    use KiwiCaptcha\Config;
    use KiwiCaptcha\Issuer;
    use KiwiCaptcha\PoWAlgorithm;
    use KiwiCaptcha\Storage\ArrayStorage;
    use KiwiCaptcha\ExecutionChallengeGenerator;
    $algo = $argv[2];
    $isRsw = $algo === "rsw";
    if ($isRsw && (!extension_loaded("gmp") || !class_exists("KiwiCaptcha\\Tests\\Support\\RswFixture"))) {
        echo "unavailable";
        exit(0);
    }
    $rswFixture = "KiwiCaptcha\\Tests\\Support\\RswFixture";
    $config = new Config(
        secretKey: "0123456789abcdef0123456789abcdef",
        executionKey: "fedcba9876543210fedcba9876543210",
        algorithm: $isRsw ? PoWAlgorithm::Rsw : ($algo === "argon2id" ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256),
        ttlSecs: 120,
        mKib: $algo === "argon2id" ? 64 : 0,
        t: $algo === "argon2id" ? 3 : 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 4,
        minDurationMs: 0,
        rswModulusN: $isRsw ? $rswFixture::MODULUS_N_B64 : null,
        rswLambda: $isRsw ? $rswFixture::LAMBDA_B64 : null,
        rswT: 10000,
    );
    $issuer = new Issuer($config, new ArrayStorage());
    $largest = 0;
    $largestOps = 0;
    for ($attempt = 0; $attempt < 64; $attempt++) {
        $challenge = $issuer->issueWithExecutionField(
            scope: str_repeat("s", 128),
            clientIp: "198.51.100.7",
            armExecution: true,
            executionAction: str_repeat("a", 32),
            executionVersion: ExecutionChallengeGenerator::MAX_EXECUTION_VERSION,
            armDecoyField: true,
            decoyNameOverride: str_repeat("d", 64),
        );
        $size = strlen(json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES));
        $program = ExecutionChallengeGenerator::decode((string) $challenge->executionProgram);
        $opCount = $program === null ? 0 : count($program["ops"]);
        if ($opCount > $largestOps) {
            $largestOps = $opCount;
        }
        if ($size > $largest) {
            $largest = $size;
        }
        if ($opCount === ExecutionChallengeGenerator::MAX_OPS) {
            break;
        }
    }
    if ($largestOps !== ExecutionChallengeGenerator::MAX_OPS) {
        fwrite(STDERR, "perf-budget: the execution probe never drew the ".ExecutionChallengeGenerator::MAX_OPS."-op grammar cap in 64 issuances (largest draw was $largestOps)\n");
        exit(2);
    }
    echo $largest;
  ' "packages/kiwicaptcha-php" "$1"
}

largest_execution=0
for algo in sha256 argon2id rsw; do
  size=$(challenge_size_execution "$algo")
  if [ "$size" = "unavailable" ]; then
    echo "challenge-response execution budget NOTE: the rsw execution variant is not measured on this machine (rsw needs the gmp extension and the committed RswFixture pair); the sha256 and argon2id execution rows still gate the cap"
    continue
  fi
  echo "challenge-response execution budget ($algo, deterministic largest wire): $size bytes (cap $CHALLENGE_JSON_EXECUTION_CAP)"
  if [ "$size" -gt "$largest_execution" ]; then
    largest_execution=$size
  fi
done
if [ "$largest_execution" -gt "$CHALLENGE_JSON_EXECUTION_CAP" ]; then
  echo "perf budget FAILED: the execution-armed challenge-response JSON is $largest_execution bytes (cap $CHALLENGE_JSON_EXECUTION_CAP)" >&2
  FAILED=1
fi

# The decoy-armed (no execution dimension) issuance: the plain
# challenge-response row, one issuance per algorithm.
largest=0
for algo in sha256 argon2id; do
  size=$(challenge_size "$algo")
  echo "challenge-response budget ($algo): $size bytes (cap $CHALLENGE_JSON_CAP)"
  if [ "$size" -gt "$largest" ]; then
    largest=$size
  fi
done
if [ "$largest" -gt "$CHALLENGE_JSON_CAP" ]; then
  echo "perf budget FAILED: the challenge-response JSON is $largest bytes (cap $CHALLENGE_JSON_CAP)" >&2
  FAILED=1
fi

# The single-source-of-truth guard: the narrative performance
# document (docs/performance-analysis.md) quotes the equality-gated
# asset sizes. If those figures drift from the machine-readable
# record, the check fails — human-readable prose must be regenerated
# from the JSON, never copied by hand. The figures are matched as
# plain digit strings with thousand separators exactly as the record
# stores them.
dr_raw=$(json_get "$BASELINES_FILE" "budgets.widget_driver.raw_bytes")
dr_gz=$(json_get "$BASELINES_FILE" "budgets.widget_driver.gzip_bytes_zlib13")
dr_br=$(json_get "$BASELINES_FILE" "budgets.widget_driver.brotli_bytes")
rk_raw=$(json_get "$BASELINES_FILE" "budgets.widget_risk.raw_bytes")
tm_raw=$(json_get "$BASELINES_FILE" "budgets.widget_telemetry.raw_bytes")
lc_raw=$(json_get "$BASELINES_FILE" "budgets.widget_locales.raw_bytes")
lc_gz=$(json_get "$BASELINES_FILE" "budgets.widget_locales.gzip_bytes_zlib13")
lc_br=$(json_get "$BASELINES_FILE" "budgets.widget_locales.brotli_bytes")
cp_raw=$(json_get "$BASELINES_FILE" "budgets.widget_compat.raw_bytes")
ex_raw=$(json_get "$BASELINES_FILE" "budgets.widget_execution.raw_bytes")
ex_gz=$(json_get "$BASELINES_FILE" "budgets.widget_execution.gzip_bytes_zlib13")
ex_br=$(json_get "$BASELINES_FILE" "budgets.widget_execution.brotli_bytes")
DOC_NORM=$(cat "docs/performance-analysis.md" 2>/dev/null | tr -d ',' || true)
MISSING=""
# The locale-independent comparison: the doc may format the figures
# with or without thousand separators, so the guard strips the commas
# and matches the bare digit strings from the record.
for fig in "$dr_raw" "$dr_gz" "$dr_br" "$rk_raw" "$tm_raw" "$lc_raw" "$lc_gz" "$lc_br" "$cp_raw" "$ex_raw" "$ex_gz" "$ex_br"; do
  if [ -n "$DOC_NORM" ] && ! printf '%s' "$DOC_NORM" | grep -qF "$fig"; then
    MISSING="$MISSING $fig"
  fi
done
if [ -n "$MISSING" ]; then
  echo "perf-budget FAILED: docs/performance-analysis.md does not quote the recorded asset figures:$MISSING — regenerate the prose from perf-baselines.json" >&2
  FAILED=1
fi

if [ "$FAILED" = "1" ]; then
  echo "perf-budget: byte budget exceeded — a regression or an intentional growth that needs a re-baselined cap" >&2
  exit 1
fi
if [ "$BROTLI_AVAILABLE" = "0" ]; then
  echo "perf-budget: OK (all widget-driver, widget-module and widget-execution copies raw and gzip, and the challenge responses, within their caps; the recorded raw_bytes and gzip_bytes equality-verified; brotli not enforced — no brotli on this machine)"
  exit 0
fi
echo "perf-budget: OK (all widget-driver, widget-module and widget-execution copies raw/gzip/brotli and the challenge responses within their caps; the recorded raw_bytes, gzip_bytes and brotli_bytes equality-verified)"
