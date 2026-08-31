#!/usr/bin/env bash
# perf-budget.sh — hard deterministic byte budgets for the widget assets
# and the challenge-response JSON.
#
# The three widget-driver copies (the canonical WASM asset, the core
# crate's embedded resources copy and the Symfony bundle's public copy)
# must each stay under the widget-driver cap. The cap values are not
# defined here: the shell reads them from the budgets section of
# packages/kiwicaptcha/tools/perf-baselines.json, the single hard-budget
# authority. A cap that the record cannot supply (missing file, missing
# section, non-numeric value) fails the script, because the budget
# cannot be enforced from a second authority that does not exist.
#
# Measured-byte equality: the budgets section records the measured
# sizes (raw_bytes of the widget driver, worker, runtime and css; plus
# gzip/brotli of the driver), and this script verifies the recorded
# raw_bytes equal the current measured bytes — a stale record describes
# bytes the caps no longer gate, so a drift is a hard failure, never
# just cap-compliance. The recorded sizes are re-measured by hand on a
# clean local machine (the eager-import removal regenerated them against
# the current assets).
#
# Compressed budgets: the same three copies must stay under a gzip cap
# and a brotli cap, so a regression that bloats the wire bytes the
# browser actually downloads (gzip on the wire, brotli when the server
# offers it) is caught even when the raw cap still has headroom. The
# caps are read from the same budgets section. Brotli is enforced when
# the CLI or the python3 brotli module exists and noted as skipped when
# neither is available (the CI job installs the brotli CLI so the cap is
# enforced on the runner).
#
# The challenge-response JSON is measured by issuing real challenges
# through the PHP core (sha256 and argon2id, decoy armed) and encoding
# the wire shape of the bundle's /challenge response. Its cap is read
# from the budgets section too. The php-core vendor must be installed
# before this script runs (the CI job installs it).
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

WIDGET_DRIVER_CAP=$(json_get "$BASELINES_FILE" "budgets.widget_driver.raw_cap_bytes")
WIDGET_DRIVER_GZIP_CAP=$(json_get "$BASELINES_FILE" "budgets.widget_driver.gzip_cap_bytes")
WIDGET_DRIVER_BROTLI_CAP=$(json_get "$BASELINES_FILE" "budgets.widget_driver.brotli_cap_bytes")
CHALLENGE_JSON_CAP=$(json_get "$BASELINES_FILE" "budgets.challenge_response_json.cap_bytes")

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

for copy in packages/kiwicaptcha-wasm/assets/widget-driver.js \
            packages/kiwicaptcha/resources/widget-driver.js \
            packages/kiwicaptcha/integrations/symfony/Resources/public/widget-driver.js; do
  size=$(wc -c < "$copy")
  if [ "$size" -gt "$WIDGET_DRIVER_CAP" ]; then
    echo "perf budget FAILED: $copy is $size bytes (cap $WIDGET_DRIVER_CAP)" >&2
    FAILED=1
  else
    echo "widget-driver budget OK: $copy $size bytes (cap $WIDGET_DRIVER_CAP)"
  fi

  gzip_size=$(gzip -c "$copy" | wc -c | tr -d ' ')
  if [ "$gzip_size" -gt "$WIDGET_DRIVER_GZIP_CAP" ]; then
    echo "perf budget FAILED: gzip of $copy is $gzip_size bytes (cap $WIDGET_DRIVER_GZIP_CAP)" >&2
    FAILED=1
  else
    echo "widget-driver gzip budget OK: $copy $gzip_size bytes (cap $WIDGET_DRIVER_GZIP_CAP)"
  fi

  br_size=$(brotli_size "$copy")
  if [ "$br_size" = "unavailable" ]; then
    echo "widget-driver brotli budget NOTE: brotli is not installed; the brotli cap is not enforced on this machine"
  else
    BROTLI_AVAILABLE=1
    if [ "$br_size" -gt "$WIDGET_DRIVER_BROTLI_CAP" ]; then
      echo "perf budget FAILED: brotli of $copy is $br_size bytes (cap $WIDGET_DRIVER_BROTLI_CAP)" >&2
      FAILED=1
    else
      echo "widget-driver brotli budget OK: $copy $br_size bytes (cap $WIDGET_DRIVER_BROTLI_CAP)"
    fi
  fi
done

# Measured-byte equality gate: the recorded raw_bytes in the budgets
# section must equal the current measured bytes of the canonical copy of
# every widget asset (driver, worker, runtime, css). raw_bytes is a
# measured fact, never a budget: it is re-recorded by hand on a clean
# local machine, and this equality check turns a drifted record into a
# hard failure instead of letting the caps silently gate different bytes
# than the record describes.
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

verify_recorded_raw_bytes widget_driver packages/kiwicaptcha-wasm/assets/widget-driver.js
verify_recorded_raw_bytes widget_worker packages/kiwicaptcha-wasm/assets/kiwi-worker.js
verify_recorded_raw_bytes widget_runtime packages/kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js
verify_recorded_raw_bytes widget_css packages/kiwicaptcha-wasm/assets/widget.css

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

if [ "$FAILED" = "1" ]; then
  echo "perf-budget: byte budget exceeded — a regression or an intentional growth that needs a re-baselined cap" >&2
  exit 1
fi
if [ "$BROTLI_AVAILABLE" = "0" ]; then
  echo "perf-budget: OK (all widget-driver copies raw and gzip, and the challenge response, within their caps; brotli not enforced — no brotli on this machine)"
  exit 0
fi
echo "perf-budget: OK (all widget-driver copies raw/gzip/brotli and the challenge response within their caps)"
