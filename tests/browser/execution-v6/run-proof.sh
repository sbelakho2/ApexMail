#!/usr/bin/env bash
#
# run-proof.sh, the version-6 envelope fail-harness runner.
#
# Four legs over one deterministic synthetic corpus: the nonce is
# sha256 over the corpus index, the programs come from the real PHP
# generator at the real-platform rung.
#
#   oracle    the unchanged browserless forgery solver, the pure
#             state-machine oracle that forges every v1-v5 trace,
#             forges a trace per program with pure-sim placeholders;
#             the PHP envelope walker judges it. This leg rejects 100
#             percent only because the naive forger never implemented
#             the envelopes, that figure is NOT a full-knowledge number.
#   whitebox  the full-knowledge forger (WhiteBoxEnvelopeForger) that
#             reimplements the five published envelopes from the
#             open-source verifier and emits in-band entries without a
#             browser. This is the honest adversary under the red-team
#             program's full-knowledge rule; its pass rate is the true
#             number to publish. Version 6 costs one reading of the
#             source, the same class as v1-v5, NOT a browser boundary.
#   jsdom     the unmodified interpreter asset runs inside a fresh
#             jsdom window per program; the produced traces are judged
#             by the same walker.
#   happy-dom the same attempt under happy-dom.
#
# Each leg shards across 5 workers for the oracle and whitebox legs and
# 8 for the emulator legs; the per-attempt wall cost the emulator legs
# report is the Plane 8 full-fidelity-emulator cost figure. Requirements:
# php + the php-core vendor dev autoload (packages/kiwicaptcha-php),
# node + the jsdom and happy-dom dev dependencies of tests/browser.
#
# Usage: bash run-proof.sh [per-shard N]   (default 20000; the proof
# figure in docs/performance-analysis.md is the 5x20000 + 8x12500 +
# 8x12500 run = 10^5 programs per leg)
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PER_SHARD=${1:-20000}

for s in 0 1 2 3 4; do
  php "$HERE/oracle-leg.php" $((s * PER_SHARD)) "$PER_SHARD" > "/tmp/v6-proof-oracle-$s.json"
done
cat /tmp/v6-proof-oracle-*.json | php -r '
$t = 0; $r = 0; $ms = 0;
while ($line = fgets(STDIN)) { $d = json_decode($line, true); $t += $d["attempted"]; $r += $d["rejected"]; $ms += $d["wallMs"]; }
echo json_encode(["leg" => "oracle", "attempted" => $t, "rejected" => $r, "rejectionRate" => round($r / $t, 6), "wallMs" => $ms]), "\n";
'
rm -f /tmp/v6-proof-oracle-*.json

for s in 0 1 2 3 4; do
  php "$HERE/whitebox-leg.php" $((s * PER_SHARD)) "$PER_SHARD" > "/tmp/v6-proof-whitebox-$s.json"
done
cat /tmp/v6-proof-whitebox-*.json | php -r '
$t = 0; $p = 0; $ms = 0;
while ($line = fgets(STDIN)) { $d = json_decode($line, true); $t += $d["attempted"]; $p += $d["passed"]; $ms += $d["wallMs"]; }
echo json_encode(["leg" => "whitebox", "attempted" => $t, "passed" => $p, "rejected" => $t - $p, "passRate" => round($p / $t, 6), "rejectionRate" => round(($t - $p) / $t, 6), "wallMs" => $ms]), "\n";
'
rm -f /tmp/v6-proof-whitebox-*.json

EMULATOR_SHARD=$((PER_SHARD / 2))
for engine in jsdom happy-dom; do
  for s in 0 1 2 3 4 5 6 7; do
    (php "$HERE/corpus.php" $((s * EMULATOR_SHARD)) "$EMULATOR_SHARD" \
      | node "$HERE/emulator-leg.mjs" "$engine" 2>/dev/null \
      | php "$HERE/verify-leg.php" "$engine" > "/tmp/v6-proof-$engine-$s.json") &
  done
  wait
  cat /tmp/v6-proof-"$engine"-*.json | php -r '
    $t = 0; $r = 0; $p = 0; $c = 0; $ms = 0;
    while ($line = fgets(STDIN)) { $d = json_decode($line, true); $t += $d["attempted"]; $r += $d["rejected"]; $p += $d["produced"]; $c += $d["crashed"]; $ms += $d["msPerAttempt"] * $d["attempted"]; }
    echo json_encode(["leg" => $argv[1], "attempted" => $t, "produced" => $p, "crashed" => $c, "rejected" => $r, "rejectionRate" => round($r / $t, 6), "msPerAttempt" => round($ms / $t, 3)]), "\n";
  ' "$engine"
  rm -f /tmp/v6-proof-"$engine"-*.json
done
