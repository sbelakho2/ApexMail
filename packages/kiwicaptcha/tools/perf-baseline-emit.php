<?php

declare(strict_types=1);

/**
 * Machine-readable baseline emission and read-back for the perf tools.
 *
 * The five timing tools (perf-bench.php, perf-bench-risk.php,
 * perf-load.php, perf-wait.php and perf-wait-replica.php) share this
 * helper. Each tool accepts --baseline-out with a target path and
 * merges its measured values into the committed record
 * tools/perf-baselines.json, the single source of truth for the
 * performance-analysis document. The merge is section-scoped: a tool
 * replaces only its own subtree and preserves every other section, so
 * running the five tools in sequence after a deliberate change
 * regenerates the record in place. The write is atomic (a temp file in
 * the same directory plus a rename), so an interrupted run never
 * leaves a truncated record. The record is updated only by hand on a
 * clean local machine with --baseline-out; the CI timing steps never
 * write it.
 *
 * The ratchets read the record back through perf_baseline_float(): the
 * tools compile no baseline constants, so the JSON is the single
 * baseline authority and a re-baselined record is the very file the
 * ratchets compare against. A missing leaf reads as the fallback
 * (0.0), which the tools report loudly as an unrecorded baseline
 * without failing. Under the $KIWI_STRICT_BASELINE=1 env flag a missing
 * timing-baseline leaf fails instead: a hard-ratchet run with no
 * baseline is not a hard ratchet. The noisy CI timing steps never set
 * the flag, so they keep the note degradation.
 */

function perf_baseline_read(string $file): array
{
    if (!is_file($file)) {
        return [];
    }
    $raw = (string) file_get_contents($file);
    if (trim($raw) === '') {
        return [];
    }
    try {
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new RuntimeException(sprintf('perf-baseline: %s is not valid JSON', $file));
    }

    return is_array($data) ? $data : [];
}

/**
 * Read a numeric leaf from the record at the given nested path. The
 * fallback is returned when the leaf is absent or not numeric, so a
 * partial record degrades to the unrecorded-baseline path instead of
 * a hard failure.
 *
 * @param list<string> $path
 */
function perf_baseline_float(string $file, array $path, float $fallback = 0.0): float
{
    $data = perf_baseline_read($file);
    $cursor = $data;
    foreach ($path as $key) {
        if (!is_array($cursor) || !array_key_exists($key, $cursor)) {
            return $fallback;
        }
        $cursor = $cursor[$key];
    }

    return is_int($cursor) || is_float($cursor) ? (float) $cursor : $fallback;
}

/**
 * Whether this run is a hard-ratchet run: $KIWI_STRICT_BASELINE=1 in
 * the environment. The manual workflow_dispatch perf-latency job sets
 * it, so a missing timing-baseline leaf fails that run instead of
 * degrading. The noisy CI timing steps run without it and keep the
 * note behavior.
 */
function perf_baseline_strict(): bool
{
    return getenv('KIWI_STRICT_BASELINE') === '1';
}

/**
 * Report a missing timing-baseline leaf. Under strict mode the missing
 * leaf is a hard failure (the tool returns false and the run exits
 * non-zero); otherwise it is the note degradation (returns true). The
 * tool name and the leaf label are spelled in the message either way.
 */
function perf_baseline_missing(string $tool, string $label): bool
{
    if (perf_baseline_strict()) {
        fwrite(STDERR, sprintf("%s FAILED: %s has no recorded baseline and this is a strict hard-ratchet run (KIWI_STRICT_BASELINE=1); record one with --baseline-out on a clean local machine\n", $tool, $label));

        return false;
    }
    fwrite(STDERR, sprintf("%s NOTE: %s has no recorded baseline; run with --baseline-out on a clean local machine to record one\n", $tool, $label));

    return true;
}

/**
 * Merge the measured values into the record at the given path and
 * write the file back atomically. The path is a nested key list; the
 * values replace the whole subtree at that path. The generated stamp
 * is refreshed on every write.
 *
 * @param list<string> $path
 */
function perf_baseline_emit(string $file, array $path, array $values): void
{
    $data = perf_baseline_read($file);
    $cursor = &$data;
    foreach ($path as $key) {
        if (!isset($cursor[$key]) || !is_array($cursor[$key])) {
            $cursor[$key] = [];
        }
        $cursor = &$cursor[$key];
    }
    $cursor = $values;
    unset($cursor);
    $data['generated'] = date('Y-m-d');
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    $tmp = $file.'.tmp'.getmypid();
    if (file_put_contents($tmp, $json) === false) {
        throw new RuntimeException(sprintf('perf-baseline: cannot write %s', $tmp));
    }
    if (!rename($tmp, $file)) {
        @unlink($tmp);
        throw new RuntimeException(sprintf('perf-baseline: cannot replace %s', $file));
    }
}
