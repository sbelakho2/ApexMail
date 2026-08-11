<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Bot-detection telemetry scorer — mirrors the Rust crate's
 * `score_telemetry` (packages/kiwicaptcha/src/verify.rs) exactly.
 *
 * Returns true when the telemetry is characteristic of a bot, false for
 * human-like or benign signals.
 *
 * Hard rejection signals:
 *  1. webdriver flag set ("wd" == true).
 *  2. Solve completes in > 30s with zero mouse/key events (headless solver).
 *  3. Solve takes > 300s total (well beyond expected).
 *  4. >= 24 discrete event timings ("et") whose mean interval is >= 8ms with
 *     a coefficient of variation < 0.02 — bots simulate events with perfectly
 *     uniform intervals, which a person cannot produce.
 *
 * The check is deliberately conservative: it only considers *discrete*
 * events (pointerdown, non-repeat keydown, wheel, click — never coalesced
 * mousemove or OS key auto-repeat), so a burst of sub-frame events that
 * rounds to identical millisecond timestamps is never misclassified
 * (mean < 8ms fails the gate).
 */
final class Telemetry
{
    /**
     * @param array<string, mixed> $telemetry decoded telemetry JSON
     * @param int                  $durationMs client-reported solve duration
     */
    public static function score(array $telemetry, int $durationMs): bool
    {
        $wd = self::boolField($telemetry, 'wd');
        if ($wd) {
            return true;
        }

        $me = self::intField($telemetry, 'me');
        $ke = self::intField($telemetry, 'ke');
        $hc = self::intField($telemetry, 'hc');
        $dm = self::intField($telemetry, 'dm');
        $pl = self::intField($telemetry, 'pl');

        // 1. Solve completes in >30s with zero mouse/key events (headless solver).
        if ($durationMs > 30_000 && $me === 0 && $ke === 0) {
            return true;
        }

        // 2. Solve takes >300s total (well beyond expected).
        if ($durationMs > 300_000) {
            return true;
        }

        // 3. Entropy check: uniform-interval discrete events reveal simulated
        //    interaction. Rust mirrors this arithmetic (mean, variance,
        //    coefficient of variation) bit-for-bit.
        if (isset($telemetry['et']) && \is_array($telemetry['et'])) {
            $diffs = [];
            $events = $telemetry['et'];
            $count = \count($events);
            for ($i = 1; $i < $count; $i++) {
                $t1 = $events[$i];
                $t0 = $events[$i - 1];
                // Rust's as_u64(): only integers count; floats/strings are
                // skipped exactly as serde_json's u64 coercion would fail.
                if (\is_int($t1) && \is_int($t0) && $t1 >= $t0) {
                    $diffs[] = $t1 - $t0;
                }
            }

            if (\count($diffs) >= 23) {
                $sum = 0;
                foreach ($diffs as $d) {
                    $sum += $d;
                }
                $mean = $sum / \count($diffs);
                if ($mean >= 8.0) {
                    $variance = 0.0;
                    foreach ($diffs as $d) {
                        $diff = $d - $mean;
                        $variance += $diff * $diff;
                    }
                    $variance /= \count($diffs);
                    $cv = sqrt($variance) / $mean;
                    if ($cv < 0.02) {
                        return true;
                    }
                }
            }
        }

        // Soft signals (hc=0, dm=0 / hc=0, pl=0) are logged by the Rust
        // verifier but never rejected — the PHP port has no logger dependency,
        // so they are intentionally ignored here.

        return false;
    }

    private static function boolField(array $telemetry, string $key): bool
    {
        return \is_bool($telemetry[$key] ?? null) && $telemetry[$key];
    }

    private static function intField(array $telemetry, string $key): int
    {
        $v = $telemetry[$key] ?? null;

        return \is_int($v) ? $v : 0;
    }
}
