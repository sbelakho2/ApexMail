<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Bot-detection telemetry scorer, mirroring the Rust crate's
 * `score_telemetry` (packages/kiwicaptcha/src/verify.rs) exactly.
 *
 * Returns true when the telemetry is characteristic of a bot, false for
 * human-like or benign signals.
 *
 * Hard rejection signals:
 *  1. webdriver flag set ("wd" == true).
 *  2. Solve takes > 300s total: beyond any expected solve while still
 *     allowing very slow hardware. There is deliberately NO "long solve
 *     with zero interaction" rule — the widget auto-solves with
 *     widget-local listeners, so a slow device or an Argon2id profile
 *     legitimately produces no events.
 *  3. >= 24 discrete event timings ("et") whose mean interval is >= 8ms
 *     with a coefficient of variation < 0.02. Bots simulate events with
 *     perfectly uniform intervals, which a person cannot produce.
 *
 * The check is deliberately conservative: it only considers *discrete*
 * events (pointerdown, non-repeat keydown, click; never coalesced
 * mousemove or OS key auto-repeat). A burst of sub-frame events that
 * rounds to identical millisecond timestamps is therefore never
 * misclassified; a mean below 8ms fails the gate.
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

        // 1. Solve takes >300s total (well beyond expected). There is
        //    deliberately NO "long solve with zero interaction" rule: the
        //    widget auto-solves and its listeners sit only on the widget,
        //    so a real user on a slow device (or an Argon2id profile)
        //    has no reason to interact and would be misclassified.
        // A negative duration cannot arrive over the wire (the token
        // decoder only accepts canonical digit strings), but a direct
        // caller could pass one; Rust's u64 cannot be negative, so clamp
        // to 0 for exact parity.
        if ($durationMs < 0) {
            $durationMs = 0;
        }
        if ($durationMs > 300_000) {
            return true;
        }

        // 2. Entropy check: uniform-interval discrete events reveal simulated
        //    interaction. Rust mirrors this arithmetic (mean, variance,
        //    coefficient of variation) bit-for-bit.
        if (isset($telemetry['et']) && \is_array($telemetry['et'])) {
            $diffs = [];
            $events = $telemetry['et'];
            $count = \count($events);
            for ($i = 1; $i < $count; $i++) {
                $t1 = $events[$i];
                $t0 = $events[$i - 1];
                // Rust's as_u64(): only non-negative integers count;
                // floats, strings and negatives are skipped exactly as
                // serde_json's u64 coercion would fail (a negative
                // timestamp breaks the pair chain instead of forming a
                // diff, which the earlier permissive check allowed).
                if (\is_int($t1) && \is_int($t0) && $t1 >= 0 && $t0 >= 0 && $t1 >= $t0) {
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

        return false;
    }

    private static function boolField(array $telemetry, string $key): bool
    {
        return \is_bool($telemetry[$key] ?? null) && $telemetry[$key];
    }
}
