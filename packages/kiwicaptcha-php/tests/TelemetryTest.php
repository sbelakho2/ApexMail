<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Telemetry;
use PHPUnit\Framework\TestCase;

/**
 * Mirrors the Rust crate's score_telemetry test suite
 * (packages/kiwicaptcha/src/verify.rs) 1:1.
 */
final class TelemetryTest extends TestCase
{
    public function testHumanLikeTelemetryPasses(): void
    {
        // Rust: t1 = {"wd": false, "me": 20, "ke": 0}
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0], 5_000));
    }

    public function testWebdriverRejected(): void
    {
        self::assertTrue(Telemetry::score(['wd' => true], 5_000));
    }

    public function testTooSlowRejected(): void
    {
        self::assertTrue(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0], 301_000));
    }

    public function testZeroInteractionLongSolveRejected(): void
    {
        self::assertTrue(Telemetry::score(['wd' => false, 'me' => 0, 'ke' => 0], 31_000));
    }

    public function testZeroInteractionShortSolvePasses(): void
    {
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 0, 'ke' => 0], 5_000));
    }

    public function testUniformTimingBotRejected(): void
    {
        // 30 discrete events at perfectly uniform 100ms intervals:
        // mean = 100ms >= 8ms, CV = 0 < 0.02.
        $uniform = [];
        for ($i = 0; $i < 30; $i++) {
            $uniform[] = 100 + $i * 100;
        }
        self::assertTrue(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0, 'et' => $uniform], 5_000));
    }

    public function testHumanJitteredTimingPasses(): void
    {
        // Rust: i * 97 + (i * 7 % 13) — intervals alternate between 91ms and
        // 104ms, so the coefficient of variation is well above 0.02.
        $jittered = [];
        for ($i = 0; $i < 30; $i++) {
            $jittered[] = $i * 97 + ($i * 7 % 13);
        }
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0, 'et' => $jittered], 5_000));
    }

    public function testSubFrameEventsPass(): void
    {
        // 1-2ms diffs: coalesced events can round to identical millisecond
        // timestamps; the mean (2ms) is below the 8ms gate.
        $subframe = [];
        for ($i = 0; $i < 30; $i++) {
            $subframe[] = $i * 2;
        }
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0, 'et' => $subframe], 5_000));
    }

    public function testSparseHumanEventsPass(): void
    {
        // High-variance intervals far from any uniform pattern.
        $sparse = [];
        for ($i = 0; $i < 30; $i++) {
            $sparse[] = $i * 143 + ($i * 11 % 37);
        }
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0, 'et' => $sparse], 5_000));
    }

    public function testFewerThan24EventsNeverRejected(): void
    {
        $uniform = [];
        for ($i = 0; $i < 20; $i++) {
            $uniform[] = 100 + $i * 100;
        }
        self::assertFalse(Telemetry::score(['wd' => false, 'me' => 20, 'ke' => 0, 'et' => $uniform], 5_000));
    }

    public function testMissingFieldsDefaultToZero(): void
    {
        // Rust: as_u64() on a missing key yields 0.
        self::assertTrue(Telemetry::score([], 31_000), 'missing me/ke must default to 0');
        self::assertFalse(Telemetry::score([], 5_000));
    }

    public function testNonIntegerEventTimingsAreSkippedLikeAsU64(): void
    {
        // Rust's as_u64() rejects floats; the PHP port must mirror that by
        // ignoring them, never casting.
        $mixed = [100.0, 200.0, 300.0];
        self::assertFalse(Telemetry::score(['et' => $mixed], 5_000));
    }

    public function testDecreasingTimestampsAreSkipped(): void
    {
        // t1 >= t0 is required; decreasing pairs are dropped (Rust skips them).
        $decreasing = [];
        for ($i = 0; $i < 30; $i++) {
            $decreasing[] = 3_000 - $i * 100;
        }
        self::assertFalse(Telemetry::score(['et' => $decreasing], 5_000));
    }

    public function testStringFieldsAreIgnored(): void
    {
        // as_bool()/as_u64() fail on strings => defaults used.
        self::assertFalse(Telemetry::score(['wd' => 'true', 'me' => '20'], 5_000));
    }
}
