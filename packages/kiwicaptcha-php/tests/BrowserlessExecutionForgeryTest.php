<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\BrowserlessForgerySolver;
use PHPUnit\Framework\TestCase;

/**
 * The browserless execution forgery regression oracle (lazy forger).
 *
 * The shadow solver must succeed on every pure-semantics grammar the
 * generator emits, versions 1 through 5, the causal object-graph rung
 * included. For every generated program the forged trace verifies and
 * digests at several chosen observed heights. The sweep pins the
 * forgeability boundary at the synthesis ceiling on purpose: the trace
 * of versions 1-5 is supplementary evidence, reproducible by any
 * implementation of the public semantics, never a browser attestation.
 *
 * Version 6 is rejected by this solver only because it emits the
 * pure-sim placeholders rather than the operand-derived envelope
 * entries. That 100 percent rejection is a lazy-forger number, NOT a
 * full-knowledge number. The white-box forger (WhiteBoxExecutionForgeryTest
 * / WhiteBoxEnvelopeForger) reimplements the five published envelopes
 * and passes every version-6 program without a browser — version 6
 * costs one reading of the source, the same class as versions 1-5, and
 * is NOT a browser boundary.
 */
final class BrowserlessExecutionForgeryTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';
    private const SCOPE = 'login';
    private const ACTION = 'login-action';
    /** The observed heights the oracle forges with: 1, 10, 17 and 255. */
    private const OBSERVED_HEIGHTS = [1, 10, 17, 255];
    /**
     * The highest rung the pure public semantics can reproduce: the
     * causal object-graph grammar. The real-platform rung (version 6)
     * sits above it and must make the oracle fail.
     */
    private const SOLVER_MAX_VERSION = 5;

    public function testBrowserlessShadowSolverForgesEveryPureSemanticsVersionTrace(): void
    {
        $solved = 0;
        for ($version = 1; $version <= self::SOLVER_MAX_VERSION; $version++) {
            for ($i = 0; $i < 100; $i++) {
                $label = sprintf('browserless-solver-v%d-%03d', $version, $i);
                $nonce = $this->nonceFor($label);
                $programB64 = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, $version);
                $decoded = ExecutionChallengeGenerator::decode($programB64);
                self::assertNotNull($decoded, 'every generated program must parse');
                self::assertSame($version, $decoded['op_version'], 'the corpus stays on its declared version');
                $digests = [];
                foreach (self::OBSERVED_HEIGHTS as $height) {
                    $trace = BrowserlessForgerySolver::solve($decoded, $height);
                    self::assertNotNull(
                        ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $trace),
                        sprintf('the forged trace of the v%d program must verify at height %d', $version, $height),
                    );
                    $digest = ExecutionChallengeGenerator::digestOverTrace($programB64, $nonce, $trace);
                    self::assertNotNull($digest, 'the forged trace must digest');
                    $digests[$height] = $digest;
                    $solved++;
                }
                // The observe choice flows into the evidence: different
                // heights change the digest of a version >= 2 program
                // (its mandatory observe entry) and leave the version-1
                // digest untouched (no observe opcode).
                if ($version >= 2) {
                    self::assertNotSame($digests[1], $digests[255], 'the chosen height must change the forged evidence');
                } else {
                    self::assertSame($digests[1], $digests[255], 'a version-1 trace carries no observe entry');
                }
            }
        }
        self::assertSame(
            100 * \count(self::OBSERVED_HEIGHTS) * self::SOLVER_MAX_VERSION,
            $solved,
            'the oracle solves 100 programs of every pure-semantics version at each observed height',
        );
    }

    public function testBrowserlessShadowSolverFailsOnTheRealPlatformRung(): void
    {
        // The version-6 envelope gate: 100 deterministic v6 programs,
        // each forged at every observed height, must be rejected
        // without exception. The solver has no real layout engine, no
        // real observer delivery and no real event path, so its
        // entries violate the operand-derived envelopes.
        $rejected = 0;
        $attempted = 0;
        for ($i = 0; $i < 100; $i++) {
            $label = sprintf('browserless-solver-v6-%03d', $i);
            $nonce = $this->nonceFor($label);
            $programB64 = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, 6);
            $decoded = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($decoded, 'every generated program must parse');
            self::assertSame(6, $decoded['op_version'], 'the corpus stays on the real-platform rung');
            foreach (self::OBSERVED_HEIGHTS as $height) {
                $trace = BrowserlessForgerySolver::solve($decoded, $height);
                $attempted++;
                if (ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $trace) === null) {
                    ++$rejected;
                }
            }
        }
        self::assertSame(400, $attempted, 'the sweep attempted every program at every height');
        self::assertSame(
            $attempted,
            $rejected,
            'the browserless oracle must fail on every version-6 program (a 100 percent rejection rate)',
        );
    }

    private function nonceFor(string $label): string
    {
        return base64_encode(hash('sha256', $label, true));
    }
}
