<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\BrowserlessForgerySolver;
use PHPUnit\Framework\TestCase;

/**
 * The browserless execution forgery regression oracle.
 *
 * The shadow solver must succeed on every live grammar the generator
 * emits, versions 1 through
 * ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, the causal
 * object-graph rung included. For every generated program the forged
 * trace verifies and digests at several chosen observed heights. The
 * sweep therefore runs to the generator maximum and pins the
 * forgeability boundary there on purpose: the trace is supplementary
 * evidence, reproducible by any implementation of the public
 * semantics, never a browser attestation. A grammar beyond the
 * generator maximum must make this oracle fail until the solver
 * implements those real Web Platform semantics. The sweep is extended
 * only together with them.
 */
final class BrowserlessExecutionForgeryTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';
    private const SCOPE = 'login';
    private const ACTION = 'login-action';
    /** The observed heights the oracle forges with: 1, 10, 17 and 255. */
    private const OBSERVED_HEIGHTS = [1, 10, 17, 255];

    public function testBrowserlessShadowSolverForgesEveryLiveVersionTrace(): void
    {
        $solved = 0;
        for ($version = 1; $version <= ExecutionChallengeGenerator::MAX_EXECUTION_VERSION; $version++) {
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
            100 * \count(self::OBSERVED_HEIGHTS) * ExecutionChallengeGenerator::MAX_EXECUTION_VERSION,
            $solved,
            'the oracle solves 100 programs of every live version at each observed height',
        );
    }

    private function nonceFor(string $label): string
    {
        return base64_encode(hash('sha256', $label, true));
    }
}
