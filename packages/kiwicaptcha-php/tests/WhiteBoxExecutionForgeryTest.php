<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\BrowserlessForgerySolver;
use KiwiCaptcha\Tests\Support\WhiteBoxEnvelopeForger;
use PHPUnit\Framework\TestCase;

/**
 * The white-box execution forgery measurement: the honest full-knowledge
 * adversary number for the version-6 real-platform rung.
 *
 * The naive oracle (BrowserlessExecutionForgeryTest) emits the pure-sim
 * placeholders and is rejected 100 percent of the time. That figure never
 * measured a forger who implemented the published envelopes. This test
 * closes that hole: the white-box forger reimplements the five
 * operand-derived envelopes exactly as the open-source verifier does and
 * emits a passing trace for every version-6 program without ever opening
 * a browser.
 *
 * The measured pass rate is the truth to publish: version 6 costs an
 * attacker one reading of the source, the same class as versions 1-5.
 * It is supplementary evidence, never a browser boundary. The risk
 * engine must not weight execution evidence as proof of a real browser
 * (see EvidenceModel / RiskV2Signals: they do not).
 */
final class WhiteBoxExecutionForgeryTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';
    private const SCOPE = 'login';
    private const ACTION = 'login-action';

    public function testWhiteBoxForgerPassesEveryVersion6ProgramWithoutABrowser(): void
    {
        $attempted = 0;
        $passed = 0;
        for ($i = 0; $i < 100; $i++) {
            $label = sprintf('whitebox-forger-v6-%03d', $i);
            $nonce = base64_encode(hash('sha256', $label, true));
            $programB64 = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, 6);
            $decoded = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($decoded, 'every generated program must parse');
            self::assertSame(6, $decoded['op_version'], 'the corpus stays on the real-platform rung');
            $trace = WhiteBoxEnvelopeForger::forge($decoded);
            $attempted++;
            $verified = ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $trace);
            if ($verified !== null) {
                $passed++;
                $digest = ExecutionChallengeGenerator::digestOverTrace($programB64, $nonce, $trace);
                self::assertNotNull($digest, 'a forged trace that verifies must also digest');
            }
        }
        self::assertSame(100, $attempted, 'the sweep attempted every program');
        self::assertSame(
            100,
            $passed,
            'WHITE-BOX PASS RATE: the full-knowledge forger must pass every version-6 program '
                .'without a browser — the published envelopes are pure functions of the operands '
                .'that ship with the program (pass rate 1.0, rejection rate 0.0)',
        );
    }

    public function testWhiteBoxForgerStillSolvesThePureSemanticsRungs(): void
    {
        // The same forger (public semantics + published envelopes) is a
        // superset of the naive oracle: it must also forge versions 1-5.
        for ($version = 1; $version <= 5; $version++) {
            $nonce = base64_encode(hash('sha256', sprintf('whitebox-forger-v%d', $version), true));
            $programB64 = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, $version);
            $decoded = ExecutionChallengeGenerator::decode($programB64);
            self::assertNotNull($decoded);
            $trace = WhiteBoxEnvelopeForger::forge($decoded);
            self::assertNotNull(
                ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $trace),
                sprintf('the white-box forger must also forge the version-%d pure-semantics trace', $version),
            );
        }
    }

    public function testNaiveOracleStillRejectedOnVersion6(): void
    {
        // The contrast that makes the hole visible: the forger who does
        // NOT implement the envelopes (the naive oracle) is still
        // rejected. The 100 percent rejection figure is real for that
        // adversary class and worthless as a full-knowledge number.
        $nonce = base64_encode(hash('sha256', 'whitebox-contrast-naive', true));
        $programB64 = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, 6);
        $decoded = ExecutionChallengeGenerator::decode($programB64);
        self::assertNotNull($decoded);
        $naive = BrowserlessForgerySolver::solve($decoded, 17);
        self::assertNull(
            ExecutionChallengeGenerator::verifyExecutedTrace($programB64, $nonce, $naive),
            'the naive placeholder forger must still fail the envelope walker',
        );
    }
}
