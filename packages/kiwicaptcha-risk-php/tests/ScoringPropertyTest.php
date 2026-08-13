<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;
use PHPUnit\Framework\TestCase;

/**
 * Seeded scoring properties + the 10,000-vector parity anchor.
 *
 * The anchor hash was computed with an independent reference implementation
 * (the same LCG below, verified against a Python bignum reference): the Rust
 * side must produce the identical hash from the identical stream.
 *
 * Encoding: 10,000 vectors; each scored with base 100 and the contract
 * default weights; scores concatenated as unsigned big-endian 16-bit
 * (pack('n')); sha256 of the 20,000 bytes.
 */
final class ScoringPropertyTest extends TestCase
{
    private const TEN_K_HASH = 'f711eac8057f8c142a4f4e63c33fabe4cfe6de62b1d0bd4deb9f21883eddb8ac';

    private const POSITIVE_FIELDS = [
        'source_fast', 'source_slow', 'subnet_fast', 'issue_debt', 'bad_proof',
        'malformed', 'replay', 'action_failure', 'scope_switch',
        'global_pressure', 'network_risk',
    ];

    public function testTenThousandVectorParityAnchor(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $prng = new SeededVector();

        $blob = '';
        for ($i = 0; $i < 10000; $i++) {
            $vector = SignalVector::fromArray($prng->vector());
            $blob .= pack('n', $scorer->score(100, $vector, $weights));
        }

        self::assertSame(20000, strlen($blob));
        self::assertSame(self::TEN_K_HASH, hash('sha256', $blob));
    }

    public function testSeededPrngFirstValues(): void
    {
        // Anchor the LCG stream itself: x1 = 0x91778aed87ee5eb1, value1 = 291
        $prng = new SeededVector();
        self::assertSame(291, $prng->next());
    }

    public function testRaisingPositiveSignalNeverLowersScore(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $prng = new SeededVector();

        for ($i = 0; $i < 500; $i++) {
            $base = $prng->vector();
            $score = $scorer->score(100, SignalVector::fromArray($base), $weights);
            foreach (self::POSITIVE_FIELDS as $field) {
                $raised = $base;
                $raised[$field] = min(1000, $raised[$field] + 1);
                $raisedScore = $scorer->score(100, SignalVector::fromArray($raised), $weights);
                self::assertGreaterThanOrEqual(
                    $score,
                    $raisedScore,
                    sprintf('%s +1 lowered score from %d to %d', $field, $score, $raisedScore)
                );
            }
        }
    }

    public function testRaisingTrustCreditNeverRaisesScore(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $prng = new SeededVector();

        for ($i = 0; $i < 500; $i++) {
            $base = $prng->vector();
            $score = $scorer->score(100, SignalVector::fromArray($base), $weights);
            foreach (['trust_credit', 'principal_credit'] as $field) {
                $raised = $base;
                $raised[$field] = min(1000, $raised[$field] + 1);
                $raisedScore = $scorer->score(100, SignalVector::fromArray($raised), $weights);
                self::assertLessThanOrEqual(
                    $score,
                    $raisedScore,
                    sprintf('%s +1 raised score from %d to %d', $field, $score, $raisedScore)
                );
            }
        }
    }

    public function testScoresStayInRange(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $prng = new SeededVector();
        for ($i = 0; $i < 10000; $i++) {
            $score = $scorer->score(100, SignalVector::fromArray($prng->vector()), $weights);
            self::assertGreaterThanOrEqual(0, $score);
            self::assertLessThanOrEqual(1000, $score);
        }
    }

    public function testWeightedFunctionIsIntegerDivision(): void
    {
        // weighted(1, 1) = intdiv(1, 1000) = 0; weighted(500, 500) = 250.
        $scorer = new RiskScorer();
        $vector = SignalVector::fromArray(['source_fast' => 1] + array_fill_keys([
            'source_slow', 'subnet_fast', 'issue_debt', 'bad_proof', 'malformed',
            'replay', 'action_failure', 'scope_switch', 'global_pressure',
            'network_risk', 'trust_credit', 'principal_credit',
        ], 0));
        $weights = new RiskWeights();
        self::assertSame(100, $scorer->score(100, $vector, $weights));

        $vector = SignalVector::fromArray(['source_fast' => 500] + array_fill_keys([
            'source_slow', 'subnet_fast', 'issue_debt', 'bad_proof', 'malformed',
            'replay', 'action_failure', 'scope_switch', 'global_pressure',
            'network_risk', 'trust_credit', 'principal_credit',
        ], 0));
        // 100 + intdiv(500*190, 1000) = 100 + 95 = 195
        self::assertSame(195, $scorer->score(100, $vector, $weights));
    }

    /**
     * AUDIT #88 (a) — ASYMMETRIC TRUST: the exact-IP (source) signals must
     * outweigh the subnet (network) signals in the scorer weights, so one
     * attacker IP is always punished harder than the /64 aggregate it
     * shares. Pinned on the contract defaults; a future symmetric-weight
     * regression fails here.
     */
    public function testSourceWeightsOutweighSubnetWeights(): void
    {
        $weights = new RiskWeights();
        self::assertGreaterThan(
            $weights->subnetFast,
            $weights->sourceFast,
            'source_fast (exact-IP burst) must outweigh subnet_fast (network burst)'
        );
        self::assertGreaterThan(
            $weights->subnetFast,
            $weights->badProof,
            'bad_proof (exact-IP invalid proofs) must outweigh the subnet effect'
        );
        // The CONTRIBUTION-level asymmetry: for the same signal value the
        // exact-IP channel contributes strictly more score than the subnet
        // aggregate channel.
        $scorer = new RiskScorer();
        $same = array_fill_keys([
            'source_slow', 'issue_debt', 'bad_proof', 'malformed', 'replay',
            'action_failure', 'scope_switch', 'global_pressure', 'network_risk',
            'trust_credit', 'principal_credit',
        ], 0);
        $sourceOnly = SignalVector::fromArray(['source_fast' => 500] + $same);
        $subnetOnly = SignalVector::fromArray(['subnet_fast' => 500] + $same);
        self::assertGreaterThan(
            $scorer->score(0, $subnetOnly, $weights),
            $scorer->score(0, $sourceOnly, $weights),
            'an identical exact-IP signal must contribute more than the same network aggregate signal'
        );
    }

    /**
     * AUDIT #88 (b) — ABSOLUTE USER-VISIBLE CAP: the score is clamped to
     * 0..1000, so a poisoned source (every signal at saturation) reaches
     * the cap but can NEVER exceed it — there is no unbounded punishment
     * mode.
     */
    public function testSaturatedSourceReachesTheCapButNeverExceedsIt(): void
    {
        $scorer = new RiskScorer();
        $weights = new RiskWeights();
        $saturated = array_fill_keys([
            'source_fast', 'source_slow', 'subnet_fast', 'issue_debt', 'bad_proof',
            'malformed', 'replay', 'action_failure', 'scope_switch',
            'global_pressure', 'network_risk',
        ], 1000) + ['trust_credit' => 0, 'principal_credit' => 0];
        $score = $scorer->score(100, SignalVector::fromArray($saturated), $weights);
        self::assertSame(1000, $score, 'a fully saturated source must reach the cap');
        self::assertLessThanOrEqual(1000, $score, 'the score must never exceed the 0..1000 cap');

        // Hundreds of invalid proofs alone: bad_proof saturates at 1000 and
        // the contribution is bounded by the weight (220/1000 of it).
        $vector = SignalVector::fromArray(['bad_proof' => 1000] + array_fill_keys([
            'source_fast', 'source_slow', 'subnet_fast', 'issue_debt', 'malformed',
            'replay', 'action_failure', 'scope_switch', 'global_pressure',
            'network_risk', 'trust_credit', 'principal_credit',
        ], 0));
        self::assertSame(100 + intdiv(1000 * 220, 1000), $scorer->score(100, $vector, $weights));
    }
}
