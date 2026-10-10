<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\IdentityVector;
use KiwiCaptcha\Risk\IdentityVectorInput;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use PHPUnit\Framework\TestCase;

/**
 * The measured cost budget of the full identity-vector computation
 * (change.md 2 / 3.1.1): one derive() of all seven dimensions must
 * average under 20 µs, measured via hrtime over 20,000 fresh
 * computations. Each iteration varies the clock, so the memo never
 * serves a cached vector and the number is the honest per-request
 * cost. The memo-hit cost is measured and printed beside it: that is
 * the price a second reader of the same request's vector pays.
 */
final class IdentityVectorPerfTest extends TestCase
{
    private const ITERATIONS = 20_000;

    private const BUDGET_US = 20.0;

    public function testFullSevenDimensionDerivationAveragesUnderTheBudget(): void
    {
        $dataset = AsnDataset::open(dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv');
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat(chr(0x42), 32)));
        $base = new IdentityVectorInput(
            clientIp: '203.0.113.27',
            sessionCookieHex: '5ae1a4b8c0d1e2f30011223344556677',
            principalId: 'principal-42',
            agentKeyId: 'agent-key-7',
            targetNormalized: 'user@example.com',
            asnDataset: $dataset,
            nowUnixSecs: 1_700_000_000,
        );

        // Fresh computations: the varying clock defeats the memo, so
        // every iteration pays the full seven-dimension derivation.
        $start = hrtime(true);
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $input = new IdentityVectorInput(
                clientIp: $base->clientIp,
                sessionCookieHex: $base->sessionCookieHex,
                principalId: $base->principalId,
                agentKeyId: $base->agentKeyId,
                targetNormalized: $base->targetNormalized,
                asnDataset: $dataset,
                nowUnixSecs: $base->nowUnixSecs + $i,
            );
            $vector = IdentityVector::derive($input, $factory);
            if ($vector->source === '') {
                self::fail('the derivation must produce a vector');
            }
        }
        $freshUs = (hrtime(true) - $start) / 1000 / self::ITERATIONS;

        // Memo hits: the same descriptor derived repeatedly, the shape
        // of a second reader inside one request.
        $start = hrtime(true);
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $vector = IdentityVector::derive($base, $factory);
            if ($vector->source === '') {
                self::fail('the memo must produce a vector');
            }
        }
        $memoUs = (hrtime(true) - $start) / 1000 / self::ITERATIONS;

        fwrite(STDERR, sprintf(
            "\nIdentityVector perf: %d fresh seven-dimension derivations, mean %.2f µs each (budget %.0f µs); memo-hit mean %.2f µs\n",
            self::ITERATIONS,
            $freshUs,
            self::BUDGET_US,
            $memoUs,
        ));

        self::assertLessThan(
            self::BUDGET_US,
            $freshUs,
            sprintf('mean %.2f µs per fresh derivation exceeds the %.0f µs budget', $freshUs, self::BUDGET_US),
        );
    }
}
