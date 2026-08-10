<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Tests\Fixtures\Vectors;

/**
 * Shared helpers for building records/tokens from the fixture vectors.
 */
trait VerifyFixtureTrait
{
    /** @param array<string, mixed> $vector */
    private function recordFromVector(array $vector): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $vector['nonce'],
            scope: 'login',
            ipHash: Vectors::IP_HASH,
            issuedAt: Vectors::ISSUED_AT,
            expiresAt: Vectors::ISSUED_AT + 120,
            algorithm: PoWAlgorithm::from($vector['algorithm']),
            mKib: (int) $vector['m_kib'],
            t: (int) $vector['t'],
            p: (int) $vector['p'],
            targetBits: (int) $vector['target_bits'],
            salt: $vector['salt'],
            prefix: $vector['prefix'],
            challenge: $vector['challenge'],
            minDurationMs: 0,
        );
    }

    /** @param array<string, mixed> $vector */
    private function tokenFor(array $vector, ?int $counter = null, ?int $durationMs = null): string
    {
        return \KiwiCaptcha\SolutionToken::create(
            $vector['nonce'],
            $counter ?? (int) $vector['counter'],
            $durationMs ?? 5000,
            ['wd' => false, 'me' => 3, 'ke' => 1, 'et' => [100, 250, 480]],
        )->encode();
    }
}
