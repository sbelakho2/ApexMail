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
            bindingTag: Vectors::IP_HASH,
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
            // Server-side issuance timestamp (epoch microseconds). The
            // verifier's minimum-duration check runs only when the record
            // carries a floor; the vectors use minDurationMs 0, so the
            // absolute value is irrelevant as long as it is > 0 (0 would be
            // rejected as an untimed record).
            issuedAtNs: Vectors::ISSUED_AT * 1_000_000,
            // The fixtures are Rust-generated v1 challenges (payload
            // nonce|scope|ip_hash|issued_at), so their records are v1.
            protocolVersion: 1,
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
