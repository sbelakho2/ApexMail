<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Issuance difficulty floors: issueWithProfile must refuse
 * out-of-range profiles at issuance — the server-owned floors guarantee the
 * issuer never signs below-floor work (the widget sends no difficulty
 * parameters, so a client-reported capability can never lower difficulty
 * below these).
 */
final class IssuanceFloorTest extends TestCase
{
    private function issuer(): Issuer
    {
        return new Issuer(
            new \KiwiCaptcha\Config(secretKey: Vectors::SECRET, targetBits: 8),
            new ArrayStorage(),
        );
    }

    public function testMemoryBelowFloorRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->issuer()->issueWithProfile(
            'login',
            '198.51.100.7',
            new ChallengeProfile(PoWAlgorithm::Argon2id, 1, mKib: 1, t: 3, p: 1),
        );
    }

    public function testMemoryAboveFloorRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->issuer()->issueWithProfile(
            'login',
            '198.51.100.7',
            new ChallengeProfile(PoWAlgorithm::Argon2id, 1, mKib: 131072, t: 3, p: 1),
        );
    }

    public function testTimeBelowFloorRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->issuer()->issueWithProfile(
            'login',
            '198.51.100.7',
            new ChallengeProfile(PoWAlgorithm::Argon2id, 1, mKib: 8, t: 2, p: 1),
        );
    }

    public function testParallelismOtherThanOneRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->issuer()->issueWithProfile(
            'login',
            '198.51.100.7',
            new ChallengeProfile(PoWAlgorithm::Argon2id, 1, mKib: 8, t: 3, p: 2),
        );
    }

    public function testShaProfilesAreNotSubjectToArgonFloors(): void
    {
        // A SHA-256 profile carries mKib=0 by default (unused) — the argon
        // floors must not reject it.
        $challenge = $this->issuer()->issueWithProfile('login', '198.51.100.7', ChallengeProfile::sha(8));

        self::assertSame(PoWAlgorithm::Sha256, $challenge->algorithm);
        self::assertSame(8, $challenge->targetBits);
    }

    public function testValidArgonProfileIssues(): void
    {
        $challenge = $this->issuer()->issueWithProfile('login', '198.51.100.7', ChallengeProfile::argon16());

        self::assertSame(PoWAlgorithm::Argon2id, $challenge->algorithm);
        self::assertSame(16384, $challenge->mKib);
        self::assertSame(3, $challenge->t);
        self::assertSame(1, $challenge->p);
    }
}
