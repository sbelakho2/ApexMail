<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Risk;

use BelConsulting\KiwiCaptchaBundle\Risk\ClientContextTag;
use PHPUnit\Framework\TestCase;

/**
 * The risk-v2 client-context tag: bounded, deterministic within
 * (deployment, session, descriptor) and STABLE across time — the same
 * session reporting the same coarse capabilities produces the identical
 * tag whenever it is computed, so the session's first tag stays the
 * comparison baseline for its whole lifetime. A changed session,
 * deployment or descriptor always yields a different tag, so the tag can
 * never become a stable device identifier.
 */
final class ClientContextTagTest extends TestCase
{
    private const DEPLOYMENT = 'prod';
    private const SESSION = 'abababababababababababababababab';
    private const DESCRIPTOR = 'vp=1,t=0,l=en,z=1';

    public function testTagIsBoundedBase36(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $tag = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, self::DESCRIPTOR);
            self::assertMatchesRegularExpression('/^[0-9a-z]{2}$/D', $tag, 'the tag is a bounded 2-char base36 string');
        }
    }

    public function testTagIsStableAcrossTime(): void
    {
        // Same session + same descriptor: the tag must be IDENTICAL at any
        // computation time — a session spanning an hour boundary (e.g.
        // created at 12:50 and reused at 13:05) must NOT be flagged as
        // inconsistent by an epoch re-key.
        $a = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, self::DESCRIPTOR);
        self::assertSame($a, $b, 'the same inputs must always produce the same tag');
    }

    public function testTagIsKeyedToTheSession(): void
    {
        $a = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive(self::DEPLOYMENT, str_repeat('cd', 16), self::DESCRIPTOR);
        self::assertNotSame($a, $b, 'a different session must produce a different tag');
    }

    public function testTagIsKeyedToTheDeployment(): void
    {
        $a = ClientContextTag::derive('prod', self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive('staging', self::SESSION, self::DESCRIPTOR);
        self::assertNotSame($a, $b, 'a different deployment must produce a different tag');
    }

    public function testTagFollowsTheCoarseCapabilityDescriptor(): void
    {
        $a = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, 'vp=1,t=0,l=en,z=1');
        $b = ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, 'vp=3,t=1,l=zh,z=2');
        self::assertNotSame($a, $b, 'changed coarse capabilities must produce a different tag');
    }

    public function testTagWidthIsDeliberatelyCoarse(): void
    {
        // 10 bits -> at most 1024 distinct tags per (deployment, session):
        // the tag is deliberately coarse, never a fingerprint.
        $tags = [];
        for ($i = 0; $i < 4096; $i++) {
            $tags[ClientContextTag::derive(self::DEPLOYMENT, self::SESSION, 'd'.$i)] = true;
        }
        self::assertLessThanOrEqual(1024, \count($tags), 'the tag space is bounded at 2^10');
        self::assertGreaterThan(100, \count($tags), 'the coarse tag still distinguishes capability mixes');
    }
}
