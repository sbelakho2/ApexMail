<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Risk;

use BelConsulting\KiwiCaptchaBundle\Risk\ClientContextTag;
use PHPUnit\Framework\TestCase;

/**
 * The risk-v2 client-context tag: bounded, deterministic within
 * (deployment, epoch, session, descriptor), and keyed to all four — a
 * changed session, epoch or deployment always yields a different tag, so
 * the tag can never become a stable device identifier.
 */
final class ClientContextTagTest extends TestCase
{
    private const DEPLOYMENT = 'prod';
    private const SESSION = 'abababababababababababababababab';
    private const DESCRIPTOR = 'vp=1,t=0,l=en,z=1';

    public function testTagIsBoundedBase36(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $tag = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000 + $i, self::SESSION, self::DESCRIPTOR);
            self::assertMatchesRegularExpression('/^[0-9a-z]{2}$/D', $tag, 'the tag is a bounded 2-char base36 string');
        }
    }

    public function testTagIsDeterministicWithinOneEpoch(): void
    {
        // An epoch-aligned base time (472222 * 3600) so +3599 stays inside
        // the SAME epoch.
        $base = 1_699_999_200;
        $a = ClientContextTag::derive(self::DEPLOYMENT, $base, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive(self::DEPLOYMENT, $base + 3599, self::SESSION, self::DESCRIPTOR);
        self::assertSame($a, $b, 'the same inputs inside one epoch must produce the same tag');
    }

    public function testTagIsKeyedToTheEpoch(): void
    {
        $a = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000 + ClientContextTag::EPOCH_SECS, self::SESSION, self::DESCRIPTOR);
        self::assertNotSame($a, $b, 'a new epoch must re-key the tag');
    }

    public function testTagIsKeyedToTheSession(): void
    {
        $a = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, str_repeat('cd', 16), self::DESCRIPTOR);
        self::assertNotSame($a, $b, 'a different session must produce a different tag');
    }

    public function testTagIsKeyedToTheDeployment(): void
    {
        $a = ClientContextTag::derive('prod', 1_700_000_000, self::SESSION, self::DESCRIPTOR);
        $b = ClientContextTag::derive('staging', 1_700_000_000, self::SESSION, self::DESCRIPTOR);
        self::assertNotSame($a, $b, 'a different deployment must produce a different tag');
    }

    public function testTagFollowsTheCoarseCapabilityDescriptor(): void
    {
        $a = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, self::SESSION, 'vp=1,t=0,l=en,z=1');
        $b = ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, self::SESSION, 'vp=3,t=1,l=zh,z=2');
        self::assertNotSame($a, $b, 'changed coarse capabilities must produce a different tag');
    }

    public function testTagWidthIsDeliberatelyCoarse(): void
    {
        // 10 bits -> at most 1024 distinct tags per (deployment, epoch,
        // session): the tag is deliberately coarse, never a fingerprint.
        $tags = [];
        for ($i = 0; $i < 4096; $i++) {
            $tags[ClientContextTag::derive(self::DEPLOYMENT, 1_700_000_000, self::SESSION, 'd'.$i)] = true;
        }
        self::assertLessThanOrEqual(1024, \count($tags), 'the tag space is bounded at 2^10');
        self::assertGreaterThan(100, \count($tags), 'the coarse tag still distinguishes capability mixes');
    }
}
