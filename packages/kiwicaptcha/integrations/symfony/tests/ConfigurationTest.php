<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use KiwiCaptcha\Config;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * The bundle's config tree must not contradict the core's protocol
 * constraints: difficulty_bits is bounded by the core's
 * Config::MAX_SHA_TARGET_BITS (20) so the bundle can never allow issuing an
 * unsolvable challenge.
 */
final class ConfigurationTest extends TestCase
{
    private function process(array $overrides = []): array
    {
        $config = array_merge([
            'secret_key' => str_repeat('a', 32),
        ], $overrides);

        return (new Processor())->processConfiguration(new Configuration(), [$config]);
    }

    public function testDifficultyBits21IsRejectedByTheTree(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['difficulty_bits' => 21]);
    }

    public function testDifficultyBits24IsRejectedByTheTree(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['difficulty_bits' => 24]);
    }

    public function testDifficultyBits20IsAccepted(): void
    {
        $processed = $this->process(['difficulty_bits' => 20]);

        self::assertSame(20, $processed['difficulty_bits']);
    }

    public function testTreeCeilingTracksCoreConstant(): void
    {
        self::assertSame(Config::MAX_SHA_TARGET_BITS, 20);
    }

    public function testRedisServiceDefaultsToNull(): void
    {
        $processed = $this->process();

        self::assertNull($processed['redis_service']);
        self::assertNull($processed['rate_limit_pepper']);
        self::assertNull($processed['rate_limit_cache']);
    }

    public function testArgonTreeBoundsMatchCoreUnconditionalBounds(): void
    {
        $processed = $this->process([
            'argon_m_kib' => 65536,
            'argon_t' => 1,
            'argon_p' => 1,
        ]);

        self::assertSame(65536, $processed['argon_m_kib']);
        self::assertSame(1, $processed['argon_t']);
        self::assertSame(1, $processed['argon_p']);

        // The core's CONDITIONAL Argon2id profile rules (t >= 3, p == 1,
        // m_kib >= 8 * p) are enforced by KiwiCaptcha\Config when the
        // extension builds it — the tree intentionally does not duplicate
        // them (see the Configuration comments). Prove the boundary cases
        // are tree-valid and left to the core:
        $this->process(['argon_t' => 2]);
        $this->process(['argon_p' => 2]);
        $this->process(['argon_m_kib' => 1]);
    }
}
