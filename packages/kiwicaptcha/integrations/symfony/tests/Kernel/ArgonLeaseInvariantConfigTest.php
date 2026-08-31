<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * The Argon admission lease/verification-runtime SLO: the Redis
 * semaphore stores leases in a ZSET with `ZREMRANGEBYSCORE` pruning and
 * no renewal, so a lease that can expire while the Argon hash still
 * runs admits more derivations than the configured concurrency cap.
 * Renewal during the blocking native hash is impractical in PHP, so the
 * deployment declares its SLO: the maximum verification runtime
 * (`argon2_max_verification_runtime_ms`) and the lease must exceed it
 * by the safety margin (5000 ms).
 * A misconfiguration is refused at container compile time in every
 * environment with the exact message.
 * The declared runtime is a deployment bound, never an enforced
 * wall-clock timeout around the blocking hash.
 */
final class ArgonLeaseInvariantConfigTest extends TestCase
{
    private const SAFETY_MARGIN_MS = 5000;

    private const MESSAGE = 'kiwi_captcha.argon2_lease_ms %d must exceed argon2_max_verification_runtime_ms %d by the safety margin of %d ms (%d <= %d + %d = %d): a Redis admission lease that can expire while an Argon2 verification is still running admits more derivations than the configured concurrency cap (ZREMRANGEBYSCORE pruning, no lease renewal), and the positive-feedback cycle (more contention -> longer hashes -> more expiries) amplifies it. Raise argon2_lease_ms or lower argon2_max_verification_runtime_ms; the declared runtime is the deployment SLO that the lease must outlive by the margin (not an enforced wall-clock bound around the blocking hash).';

    private function load(array $options): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', __DIR__);
        $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.storage',
        ], $options)], $container);
    }

    private function expectRefused(array $options): void
    {
        try {
            $this->load($options);
            self::fail('the lease/runtime combination must be refused by the extension: '.json_encode($options));
        } catch (\LogicException $e) {
            self::assertSame(
                sprintf(self::MESSAGE, $options['argon2_lease_ms'], $options['argon2_max_verification_runtime_ms'], self::SAFETY_MARGIN_MS, $options['argon2_lease_ms'], $options['argon2_max_verification_runtime_ms'], self::SAFETY_MARGIN_MS, $options['argon2_max_verification_runtime_ms'] + self::SAFETY_MARGIN_MS),
                $e->getMessage(),
                'the refusal must carry the exact actionable message'
            );
        }
    }

    public function testLeaseAtRuntimePlusMarginIsRefused(): void
    {
        // lease 30000 <= runtime 30000 + margin 5000 = 35000 -> refuse.
        $this->expectRefused(['argon2_lease_ms' => 30000, 'argon2_max_verification_runtime_ms' => 30000]);
    }

    public function testLeaseExactlyAtRuntimePlusMarginIsRefused(): void
    {
        // lease 40000 <= runtime 35000 + margin 5000 = 40000 -> refuse
        // (the lease must exceed the sum, equality does not hold the
        // invariant).
        $this->expectRefused(['argon2_lease_ms' => 40000, 'argon2_max_verification_runtime_ms' => 35000]);
    }

    public function testLeaseBelowRuntimePlusMarginIsRefused(): void
    {
        // lease 30000 <= runtime 28000 + margin 5000 = 33000 -> refuse.
        $this->expectRefused(['argon2_lease_ms' => 30000, 'argon2_max_verification_runtime_ms' => 28000]);
    }

    public function testDefaultsCompile(): void
    {
        // Defaults: lease 45000 > runtime 30000 + margin 5000 = 35000.
        $this->load([]);

        self::assertTrue(true);
    }

    public function testExplicitLease60000WithRuntime30000Compiles(): void
    {
        // lease 60000 > 30000 + 5000 = 35000 -> compiles.
        $this->load(['argon2_lease_ms' => 60000, 'argon2_max_verification_runtime_ms' => 30000]);

        self::assertTrue(true);
    }
}
