<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The hardening config options must reach the REAL wired services: issuance
 * rate limiting enforced at the challenge endpoint (shared PSR-6 pool
 * configured) and the Argon2id admission gate wired into the core Verifier.
 */
final class HardeningWiringTest extends TestCase
{
    private static ?HardenedTestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new HardenedTestKernel('test', true);
        self::$kernel->boot();
    }

    private function container(): ContainerInterface
    {
        return self::$kernel->getContainer()->get('test.service_container');
    }

    public function testRateLimitEnforcedThroughRealKernel(): void
    {
        // Default KernelBrowser reboots the kernel per request (like separate
        // PHP-FPM workers), which would wipe the in-memory pool state; a
        // single worker is the scenario the in-memory limiter guards.
        $client = new KernelBrowser(self::$kernel);
        $client->disableReboot();
        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        self::assertSame(200, $client->getResponse()->getStatusCode());

        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        self::assertSame(200, $client->getResponse()->getStatusCode());

        $client->request('POST', '/kiwi-captcha/challenge', content: '{"scope":"login"}');
        self::assertSame(429, $client->getResponse()->getStatusCode());
        self::assertStringContainsString('RATE_LIMITED', (string) $client->getResponse()->getContent());
    }

    public function testArgon2ModeWiresInProcessGateIntoTheVerifier(): void
    {
        // HardenedTestKernel has argon2id + no Redis client: the extension
        // must wire the InProcessArgonGate into the CORE verifier (the
        // bundle's ThrottledVerifier wrapper no longer exists — the core
        // takes the gate natively).
        $verifier = $this->container()->get('kiwi_captcha.verifier');
        self::assertInstanceOf(Verifier::class, $verifier);

        $property = new \ReflectionProperty(Verifier::class, 'argonGate');
        self::assertInstanceOf(InProcessArgonGate::class, $property->getValue($verifier));

        $validator = $this->container()->get(KiwiCaptchaValidator::class);
        $validatorProperty = new \ReflectionProperty(KiwiCaptchaValidator::class, 'verifier');
        self::assertInstanceOf(Verifier::class, $validatorProperty->getValue($validator));
    }

    public function testSha256ModeKeepsPlainVerifierWithoutGate(): void
    {
        $kernel = new TestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        $verifier = $container->get('kiwi_captcha.verifier');
        self::assertInstanceOf(Verifier::class, $verifier);

        $property = new \ReflectionProperty(Verifier::class, 'argonGate');
        self::assertNull($property->getValue($verifier), 'sha256 mode must wire no admission gate');
    }
}
