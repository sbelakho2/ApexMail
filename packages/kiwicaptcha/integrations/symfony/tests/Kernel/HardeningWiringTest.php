<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerInterface;
use KiwiCaptcha\Verifier;

/**
 * The hardening config options must reach the REAL wired services: issuance
 * rate limiting enforced at the challenge endpoint (shared PSR-6 pool
 * configured) and the Argon2id verification cap wrapping the verifier.
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

    public function testArgon2ModeWrapsVerifierInThrottledVerifier(): void
    {
        $verifier = $this->container()->get('kiwi_captcha.verifier');
        self::assertInstanceOf(ThrottledVerifier::class, $verifier);

        $validator = $this->container()->get(KiwiCaptchaValidator::class);
        $property = new \ReflectionProperty(KiwiCaptchaValidator::class, 'verifier');
        self::assertInstanceOf(ThrottledVerifier::class, $property->getValue($validator));
    }

    public function testSha256ModeKeepsPlainVerifier(): void
    {
        $kernel = new TestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');

        self::assertInstanceOf(Verifier::class, $container->get('kiwi_captcha.verifier'));
    }
}
