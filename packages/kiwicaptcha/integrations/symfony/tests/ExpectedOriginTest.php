<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Security\ExpectedOrigin;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\EnvDsnTestKernel;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\EnvNotFoundException;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The public_base_url origin contract has one validator and two lanes,
 * both fail-closed. A literal is validated at container build time in
 * every environment. An env-resolved %env()% value is validated by the
 * same canonical-HTTPS contract when the ExpectedOrigin is constructed
 * at runtime. The controller receives the validated value object,
 * never the raw string. A malformed resolved environment value can
 * therefore never silently weaken the same-origin check.
 */
final class ExpectedOriginTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const INVALID_ORIGINS = [
        'http://example.com',
        'https://user:pass@example.com',
        'https://example.com/path',
        'https://example.com/?x=1',
        'https://example.com/#fragment',
        'not-a-url',
        '',
        'https://example.com:0',
    ];

    /**
     * @param array<int, array<string, mixed>> $layers
     */
    private function load(array $layers, string $environment = 'test'): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', $environment);
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    // ── the shared contract ──────────────────────────────────────────────

    public function testCanonicalHttpsOriginsConstructTheExpectedOrigin(): void
    {
        $origin = ExpectedOrigin::fromPublicBaseUrl('https://example.com');
        self::assertSame('https://example.com:443', $origin->normalized(), 'the comparison form carries the effective port');
        self::assertSame('https://example.com', $origin->canonical(), 'the canonical config form omits the default port');
        self::assertSame('example.com', $origin->host(), 'the host feeds the server-owned record hostname');
        self::assertSame('https://example.com', (string) $origin);

        self::assertSame('https://example.com:8443', ExpectedOrigin::fromPublicBaseUrl('https://example.com:8443')->normalized());
        self::assertSame('https://example.com:8443', ExpectedOrigin::fromPublicBaseUrl('https://example.com:8443')->canonical(), 'a non-default port stays explicit');
        self::assertSame('https://example.com:443', ExpectedOrigin::fromPublicBaseUrl('https://example.com/')->normalized(), 'a bare "/" path is the empty path');
        self::assertSame('https://example.com', ExpectedOrigin::fromPublicBaseUrl('https://example.com:443')->canonical(), 'an explicit default port canonicalizes away');
    }

    public function testIdnHostIsConvertedToPunycodeWhenExtIntlIsAvailable(): void
    {
        if (!\function_exists('idn_to_ascii')) {
            self::markTestSkipped('ext-intl is not available');
        }

        self::assertSame('https://xn--bcher-kva.example:443', ExpectedOrigin::fromPublicBaseUrl('https://bücher.example')->normalized(), 'the expected origin normalizes IDN like the request side');
    }

    public function testInvalidOriginsAreRefusedByTheSharedContract(): void
    {
        foreach (self::INVALID_ORIGINS as $value) {
            self::assertNotNull(
                ExpectedOrigin::publicBaseUrlViolation($value),
                sprintf('the shared contract must refuse "%s"', $value),
            );
        }

        self::assertNull(ExpectedOrigin::publicBaseUrlViolation('https://example.com'));
        self::assertNull(ExpectedOrigin::publicBaseUrlViolation('https://example.com:8443'));
        self::assertNull(ExpectedOrigin::publicBaseUrlViolation('https://example.com/'));
    }

    public function testInvalidResolvedValuesFailClosedAtConstructionWithTheTypedError(): void
    {
        foreach (self::INVALID_ORIGINS as $value) {
            try {
                ExpectedOrigin::fromPublicBaseUrl($value);
                self::fail(sprintf('the env-resolved origin "%s" must fail closed at construction', $value));
            } catch (\LogicException $e) {
                self::assertStringContainsString('kiwi_captcha.public_base_url', $e->getMessage(), 'the runtime refusal names the offending option');
                self::assertStringContainsString('https://', $e->getMessage(), 'the runtime refusal states the accepted shape');
            }
        }
    }

    // ── the build-time literal lane ──────────────────────────────────────

    public function testLiteralInvalidOriginsFailClosedAtContainerBuildInEveryEnvironment(): void
    {
        foreach (self::INVALID_ORIGINS as $value) {
            try {
                $this->load([['secret_key' => self::SECRET, 'public_base_url' => $value]], 'dev');
                self::fail(sprintf('the literal origin "%s" must fail closed at container build in dev', $value));
            } catch (\LogicException $e) {
                self::assertStringContainsString('public_base_url', $e->getMessage(), 'the build-time refusal names the offending option');
            }
        }
    }

    public function testLiteralPublicBaseUrlWiresTheValidatedOriginService(): void
    {
        $container = $this->load([['secret_key' => self::SECRET, 'public_base_url' => 'https://example.com']], 'test');

        $origin = $container->getDefinition('kiwi_captcha.expected_origin');
        self::assertSame([ExpectedOrigin::class, 'fromPublicBaseUrl'], $origin->getFactory(), 'the literal origin is constructed through the same runtime factory as the env lane');
        self::assertSame(['https://example.com'], $origin->getArguments());
        self::assertEquals(
            new Reference('kiwi_captcha.expected_origin'),
            $container->getDefinition(ChallengeController::class)->getArgument('$expectedOrigin'),
            'the controller receives the validated expected origin, never the raw string',
        );
    }

    public function testNoExpectedOriginServiceWithoutPublicBaseUrl(): void
    {
        $container = $this->load([['secret_key' => self::SECRET]], 'test');

        self::assertFalse($container->hasDefinition('kiwi_captcha.expected_origin'), 'no expected-origin service without public_base_url');
        self::assertNull(
            $container->getDefinition(ChallengeController::class)->getArgument('$expectedOrigin'),
            'the controller stays on the request-derived fallback when public_base_url is not configured',
        );
    }

    // ── the same-origin comparison ───────────────────────────────────────

    public function testValidExpectedOriginDrivesTheSameOriginComparison(): void
    {
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), new ArrayStorage());
        $controller = new ChallengeController($issuer, null, true, null, null, null, null, [], false, null, null, false, null, ExpectedOrigin::fromPublicBaseUrl('https://example.com'));

        $same = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://example.com'], '{"scope":"login"}'));
        self::assertSame(200, $same->getStatusCode(), 'the configured origin passes the same-origin check');

        $http = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'http://example.com'], '{"scope":"login"}'));
        self::assertSame(403, $http->getStatusCode(), 'an http Origin never matches the https expected origin (refused, not normalized)');

        $cross = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'], '{"scope":"login"}'));
        self::assertSame(403, $cross->getStatusCode(), 'a different host never matches the expected origin');
    }

    // ── the runtime env lane through a real kernel ───────────────────────

    public function testEnvResolvedInvalidOriginsFailClosedWhenTheControllerIsConstructed(): void
    {
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'=redis://127.0.0.1:6399');
        try {
            foreach (self::INVALID_ORIGINS as $value) {
                putenv(EnvDsnTestKernel::PUBLIC_URL_ENV.'='.$value);
                $kernel = new EnvDsnTestKernel('test', true);
                $kernel->boot();
                $container = $kernel->getContainer()->get('test.service_container');
                try {
                    try {
                        $container->get(ChallengeController::class);
                        self::fail(sprintf('the env-resolved origin "%s" must fail closed when the controller is constructed', $value));
                    } catch (\LogicException $e) {
                        self::assertStringContainsString('kiwi_captcha.public_base_url', $e->getMessage(), 'the runtime refusal names the offending option');
                        self::assertStringContainsString('https://', $e->getMessage(), 'the runtime refusal states the accepted shape');
                    }
                } finally {
                    $kernel->shutdown();
                }
            }
        } finally {
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }

    public function testEmptyEnvResolvedPublicBaseUrlFailsClosedWhenTheControllerIsConstructed(): void
    {
        // The placeholder resolves to nothing: the variable is present but
        // empty, so the container resolves '' and the runtime guard must
        // refuse it with the typed error instead of weakening the
        // same-origin check.
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'=redis://127.0.0.1:6399');
        putenv(EnvDsnTestKernel::PUBLIC_URL_ENV.'=');
        try {
            $kernel = new EnvDsnTestKernel('test', true);
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');
            try {
                try {
                    $container->get(ChallengeController::class);
                    self::fail('an empty env-resolved public_base_url must fail closed when the controller is constructed');
                } catch (\LogicException $e) {
                    self::assertStringContainsString('kiwi_captcha.public_base_url', $e->getMessage());
                    self::assertStringContainsString('non-empty', $e->getMessage());
                }
            } finally {
                $kernel->shutdown();
            }
        } finally {
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }

    public function testMissingEnvironmentVariableFailsClosedBeforeTheControllerExists(): void
    {
        // A truly absent environment variable never resolves at all: the
        // container's env resolution refuses it with the typed
        // EnvNotFoundException when the expected-origin service is
        // constructed, so the controller can never be constructed with an
        // unresolved origin either way.
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'=redis://127.0.0.1:6399');
        putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        $kernel = new EnvDsnTestKernel('test', true);
        $kernel->boot();
        $container = $kernel->getContainer()->get('test.service_container');
        try {
            try {
                $container->get(ChallengeController::class);
                self::fail('a missing env var must fail closed — the controller must never be constructed with an unresolved origin');
            } catch (EnvNotFoundException $e) {
                self::assertStringContainsString('KIWI_PUBLIC_URL', $e->getMessage(), 'the refusal names the missing variable');
            }
        } finally {
            $kernel->shutdown();
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }

    public function testEnvResolvedValidOriginConstructsTheController(): void
    {
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'=redis://127.0.0.1:6399');
        putenv(EnvDsnTestKernel::PUBLIC_URL_ENV.'=https://example.com');
        try {
            $kernel = new EnvDsnTestKernel('test', true);
            $kernel->boot();
            $container = $kernel->getContainer()->get('test.service_container');
            try {
                $controller = $container->get(ChallengeController::class);
                self::assertInstanceOf(ChallengeController::class, $controller, 'a valid env-resolved origin constructs the controller service');
            } finally {
                $kernel->shutdown();
            }
        } finally {
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }

    public function testEnvResolvedValidOriginServesTheSameOriginComparisonThroughTheRouter(): void
    {
        $redisUrl = RedisTestUrl::resolve();
        if ($redisUrl === null) {
            self::markTestSkipped('TEST_REDIS_URL / KC_REDIS_URL not set — the env-origin end-to-end test needs a real Redis');
        }
        if (str_starts_with($redisUrl, 'tcp://')) {
            $redisUrl = 'redis://'.substr($redisUrl, 6);
        }
        putenv(EnvDsnTestKernel::REDIS_DSN_ENV.'='.$redisUrl);
        putenv(EnvDsnTestKernel::PUBLIC_URL_ENV.'=https://example.com');
        try {
            $client = new KernelBrowser(new EnvDsnTestKernel('test', true));

            $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://example.com'], content: '{"scope":"login"}');
            self::assertSame(200, $client->getResponse()->getStatusCode(), 'the env-resolved origin passes the same-origin check end to end');

            $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'http://example.com'], content: '{"scope":"login"}');
            self::assertSame(403, $client->getResponse()->getStatusCode(), 'an http Origin never matches the https expected origin');

            $client->request('POST', '/kiwi-captcha/challenge', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_ORIGIN' => 'https://evil.example'], content: '{"scope":"login"}');
            self::assertSame(403, $client->getResponse()->getStatusCode(), 'a different host never matches the env-resolved expected origin');
        } finally {
            putenv(EnvDsnTestKernel::REDIS_DSN_ENV);
            putenv(EnvDsnTestKernel::PUBLIC_URL_ENV);
        }
    }
}
