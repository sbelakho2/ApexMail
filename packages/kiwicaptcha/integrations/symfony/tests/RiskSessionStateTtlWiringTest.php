<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The server-side session-state TTL is wired from
 * risk.session_state_ttl_secs, never from the browser cookie lifetime.
 * continuity_cookie.ttl_secs: 0 is a legitimate session cookie (no
 * Max-Age), but Redis risk state must always carry a positive bounded
 * expiry: the earlier wiring passed the cookie lifetime into
 * RedisRiskStateStore::$sessionTtlSecs, which produced invalid
 * `SET ... EX 0` commands or, through the Lua zero-skip, a persistent
 * session risk hash.
 */
final class RiskSessionStateTtlWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** @param array<string, mixed> $risk */
    private function load(array $risk): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                ...$risk,
            ],
        ]], $container);

        return $container;
    }

    public function testTheDefaultSessionStateTtlIsWiredIndependentlyOfTheCookie(): void
    {
        $container = $this->load([]);
        $store = $container->getDefinition('kiwi_captcha.risk.store');
        self::assertSame(1800, $store->getArgument('$sessionTtlSecs'), 'the store defaults to the 1800 s session-state TTL');

        $cookie = $container->getDefinition(ContinuityCookie::class);
        self::assertSame(1800, $cookie->getArgument(1), 'the browser cookie keeps its own lifetime');
    }

    public function testAZeroCookieTtlStillWiresAPositiveRiskStateTtl(): void
    {
        // The exact defect: a session cookie (ttl_secs 0) must not become
        // a zero Redis TTL. The store receives the session-state TTL; the
        // cookie receives 0.
        $container = $this->load([
            'continuity_cookie' => ['ttl_secs' => 0],
            'session_state_ttl_secs' => 120,
        ]);

        $store = $container->getDefinition('kiwi_captcha.risk.store');
        self::assertSame(120, $store->getArgument('$sessionTtlSecs'), 'the Redis state TTL is the configured session_state_ttl_secs, never the cookie lifetime');
        self::assertNotSame(0, $store->getArgument('$sessionTtlSecs'), 'a zero Redis risk-state TTL is never wired');

        $cookie = $container->getDefinition(ContinuityCookie::class);
        self::assertSame(0, $cookie->getArgument(1), 'the browser cookie is the session cookie the operator asked for');
    }
}
