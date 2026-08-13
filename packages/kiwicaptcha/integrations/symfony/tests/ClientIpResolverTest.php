<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trusted client-IP policy (audit #64): the explicit risk.client_ip_mode
 * decides how the canonical client IP is derived. "direct" ALWAYS ignores
 * forwarding headers (socket peer only); "symfony_trusted_proxies" routes
 * through Symfony's trusted-proxy machinery configured from the CIDR list —
 * forwarding headers from UNTRUSTED peers are ignored, headers from a
 * TRUSTED peer are used, and BOTH X-Forwarded-For + Forwarded from a
 * trusted peer is an anomaly (logged, or rejected with 400 when
 * risk.reject_ambiguous_forwarding is true).
 */
final class ClientIpResolverTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    protected function tearDown(): void
    {
        // setTrustedProxies is GLOBAL static state — reset it so no test
        // leaks its trust configuration into another.
        Request::setTrustedProxies([], -1);
    }

    private function request(string $peer, array $headers = []): Request
    {
        $server = ['REMOTE_ADDR' => $peer];
        foreach ($headers as $name => $value) {
            $server['HTTP_'.$name] = $value;
        }

        return Request::create('/challenge', 'POST', [], [], [], $server, '{"scope":"login"}');
    }

    public function testDirectModeAlwaysUsesTheSocketPeer(): void
    {
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_DIRECT);

        // A forged X-Forwarded-For (and Forwarded) from ANY peer — trusted or
        // not — is ignored: the canonical IP is the socket peer.
        self::assertSame('198.51.100.7', $resolver->resolve($this->request('198.51.100.7', [
            'X-Forwarded-For' => '203.0.113.9',
            'Forwarded' => 'for=203.0.113.9',
        ])), 'direct mode must ignore forged forwarding headers from an untrusted peer');
    }

    public function testDirectModeIgnoresForwardingEvenFromTrustedCidrs(): void
    {
        // The trusted_proxies list is UNUSED in direct mode.
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_DIRECT, ['10.0.0.0/8']);

        self::assertSame('10.1.2.3', $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9',
        ])), 'direct mode never trusts forwarding headers — even from a listed CIDR');
    }

    public function testUntrustedPeerForwardingIgnoredInSymfonyTrustedProxiesMode(): void
    {
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);

        self::assertSame('198.51.100.7', $resolver->resolve($this->request('198.51.100.7', [
            'X-Forwarded-For' => '203.0.113.9',
        ])), 'Symfony\'s trusted-proxy machinery must ignore X-Forwarded-For from an untrusted peer');
    }

    public function testTrustedProxyForwardingIsUsed(): void
    {
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);

        self::assertSame('203.0.113.9', $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9, 10.1.2.3',
        ])), 'a trusted proxy\'s X-Forwarded-For chain yields the original client');
    }

    public function testEmptyTrustedProxiesListTrustsNobody(): void
    {
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, []);

        self::assertSame('198.51.100.7', $resolver->resolve($this->request('198.51.100.7', [
            'X-Forwarded-For' => '203.0.113.9',
        ])), 'an empty trusted_proxies list must ignore forwarding headers everywhere');
    }

    public function testBothForwardingHeadersFromTrustedPeerAreLoggedByDefault(): void
    {
        $logs = [];
        $logger = new class($logs) extends NullLogger {
            /** @var list<string> */
            public array $seen = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->seen[] = (string) $message;
            }
        };
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8'], false, $logger);

        // Both headers from a trusted peer: the anomaly is LOGGED, the
        // request proceeds (reject_ambiguous_forwarding defaults false).
        $ip = $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9',
            'Forwarded' => 'for=198.51.100.9',
        ]));
        self::assertNotSame('', $ip, 'the request proceeds with the (ambiguous) derivation');
        self::assertCount(1, $logger->seen, 'the anomaly must be logged');
        self::assertStringContainsString('ambiguous', $logger->seen[0]);
    }

    public function testBothForwardingHeadersFromTrustedPeerRejectWhenConfigured(): void
    {
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8'], true);

        $this->expectException(AmbiguousForwardingException::class);
        $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9',
            'Forwarded' => 'for=198.51.100.9',
        ]));
    }

    public function testBothForwardingHeadersFromUntrustedPeerAreNotAnAnomaly(): void
    {
        // From an UNTRUSTED peer both headers are ignored entirely — never
        // ambiguous, never an anomaly (even with rejection enabled).
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8'], true);

        self::assertSame('198.51.100.7', $resolver->resolve($this->request('198.51.100.7', [
            'X-Forwarded-For' => '203.0.113.9',
            'Forwarded' => 'for=198.51.100.9',
        ])), 'untrusted peers are never ambiguous — their headers are ignored');
    }

    public function testInvalidModeIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ClientIpResolver('bogus');
    }

    // ── Controller wiring ─────────────────────────────────────────────────

    /**
     * The controller's canonical client IP follows the mode: in direct mode
     * a forged X-Forwarded-For cannot change the IP the challenge is BOUND
     * to (the binding tag must match the socket peer).
     */
    public function testControllerBindsToTheSocketPeerInDirectMode(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_DIRECT);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, [], false, $storage, null, false, $resolver);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '198.51.100.7',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
        ], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());

        $nonce = json_decode((string) $response->getContent(), true)['nonce'];
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        self::assertSame(
            Issuer::bindingTag($nonce, '198.51.100.7', self::SECRET),
            $record->bindingTag,
            'the challenge must be bound to the SOCKET PEER — the forged X-Forwarded-For must be ignored',
        );
    }

    public function testControllerRejectsAmbiguousForwardingWith400(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8'], true);
        $controller = new ChallengeController($issuer, null, false, null, null, null, null, [], false, $storage, null, false, $resolver);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '10.1.2.3',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
            'HTTP_FORWARDED' => 'for=198.51.100.9',
        ], '{"scope":"login"}'));
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('AMBIGUOUS_FORWARDING', json_decode((string) $response->getContent(), true)['error']['code']);
    }
}
