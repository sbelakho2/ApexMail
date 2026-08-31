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
 * Trusted client-IP policy: the explicit risk.client_ip_mode decides how
 * the canonical client IP is derived. "direct" always ignores forwarding
 * headers (socket peer only). "symfony_trusted_proxies" routes through
 * Symfony's trusted-proxy machinery configured from the CIDR list:
 * headers from untrusted peers are ignored, headers from a trusted peer
 * are used. Both X-Forwarded-For and Forwarded from a trusted peer is an
 * anomaly (logged, or rejected with 400 when
 * risk.reject_ambiguous_forwarding is true).
 */
final class ClientIpResolverTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    protected function tearDown(): void
    {
        // setTrustedProxies is global static state — reset it so no test
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
        // The trusted_proxies list is unused in direct mode.
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

    public function testEmptyTrustedProxiesNeverInheritsSymfonyGlobalTrust(): void
    {
        // The Kiwi-owned trust contract: an empty risk.trusted_proxies
        // list means trust nobody — Symfony's process-global trusted
        // proxies are never inherited implicitly, even when the
        // application configured a broad global set. The forwarded
        // address is ignored and the socket peer is the canonical IP.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, []);
        $ip = $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9',
        ]));
        self::assertSame('10.1.2.3', $ip, 'the global Symfony trust is never inherited with an empty Kiwi list');
        self::assertSame(['10.0.0.0/8'], Request::getTrustedProxies(), 'the resolver restores the application global trust afterwards');
    }

    public function testSymfonyGlobalModeIsTheExplicitInheritanceOptIn(): void
    {
        // The explicit mode that inherits Symfony's global trust — the
        // operator selected it deliberately.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_GLOBAL, []);
        $ip = $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '203.0.113.9',
        ]));
        self::assertSame('203.0.113.9', $ip, 'the explicit symfony_global mode inherits the configured global trust');
        self::assertSame(['10.0.0.0/8'], Request::getTrustedProxies(), 'the resolver restores the application global trust afterwards');
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

        // Both headers from a trusted peer: the anomaly is logged, the
        // request proceeds when the resolver is constructed with the flag false.
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
        // From an untrusted peer both headers are ignored entirely — never
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
     * The controller's canonical client IP follows the mode: in direct
     * mode a forged X-Forwarded-For cannot change the IP the challenge is
     * bound to (the binding tag must match the socket peer).
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
    public function testForwardedPerformsTheSameRightToLeftChainWalkAsXff(): void
    {
        // An appending (rather than sanitizing) trusted proxy passes a
        // client-supplied left-side for= through: the right-to-left walk
        // must select the first validated untrusted address from the
        // direct-peer side, so the attacker-spoofed left value can
        // never win.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);
        $ip = $resolver->resolve($this->request('10.1.2.3', [
            'Forwarded' => 'for=attacker-spoofed, for=198.51.100.25, for=10.0.0.8',
        ]));
        self::assertSame('198.51.100.25', $ip, 'the trusted-chain walk wins: the left-side spoofed token is never the client');
        Request::setTrustedProxies([], -1);
    }

    public function testForwardedNodeIdentifiersAreValidatedIpAddresses(): void
    {
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);

        // RFC 7239 forms that ARE genuine addresses.
        $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for=192.0.2.10:4711']));
        self::assertSame('192.0.2.10', $ip, 'IPv4 with a port parses to the bare address');
        $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for="[2001:db8::1]:4711"']));
        self::assertSame('2001:db8::1', $ip, 'bracketed IPv6 with a port parses to the bare address');
        $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for="[::ffff:192.0.2.44]"']));
        self::assertSame('192.0.2.44', $ip, 'IPv4-mapped IPv6 normalizes to the IPv4 form');

        // Non-address identifiers are never returned as the client: the
        // canonical IP falls back to the socket peer.
        foreach (['unknown', '_obfuscated', 'not-an-ip', '192.0.2.10:notaport'] as $token) {
            $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for='.$token]));
            self::assertSame('10.1.2.3', $ip, 'the token "'.$token.'" is not a valid node identifier and cannot spoof the client');
        }
        Request::setTrustedProxies([], -1);
    }
    public function testSymfonyGlobalInheritsTheTrustedHeaderMaskToo(): void
    {
        // The application globally trusts 10.0.0.0/8 for X-Forwarded-For
        // only (RFC Forwarded is deliberately not trusted): symfony_global
        // must inherit both components, the proxy list and the header
        // bitmask, so an attacker-controlled Forwarded header forwarded
        // by the trusted proxy is ignored, and the canonical IP comes
        // from the trusted XFF family only.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_GLOBAL, []);
        $ip = $resolver->resolve($this->request('10.1.2.3', [
            'X-Forwarded-For' => '198.51.100.9',
            'Forwarded' => 'for=203.0.113.66',
        ]));
        self::assertSame('198.51.100.9', $ip, 'the untrusted Forwarded family is ignored: only the trusted XFF family decides');
        Request::setTrustedProxies([], -1);
    }

    public function testBracketedIpv6SuffixJunkIsRejected(): void
    {
        // The complete node identifier must be well-formed: a suffix
        // after the closing bracket that is neither empty nor a numeric
        // port makes the identifier malformed — the canonical IP falls
        // back to the socket peer.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);
        foreach (['for="[2001:db8::1]:notaport"', 'for="[2001:db8::1]garbage"'] as $identifier) {
            $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => $identifier]));
            self::assertSame('10.1.2.3', $ip, 'the malformed identifier "'.$identifier.'" cannot spoof the client');
        }
        // The well-formed bracketed form with a numeric port still parses.
        $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for="[2001:db8::1]:443"']));
        self::assertSame('2001:db8::1', $ip);
        Request::setTrustedProxies([], -1);
    }
    public function testInvalidNearestHopTerminatesTheChainWalk(): void
    {
        // An invalid nearest-side hop breaks the trust chain: the walk
        // cannot establish who lies beyond it, so the canonical IP falls
        // back conservatively to the socket peer, never an older
        // attacker-controlled address that an appending intermediary
        // let through.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        $resolver = new ClientIpResolver(ClientIpResolver::MODE_SYMFONY_TRUSTED_PROXIES, ['10.0.0.0/8']);
        $cases = [
            'Forwarded' => ['for=203.0.113.66, for=unknown', 'for=203.0.113.66, for=_obfuscated', 'for=203.0.113.66, for="[bad]"', 'for=203.0.113.66, for="[2001:db8::1]:badport"'],
            'X-Forwarded-For' => ['203.0.113.66, unknown'],
        ];
        foreach ($cases as $header => $values) {
            foreach ($values as $value) {
                $ip = $resolver->resolve($this->request('10.1.2.3', [$header => $value]));
                self::assertSame('10.1.2.3', $ip, 'the invalid nearest hop "'.$value.'" must terminate the walk: the socket peer wins, never the earlier attacker address');
            }
        }
        // A valid chain still resolves normally.
        $ip = $resolver->resolve($this->request('10.1.2.3', ['Forwarded' => 'for=203.0.113.66, for=10.0.0.8']));
        self::assertSame('203.0.113.66', $ip);
        Request::setTrustedProxies([], -1);
    }
}
