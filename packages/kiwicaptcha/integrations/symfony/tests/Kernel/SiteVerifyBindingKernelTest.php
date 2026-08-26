<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * P0 regression: the binding authority must actually reach the
 * SiteVerifyController through the container. The round-66 wiring landed * on the ChallengeController definition instead (a duplicate setter with
 * a Siteverify comment); a unit-constructed controller cannot catch that
 * class of hole, so this test boots a real kernel and redeems real tokens.
 */
final class SiteVerifyBindingKernelTest extends TestCase
{
    private static ?SiteVerifyBindingTestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new SiteVerifyBindingTestKernel('test', true);
        self::$kernel->boot();
    }

    private function container(): \Symfony\Component\DependencyInjection\ContainerInterface
    {
        return self::$kernel->getContainer()->get('test.service_container');
    }

    public function testSiteVerifyBindingAuthorityIsWiredFromTheContainer(): void
    {
        $controller = $this->container()->get(SiteVerifyController::class);
        $authority = $this->container()->get('test.binding_authority');
        $storage = $this->container()->get('kiwi_captcha.storage.array');
        $issuer = $this->container()->get('kiwi_captcha.issuer');

        // A challenge cryptographically anchored to txn-A succeeds.
        $challengeA = $issuer->issue('payment', '198.51.100.7', 'txn-A');
        $tokenA = $this->solve($challengeA->prefix, $challengeA->salt, $challengeA->targetBits, $challengeA->nonce);
        usleep(($challengeA->minDurationMs + 10) * 1000);

        $responseA = $controller->siteverify($this->request($tokenA));
        self::assertSame(200, $responseA->getStatusCode());
        self::assertTrue(json_decode((string) $responseA->getContent(), true)['success'], 'the txn-A-bound token succeeds under the txn-A authoritative context');
        self::assertGreaterThan(0, $authority->calls, 'the container-wired SiteVerifyController consulted the binding authority');

        // A challenge anchored to txn-B is refused before the consume:
        // the record must still be pending (never consumed, never burned).
        $challengeB = $issuer->issue('payment', '198.51.100.7', 'txn-B');
        $tokenB = $this->solve($challengeB->prefix, $challengeB->salt, $challengeB->targetBits, $challengeB->nonce);
        usleep(($challengeB->minDurationMs + 10) * 1000);

        $responseB = $controller->siteverify($this->request($tokenB));
        self::assertSame(200, $responseB->getStatusCode());
        $jsonB = json_decode((string) $responseB->getContent(), true);
        self::assertFalse($jsonB['success'], 'a proof anchored to txn-B must never succeed for the txn-A authoritative transaction');
        self::assertNull($storage->consumedState($challengeB->nonce), 'the binding mismatch rejects BEFORE any pending→consumed transition — no deterministic result is ever committed');
    }

    private function request(string $token): Request
    {
        return $this->siteverifyRequest([
            'secret' => SiteVerifyBindingTestKernel::SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => '198.51.100.7',
        ]);
    }

    private function solve(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.base64_decode($salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }
    private function siteverifyRequest(array $fields, string $contentType = 'application/x-www-form-urlencoded'): \Symfony\Component\HttpFoundation\Request
    {
        $body = $contentType === 'application/json' ? json_encode($fields, JSON_THROW_ON_ERROR) : http_build_query($fields);

        return \Symfony\Component\HttpFoundation\Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => $contentType], (string) $body);
    }

}
