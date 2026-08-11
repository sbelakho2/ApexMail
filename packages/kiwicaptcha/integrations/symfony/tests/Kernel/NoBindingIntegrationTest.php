<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * binding_mode: 'none' must be FULLY wired through the bundle into the core
 * Issuer: challenges carry an EMPTY binding tag and verification succeeds
 * from any client IP (maximum privacy; relay protection off).
 */
final class NoBindingIntegrationTest extends KernelTestCase
{
    protected function setUp(): void
    {
        self::bootKernel();
    }

    protected static function getKernelClass(): string
    {
        return NoBindingTestKernel::class;
    }

    public function testNoneModeIssuesEmptyBindingTagAndVerifiesFromAnyIp(): void
    {
        $container = static::getContainer();
        $issuer = $container->get('kiwi_captcha.issuer');
        self::assertInstanceOf(Issuer::class, $issuer);

        $storage = $container->get('kiwi_captcha.storage.array');
        $challenge = $issuer->issue('login', '203.0.113.9');

        // The signed v2 canonical must carry an EMPTY binding-tag segment.
        $canonical = base64_decode(explode('.', $challenge->challenge)[0], true);
        $parts = explode('|', (string) $canonical);
        self::assertSame('v2', $parts[0]);
        self::assertSame('', $parts[3], 'binding_mode none must produce an empty binding tag');

        // Solve + verify from a DIFFERENT IP: must pass (no binding).
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix . $counter . base64_decode($challenge->salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $verifier = $container->get('kiwi_captcha.verifier');
        $nowNs = (int) (microtime(true) * 1_000_000) + 1_000_000;
        $outcome = $verifier->verify($token, TestKernel::SECRET, 'login', '198.51.100.200', $nowNs);
        self::assertTrue($outcome->isOk(), sprintf('expected valid from any IP, got %s', $outcome->code()));
    }
}
