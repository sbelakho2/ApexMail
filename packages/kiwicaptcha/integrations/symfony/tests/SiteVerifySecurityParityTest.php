<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\Vectors;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The provider/native security-parity matrix: the provider-compatible
 * SiteVerify surface must never disagree with the native path in the
 * unsafe direction.
 *
 * Native Deny, StepUp and ChainRequired are final-disposition outcomes
 * of the post-solve machinery (adaptive reassessment, chain
 * obligations, durable disposition). The provider surface cannot
 * faithfully enforce them, so the configuration refuses a siteverify
 * secret mapped to a post_solve_check scope at compile time: the unsafe
 * disagreement is unrepresentable rather than silently weakened. For a
 * non-post-solve scope, the only scopes a siteverify secret may
 * target, the native validator and the provider surface agree: Pass
 * and success:true.
 */
final class SiteVerifySecurityParityTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    public function testSiteVerifySecretForAPostSolveScopeIsRefusedAtCompileTime(): void
    {
        // The matrix's unsafe rows are refused: mapping a siteverify
        // secret to a scope whose post-solve check is enabled (the
        // default login, signup, password_reset, admin_login and
        // financial_action scopes) would silently provide weaker
        // semantics than the native final-disposition path.
        $container = new ContainerBuilder();
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot faithfully enforce the native post-solve final disposition');
        (new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension())->load(
            [[
                'secret_key' => self::SECRET,
                'risk' => [
                    'siteverify_secrets' => ['compat-secret-42' => 'login'],
                ],
            ]],
            $container,
        );
    }

    public function testSiteVerifySecretForAPostSolveScopeIsRefusedAtCompileTimeWithCustomScope(): void
    {
        $container = new ContainerBuilder();
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot faithfully enforce the native post-solve final disposition');
        (new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension())->load(
            [[
                'secret_key' => self::SECRET,
                'risk' => [
                    'scopes' => ['custom_action' => ['id' => 9, 'post_solve_check' => true]],
                    'siteverify_secrets' => ['compat-secret-42' => 'custom_action'],
                ],
            ]],
            $container,
        );
    }

    public function testNativeAndSiteVerifyAgreeOnANonPostSolveScope(): void
    {
        // The only scopes a siteverify secret may target have
        // post_solve_check=false: the native validator and the provider
        // surface both accept the same proof (Pass / success:true) —
        // the matrix's safe direction, exercised end to end.
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage);
        $challenge = $issuer->issue('contact', '198.51.100.7');
        $solution = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        // Native: the same core verifier the validator wraps.
        $verifier = new Verifier($storage);
        $native = $verifier->verify($solution, self::SECRET, 'contact', '198.51.100.7');
        self::assertTrue($native->isOk(), 'the native path accepts the proof for the non-post-solve scope');

        // Provider: the SiteVerify controller with the same verifier.
        $storage2 = new ArrayStorage();
        $issuer2 = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage2);
        $challenge2 = $issuer2->issue('contact', '198.51.100.7');
        $solution2 = $this->solve($challenge2->prefix, $challenge2->salt, $challenge2->targetBits, $challenge2->nonce);
        $verifier2 = new Verifier($storage2);
        $controller = new \BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController(
            $verifier2,
            self::SECRET,
            ['compat-secret-42' => 'contact'],
            $storage2,
        );
        $response = $controller->siteverify(\Symfony\Component\HttpFoundation\Request::create('/kiwi-captcha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], http_build_query([
            'secret' => 'compat-secret-42',
            'response' => $solution2,
            'remoteip' => '198.51.100.7',
        ])));
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame(true, $body['success'] ?? null, 'the provider surface agrees with the native path on the non-post-solve scope');
    }

    private function solve(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $rawSalt = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$rawSalt, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }
}
