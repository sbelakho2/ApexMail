<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Cross-field kid-rotation validation (root-level config tree rules on
 * kid / secret_key / secrets_by_kid / revoked_kids). Each combination
 * below is a guaranteed-outage or silently-weakened-security
 * configuration and must be refused with the exact tree message at
 * configuration processing time, never at first challenge.
 */
final class InvalidKidRotationConfigTest extends TestCase
{
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

    private function expectRefused(array $options, string $messageBody): void
    {
        try {
            $this->load($options);
            self::fail('the invalid kid-rotation config must be refused by the tree: '.json_encode($options));
        } catch (InvalidConfigurationException $e) {
            self::assertSame(
                'Invalid configuration for path "kiwi_captcha": '.$messageBody,
                $e->getMessage(),
                'the refusal must carry the exact actionable message'
            );
        }
    }

    private function expectSecretsNodeRefused(array $options, string $messageBody): void
    {
        try {
            $this->load($options);
            self::fail('the invalid secrets_by_kid config must be refused by the tree: '.json_encode($options));
        } catch (InvalidConfigurationException $e) {
            self::assertSame(
                'Invalid configuration for path "kiwi_captcha.secrets_by_kid": '.$messageBody,
                $e->getMessage(),
                'the refusal must carry the exact actionable message'
            );
        }
    }

    public function testCurrentKidInRevokedKidsIsRefused(): void
    {
        $this->expectRefused(['kid' => 2, 'revoked_kids' => [2]], 'kiwi_captcha.kid must not appear in kiwi_captcha.revoked_kids: issuing under a revoked kid is a guaranteed outage, since every freshly issued challenge would fail verification with UnknownKid. Remove the kid from revoked_kids (revocation applies to superseded keys only) or bump kid to a new signing key id');
    }

    public function testCurrentKidInSecretsByKidIsRefused(): void
    {
        $this->expectRefused(['kid' => 3, 'secrets_by_kid' => [3 => str_repeat('b', 32)]], 'kiwi_captcha.secrets_by_kid must not contain the current kiwi_captcha.kid: a historical entry for the current signing key would make the verifier select the wrong secret. The current secret belongs in kiwi_captcha.secret_key, not in the historical map');
    }

    public function testHistoricalKidAtOrAboveCurrentKidIsRefused(): void
    {
        // A historical entry above the current kid silently extends the
        // verifier rollback/forward guard; an entry equal to the current
        // kid is the dedicated current-kid-in-map refusal above.
        $this->expectRefused(['kid' => 3, 'secrets_by_kid' => [4 => str_repeat('b', 32)]], 'every kiwi_captcha.secrets_by_kid key must be strictly below kiwi_captcha.kid: the map holds historical signing keys only, and a future key would silently extend the verifier rollback/forward guard (a record kid above the newest ring key) so no deployment should accept it. Bump kid above the newest historical key when rotating');
    }

    public function testValidRotationShapesStayAccepted(): void
    {
        // Defaults: kid 1 + empty map + empty revocation.
        $this->load([]);
        // kid N with an empty map (no rotation history yet).
        $this->load(['kid' => 7]);
        // The documented rotation shape: current kid above the historical
        // map, revoked kids covering superseded keys only.
        $this->load(['kid' => 3, 'secrets_by_kid' => [2 => str_repeat('b', 32)], 'revoked_kids' => [1]]);
        // A revoked historical kid is the emergency-response shape.
        $this->load(['kid' => 3, 'secrets_by_kid' => [2 => str_repeat('b', 32)], 'revoked_kids' => [2]]);
        // A multi-entry canonical key set stays accepted.
        $this->load(['kid' => 7, 'secrets_by_kid' => [2 => str_repeat('b', 32), 6 => str_repeat('c', 32)]]);

        self::assertTrue(true);
    }

    public function testNonCanonicalSecretsByKidKeysAreRefused(): void
    {
        // Hardening finding: secrets_by_kid validated values only, so
        // keys like 'foo' reached the verifier as kid 0 and '02' aliased
        // the int kid 2. Every key must be a canonical decimal integer in
        // 1..4294967295, refused here with the exact node message.
        $message = 'secrets_by_kid keys must be canonical decimal integers in 1..4294967295: a historical signing kid is written without leading zeros and without text, so "02", "0" and "foo" are all refused';
        foreach ([
            'text key' => ['kid' => 3, 'secrets_by_kid' => ['foo' => str_repeat('b', 32)]],
            'leading-zero alias key' => ['kid' => 3, 'secrets_by_kid' => ['02' => str_repeat('b', 32)]],
            'zero key' => ['kid' => 3, 'secrets_by_kid' => ['0' => str_repeat('b', 32)]],
            'above-u32 key' => ['kid' => 3, 'secrets_by_kid' => ['4294967296' => str_repeat('b', 32)]],
        ] as $case) {
            $this->expectSecretsNodeRefused($case, $message);
        }
    }

    public function testDuplicateCanonicalSecretsByKidKeysAreRefused(): void
    {
        // PHP casts a bare '2' key to int 2 at array-construction time, so
        // the expressible duplicate-canonical pair is the leading-zero
        // alias '02' (a string key) next to the int 2: both resolve to
        // the same kid and one secret would silently overwrite the other.
        $this->expectSecretsNodeRefused(
            ['kid' => 3, 'secrets_by_kid' => ['02' => str_repeat('b', 32), 2 => str_repeat('c', 32)]],
            'secrets_by_kid keys must be distinct canonical kids: two entries that resolve to the same integer would silently overwrite one historical secret'
        );
    }

    public function testPerScopeCapAtOrAboveTheGlobalCapIsRefusedWithTheExactMessage(): void
    {
        // The per-scope concentration cap is inert at or above the global
        // cap (the global cap admits fewer), so it can never provide
        // anti-starvation — refused at configuration time. The default
        // stays valid: null, derived as max(1, global - 1).
        $message = 'kiwi_captcha.argon2_max_per_tenant must be strictly below argon2_max_concurrent_verifications when the global cap is positive: a per-scope concentration cap at or above the global cap can never bind (the global cap admits fewer), so it provides no anti-starvation. Leave the option unset to derive max(1, global - 1) or set it strictly below the global cap';
        foreach ([
            'equal to the global cap' => ['argon2_max_concurrent_verifications' => 2, 'argon2_max_per_tenant' => 2],
            'above the global cap' => ['argon2_max_concurrent_verifications' => 2, 'argon2_max_per_tenant' => 8],
            'global 8, per-tenant 10' => ['argon2_max_concurrent_verifications' => 8, 'argon2_max_per_tenant' => 10],
        ] as $case) {
            $this->expectRefused($case, $message);
        }

        // Valid shapes: unset (the default), strictly below the global
        // cap, and a cap with an unlimited global (0).
        $this->load([]);
        $this->load(['argon2_max_concurrent_verifications' => 8, 'argon2_max_per_tenant' => 3]);
        $this->load(['argon2_max_concurrent_verifications' => 0, 'argon2_max_per_tenant' => 3]);
    }
}
