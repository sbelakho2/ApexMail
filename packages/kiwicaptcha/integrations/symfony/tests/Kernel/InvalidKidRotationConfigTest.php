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

        self::assertTrue(true);
    }
}
