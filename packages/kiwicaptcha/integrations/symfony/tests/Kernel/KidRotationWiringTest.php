<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * issuer / kid / secrets_by_kid / revoked_kids are now
 * first-class bundle configuration — the core's HMAC-key rotation and
 * emergency-revocation controls are reachable without replacing services.
 *
 * Argument access after compile(): the Config definition's named args are
 * reindexed into constructor positions (issuer=12, kid=13) by
 * ResolveNamedArgumentsPass, while the verifier's remain keyed by name
 * (its $region arg is only set when configured, which stops the pass).
 */
final class KidRotationWiringTest extends TestCase
{
    private function load(array $options): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', __DIR__);
        $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => str_repeat('a', 32),
            'storage' => 'my.storage',
        ], $options)], $container);

        return $container;
    }

    public function testIssuerKidAndRotationSecretsReachConfigAndVerifier(): void
    {
        $container = $this->load([
            'issuer' => 'auth-prod',
            'kid' => 3,
            'secrets_by_kid' => [2 => str_repeat('b', 32)],
            'revoked_kids' => [1],
        ]);
        $container->compile();

        self::assertSame('auth-prod', $container->getDefinition('kiwi_captcha.config')->getArgument(12));
        self::assertSame(3, $container->getDefinition('kiwi_captcha.config')->getArgument(13));

        // The verifier must receive the effective keyring: the historical
        // map merged with the current signing key (the same key the
        // issuer signs with). Without the current entry, every freshly
        // issued kid-3 challenge would fail UnknownKid the moment the
        // historical map is configured.
        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame('auth-prod', $verifier->getArgument('expectedIssuer'));
        self::assertSame([2 => str_repeat('b', 32), 3 => str_repeat('a', 32)], $verifier->getArgument('secretsByKid'));
        self::assertSame([1], $verifier->getArgument('revokedKids'));
    }

    public function testDefaultsKeepCurrentBehavior(): void
    {
        $container = $this->load([]);
        $container->compile();

        self::assertNull($container->getDefinition('kiwi_captcha.config')->getArgument(12));
        self::assertSame(1, $container->getDefinition('kiwi_captcha.config')->getArgument(13));
        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame([], $verifier->getArgument('secretsByKid'));
        self::assertSame([], $verifier->getArgument('revokedKids'));
        self::assertNull($verifier->getArgument('expectedIssuer'));
    }

    public function testHistoricalSecretsReachTheVerifierAsCanonicalIntKeys(): void
    {
        // The extension canonicalizes secrets_by_kid once, so the
        // verifier keyring is a pure array<int, string> — no textual kid
        // alias can survive into the keyring the core resolves.
        $container = $this->load([
            'kid' => 6,
            'secrets_by_kid' => [2 => str_repeat('b', 32), 5 => str_repeat('c', 32)],
        ]);
        $container->compile();

        $secrets = $container->getDefinition('kiwi_captcha.verifier')->getArgument('secretsByKid');
        self::assertSame(
            [2 => str_repeat('b', 32), 5 => str_repeat('c', 32), 6 => str_repeat('a', 32)],
            $secrets,
            'the effective keyring merges the canonical historical map with the current signing key, kid-sorted'
        );
        foreach (array_keys($secrets) as $kid) {
            self::assertIsInt($kid, 'every downstream consumer receives canonical int kid keys');
        }
    }
}
