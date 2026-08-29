<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
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

    public function testStrictKidVerificationWiresTheCurrentKeyAsTheRingWithEmptyHistorical(): void
    {
        // strict_kid_verification: true must turn the effective keyring
        // into exactly [currentKid => currentSecret] even when the
        // historical map is empty, so the verifier strictly resolves
        // record.kid == currentKid from the very first deployment.
        $container = $this->load([
            'kid' => 3,
            'strict_kid_verification' => true,
        ]);
        $container->compile();

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(
            [3 => str_repeat('a', 32)],
            $verifier->getArgument('secretsByKid'),
            'strict mode wires the current key alone as the accepted ring'
        );
    }

    public function testStrictKidVerificationKeepsTheHistoricalRingWhenConfigured(): void
    {
        // With a historical map present, strict mode changes nothing: the
        // ring is the merged map plus the current key (the rotation
        // keyring is already exact per kid).
        $container = $this->load([
            'kid' => 3,
            'secrets_by_kid' => [2 => str_repeat('b', 32)],
            'strict_kid_verification' => true,
        ]);
        $container->compile();

        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        self::assertSame(
            [2 => str_repeat('b', 32), 3 => str_repeat('a', 32)],
            $verifier->getArgument('secretsByKid'),
            'strict mode does not alter the merged rotation ring'
        );
    }

    public function testRotationConfiguredWithoutDedicatedRootKeysLogsTheAdvisoryNotes(): void
    {
        // Finding: routine signing-key rotation still resets the
        // abuse-identity secrets by default. The extension records a
        // container build log note (never throws) telling the operator
        // to configure dedicated stable rate_limit_pepper /
        // risk.master_secret keys; with a dedicated pepper the note is
        // not emitted.
        $container = $this->load([
            'kid' => 3,
            'secrets_by_kid' => [2 => str_repeat('b', 32)],
            'rate_limit' => 10,
        ]);
        $log = $container->getCompiler()->getLog();
        $joined = implode("\n", $log);
        self::assertStringContainsString('rate_limit_pepper is not configured', $joined, 'the pepper advisory must be logged when rotation is configured without a dedicated pepper');
        self::assertStringContainsString('signing-key rotation', $joined);

        $container = $this->load([
            'kid' => 3,
            'rate_limit_pepper' => 'dedicated-stable-pepper',
        ]);
        $log = $container->getCompiler()->getLog();
        $joined = implode("\n", $log);
        self::assertStringNotContainsString('rate_limit_pepper is not configured', $joined, 'no advisory when a dedicated pepper is configured');

        // No rotation configured: no advisory at all.
        $container = $this->load([]);
        $joined = implode("\n", $container->getCompiler()->getLog());
        self::assertStringNotContainsString('rate_limit_pepper is not configured', $joined);
        self::assertStringNotContainsString('risk.master_secret is not configured', $joined);
    }

    public function testRotationConfiguredWithoutRiskMasterSecretLogsTheRiskAdvisory(): void
    {
        // The risk block needs a Predis client (compile-time wiring), so
        // register one the same way the risk wiring tests do.
        $loadWithRisk = static function (array $riskOverrides): ContainerBuilder {
            $container = new ContainerBuilder();
            $container->setParameter('kernel.environment', 'test');
            $container->setParameter('kernel.project_dir', __DIR__);
            $container->setDefinition('my.storage', new Definition(ArrayStorage::class, []));
            $container->setDefinition('my.redis.client', new Definition(\Predis\Client::class, []));
            (new KiwiCaptchaExtension())->load([array_merge([
                'secret_key' => str_repeat('a', 32),
                'storage' => 'my.storage',
                'kid' => 3,
                'redis_service' => 'my.redis.client',
                'risk' => array_merge(['enabled' => true], $riskOverrides),
            ])], $container);

            return $container;
        };

        $joined = implode("\n", $loadWithRisk([])->getCompiler()->getLog());
        self::assertStringContainsString('risk.master_secret is not configured', $joined, 'the risk advisory must be logged when the risk block is enabled without a dedicated master secret');

        // With risk disabled, no risk advisory (the master secret is
        // unused); with a dedicated master secret, none either.
        $container = $this->load(['kid' => 3]);
        $joined = implode("\n", $container->getCompiler()->getLog());
        self::assertStringNotContainsString('risk.master_secret is not configured', $joined);

        $joined = implode("\n", $loadWithRisk(['master_secret' => str_repeat('d', 32)])->getCompiler()->getLog());
        self::assertStringNotContainsString('risk.master_secret is not configured', $joined, 'no advisory when a dedicated master secret is configured');
    }

    public function testResumeClaimTtlSecsReachesTheVerifierDefinitionWhenTheCoreParamExists(): void
    {
        // The recovery-claim TTL is wired by name ($resumeClaimTtlSecs)
        // only when the installed core's Verifier declares the parameter
        // (added in the round-94 core; Symfony's ResolveNamedArgumentsPass
        // refuses a named argument the class does not declare). This
        // assertion flips to the strict branch automatically once the
        // parameter lands in kiwicaptcha-php.
        $container = $this->load(['resume_claim_ttl_secs' => 90]);
        $container->compile();
        $verifier = $container->getDefinition('kiwi_captcha.verifier');
        $constructor = (new \ReflectionClass(Verifier::class))->getConstructor();
        $hasParam = $constructor !== null
            && \in_array('resumeClaimTtlSecs', array_map(
                static fn (\ReflectionParameter $p): string => $p->getName(),
                $constructor->getParameters(),
            ), true);

        if ($hasParam) {
            self::assertSame(90, $verifier->getArgument('resumeClaimTtlSecs'), 'the configured recovery-claim TTL must reach the verifier');
        } else {
            self::assertArrayNotHasKey('resumeClaimTtlSecs', $verifier->getArguments(), 'the named arg is only set when the installed core declares the parameter');
        }
    }
}
