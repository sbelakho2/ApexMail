<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use KiwiCaptcha\RswModulusIdentity;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Support\RswFixture;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * The documented rsw trapdoor rotation keyring
 * (kiwi_captcha.rsw_verification_keys) must be reachable through the
 * bundle, not only the core. The extension wired neither the Issuer nor
 * the Verifier with it. A rotation, or a mixed-node rollout, therefore
 * dropped every outstanding rsw challenge the moment the active pair
 * changed.
 *
 * This test boots two independent compiled containers over one shared
 * storage. Container A is the issuing configuration. Container B is the
 * post-rotation configuration with A kept in the keyring. It proves end
 * to end that the bundle's Issuer reconstructs and the bundle's
 * Verifier accepts the A-bound record after the rotation. The control
 * container (B active, no keyring) refuses the same record.
 */
final class RswRotationKeyringWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SECONDARY_N = 'gErZx6ByUHUa/gVrpiSDgLqurJepEQIdA3j5004QK2SXCyOAeeleXeXhzc+llE/IB7IyYuMEy+w2lQDfxLYkcP1ajKmmL1VUGG6DFfBOlJBa2cexg/v2Moc2e2sWFunXRzgtGFi0rX9kAJprkAwkbkoTP+sv8Tq88zDGdoQAPzOQI08WjGhq/Gj6ARJ7hEgNjg7RVTXzj5lh8ze+v0JQqx6KDwE9Weuwd89eASfce/cFvjl6C0gz1NPMc6kmT3XQSUEIrV7lqR5F9exY7LVkEcdikMeAETXT0xNIEpcAdwpg2mCgCrJP9M+iPFdVgLrmmEfitJYbsoL3trw3hcQ/5w==';

    private const SECONDARY_LAMBDA = 'DNRI+lzYOz7pGWbxKjbZ80XeRHWQ6BnPs4wY+4fOar1CTenzP2QjCWPJx8f29Tstml6eo30aFGRr27NJk6vQcbLvdHddayIiAnFzgjGhdUGir2DE85kyOEC4pfEbzxdiU+wEgm9FRIy9M0KkWzRqCwdoUzEeZOxGGFGtckBmbLg25PWt1wFV17OHzYSaBcJP2YhdDuSSC8fKFjzbcgFsB1+GU+oLV9eBNQwNt3KLcbnMDc4f2Yg4craAjh9jJpllzAkhMLcFlVmTR0nTmAsyZO9YaWRbnqrpGxcY8RYrKbSFbXTt4VgtLxaaErk6osZQcYwMrHXZEuQsnz4o0nIQ8A==';

    private function requireGmp(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw keyring test needs the gmp extension');
        }
    }

    /**
     * One compiled container over a shared in-memory storage, carrying
     * the given kiwi_captcha configuration.
     *
     * @param array<string, mixed> $options
     */
    private function container(array $options, ArrayStorage $storage): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        // The bundle's validator-side wiring (the quarantine marker, the
        // validator) references the framework's request_stack service;
        // this bare wiring container registers the service itself, the
        // same object FrameworkBundle would provide.
        $container->setDefinition('request_stack', new Definition(\Symfony\Component\HttpFoundation\RequestStack::class, []));
        $container->setParameter('kernel.project_dir', __DIR__);
        $definition = new Definition(ArrayStorage::class, []);
        $definition->setSynthetic(true);
        $definition->setPublic(true);
        $container->setDefinition('my.storage', $definition);
        $container->set('my.storage', $storage);
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => self::SECRET,
            'storage' => 'my.storage',
        ], $options)], $container);
        $container->compile();

        return $container;
    }

    public function testTheWiredKeyringReachesBothCoreServices(): void
    {
        $this->requireGmp();
        $keyring = [
            RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64) => [
                'modulus_n' => RswFixture::MODULUS_N_B64,
                'lambda' => RswFixture::LAMBDA_B64,
            ],
        ];
        $container = $this->container([
            'algorithm' => 'rsw',
            'rsw_modulus_n' => self::SECONDARY_N,
            'rsw_lambda' => self::SECONDARY_LAMBDA,
            'rsw_t' => 10_000,
            'rsw_verification_keys' => $keyring,
        ], new ArrayStorage());

        $issuer = $container->get('kiwi_captcha.issuer');
        $verifier = $container->get('kiwi_captcha.verifier');

        // The compiled services behave with the keyring: the historical
        // identity resolves the A pair on both.
        $identityA = RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64);
        self::assertSame(RswFixture::MODULUS_N_B64, $this->keyringModulus($issuer, 'rswModuliByHash', $identityA));
        self::assertSame(RswFixture::MODULUS_N_B64, $this->keyringModulus($verifier, 'rswModulusByHash', $identityA));
    }

    public function testTheLegacyMigrationModeReachesBothCoreServices(): void
    {
        $this->requireGmp();
        $options = [
            'algorithm' => 'rsw',
            'rsw_modulus_n' => RswFixture::MODULUS_N_B64,
            'rsw_lambda' => RswFixture::LAMBDA_B64,
            'rsw_t' => 10_000,
        ];

        // The default: the temporary grammar is off on both services.
        $default = $this->container($options, new ArrayStorage());
        self::assertFalse(
            (new \ReflectionProperty($default->get('kiwi_captcha.issuer'), 'allowLegacyRswIdentity'))->getValue($default->get('kiwi_captcha.issuer')),
            'the issuer defaults the legacy mode off',
        );
        self::assertFalse(
            (new \ReflectionProperty($default->get('kiwi_captcha.verifier'), 'allowLegacyRswIdentity'))->getValue($default->get('kiwi_captcha.verifier')),
            'the verifier defaults the legacy mode off',
        );

        // The declared drain window reaches both core services.
        $migration = $this->container($options + ['rsw_legacy_identity' => true], new ArrayStorage());
        self::assertTrue(
            (new \ReflectionProperty($migration->get('kiwi_captcha.issuer'), 'allowLegacyRswIdentity'))->getValue($migration->get('kiwi_captcha.issuer')),
            'the issuer receives the declared migration window',
        );
        self::assertTrue(
            (new \ReflectionProperty($migration->get('kiwi_captcha.verifier'), 'allowLegacyRswIdentity'))->getValue($migration->get('kiwi_captcha.verifier')),
            'the verifier receives the declared migration window',
        );
    }

    public function testIssuedUnderAReconstructsAndVerifiesAfterTheRotation(): void
    {
        $this->requireGmp();
        $identityA = RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64);
        $shared = new ArrayStorage();

        // A: the issuing configuration, no keyring yet.
        $containerA = $this->container([
            'algorithm' => 'rsw',
            'rsw_modulus_n' => RswFixture::MODULUS_N_B64,
            'rsw_lambda' => RswFixture::LAMBDA_B64,
            'rsw_t' => 10_000,
        ], $shared);
        $challenge = $containerA->get('kiwi_captcha.issuer')->issue(
            'login',
            '198.51.100.7',
            maxProtocolVersionToEmit: \KiwiCaptcha\ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION,
        );
        $record = $shared->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(5, $record->protocolVersion, 'the current writer arms the identity');
        self::assertSame($identityA, $record->rswModulusSha256);

        // B: the post-rotation configuration, A kept in the keyring.
        $containerB = $this->container([
            'algorithm' => 'rsw',
            'rsw_modulus_n' => self::SECONDARY_N,
            'rsw_lambda' => self::SECONDARY_LAMBDA,
            'rsw_t' => 10_000,
            'rsw_verification_keys' => [$identityA => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
        ], $shared);

        // Stored-response reconstruction uses the historical A pair.
        self::assertSame(
            RswFixture::MODULUS_N_B64,
            $containerB->get('kiwi_captcha.issuer')->responseFromRecord($record)?->rswModulus,
            'the bundle issuer reconstructs the rotated record through the keyring',
        );

        // Verification uses the historical A pair too.
        $token = SolutionToken::create(
            $record->nonce,
            0,
            5000,
            [],
            null,
            null,
            RswFixture::sequentialProof($record->prefix, $record->nonce, $record->t),
        )->encode();
        $outcome = $containerB->get('kiwi_captcha.verifier')->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'the bundle verifier accepts the rotated record: '.$outcome->code());

        // Control: B without the keyring cannot verify a fresh A-bound
        // record either (the identity never falls through to the active
        // pair).
        $controlChallenge = $containerA->get('kiwi_captcha.issuer')->issue(
            'login',
            '198.51.100.7',
            maxProtocolVersionToEmit: \KiwiCaptcha\ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION,
        );
        $controlRecord = $shared->find($controlChallenge->nonce);
        self::assertNotNull($controlRecord);
        $controlToken = SolutionToken::create(
            $controlRecord->nonce,
            0,
            5000,
            [],
            null,
            null,
            RswFixture::sequentialProof($controlRecord->prefix, $controlRecord->nonce, $controlRecord->t),
        )->encode();
        $containerC = $this->container([
            'algorithm' => 'rsw',
            'rsw_modulus_n' => self::SECONDARY_N,
            'rsw_lambda' => self::SECONDARY_LAMBDA,
            'rsw_t' => 10_000,
        ], $shared);
        $outcome = $containerC->get('kiwi_captcha.verifier')->verify($controlToken, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk());
        self::assertSame('unsupported_rsw_params', $outcome->code());
    }

    private function keyringModulus(object $service, string $property, string $identity): ?string
    {
        $map = (new \ReflectionProperty($service, $property))->getValue($service);
        self::assertIsArray($map);

        return $map[$identity] ?? null;
    }
}
