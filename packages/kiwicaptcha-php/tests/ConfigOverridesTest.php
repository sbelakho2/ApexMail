<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\RswModulusIdentity;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\RswFixture;
use PHPUnit\Framework\TestCase;

/**
 * Config::withOverrides() and Issuer::withConfig(): the override
 * round-trip must carry every constructor parameter, and the variant
 * issuer must carry every constructor field of its source — the
 * reflection-free replacement seam for building issuance variants.
 */
final class ConfigOverridesTest extends TestCase
{
    /**
     * A Config with each constructor parameter at a non-default valid
     * value, so a dropped field in a round-trip is observable.
     */
    private function fullConfig(): Config
    {
        return new Config(
            secretKey: 'override-master-secret-0123456789abcdef',
            algorithm: PoWAlgorithm::Rsw,
            mKib: 64,
            t: 4,
            p: 1,
            targetBits: 3,
            argon2TargetBits: 5,
            ttlSecs: 90,
            minDurationMs: 1_000,
            solverMaxHashes: 1_234_567,
            bindingMode: BindingMode::None,
            policyVersion: 7,
            issuer: 'override-issuer',
            kid: 9,
            executionKey: 'override-execution-key-0123456789abcdef',
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: 80_000,
            tenantId: 'tenant-a',
        );
    }

    /**
     * Every public field of the Config, keyed by name: the exact set
     * the round-trip must preserve.
     *
     * @return array<string, mixed>
     */
    private function fields(Config $c): array
    {
        return [
            'secretKey' => $c->secretKey,
            'algorithm' => $c->algorithm,
            'mKib' => $c->mKib,
            't' => $c->t,
            'p' => $c->p,
            'targetBits' => $c->targetBits,
            'argon2TargetBits' => $c->argon2TargetBits,
            'ttlSecs' => $c->ttlSecs,
            'minDurationMs' => $c->minDurationMs,
            'solverMaxHashes' => $c->solverMaxHashes,
            'bindingMode' => $c->bindingMode,
            'policyVersion' => $c->policyVersion,
            'issuer' => $c->issuer,
            'kid' => $c->kid,
            'executionKey' => $c->executionKey,
            'rswModulusN' => $c->rswModulusN,
            'rswLambda' => $c->rswLambda,
            'rswT' => $c->rswT,
            'tenantId' => $c->tenantId,
        ];
    }

    public function testEveryParameterSurvivesAnEmptyOverrideRoundTrip(): void
    {
        $config = $this->fullConfig();

        self::assertSame($this->fields($config), $this->fields($config->withOverrides()));
    }

    public function testOnlyTheOverriddenFieldsChange(): void
    {
        $config = $this->fullConfig();
        $overridden = $config->withOverrides(ttlSecs: 45, policyVersion: 8);

        $expected = $this->fields($config);
        $expected['ttlSecs'] = 45;
        $expected['policyVersion'] = 8;

        self::assertSame($expected, $this->fields($overridden));
    }

    public function testAnOverrideViolatingAConstructorInvariantStillThrows(): void
    {
        $config = $this->fullConfig();

        try {
            $config->withOverrides(ttlSecs: Config::MAX_TTL_SECS + 1);
            self::fail('a TTL override above the ceiling must be refused by the re-validated constructor');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('challenge TTL', $e->getMessage());
        }

        try {
            $config->withOverrides(secretKey: 'tooshort');
            self::fail('a short secret override must be refused by the re-validated constructor');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('at least 32 bytes', $e->getMessage());
        }
    }

    public function testWithConfigKeepsEveryIssuerFieldAndAdoptsTheNewConfig(): void
    {
        $storage = new ArrayStorage();
        $now = static fn (): int => 1_800_000_000;
        $keyring = [
            RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64) => [
                'modulus_n' => RswFixture::MODULUS_N_B64,
                'lambda' => RswFixture::LAMBDA_B64,
            ],
        ];
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, policyVersion: 1),
            $storage,
            $now,
            'eu',
            $keyring,
            true,
        );

        $config = new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 60, policyVersion: 2);
        $variant = $issuer->withConfig($config);

        self::assertSame($config, $variant->config(), 'the variant issues under the new Config');
        // The private constructor fields are carried over verbatim: the
        // constructor is the one authoritative copy of the deployment
        // state, so the variant can never drift from its source.
        foreach ([
            'storage' => $storage,
            'now' => $now,
            'region' => 'eu',
            'rswVerificationKeys' => $keyring,
            'allowLegacyRswIdentity' => true,
        ] as $field => $expected) {
            $property = new \ReflectionProperty(Issuer::class, $field);
            self::assertSame($expected, $property->getValue($variant), "the variant keeps the source issuer's $field");
        }

        // Behavioral proof: the variant mints through the carried
        // storage and clock, stamped with the new Config's lifetime,
        // epoch and region.
        $challenge = $variant->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record, 'the variant issues against the carried storage');
        self::assertSame(1_800_000_000, $record->issuedAt, 'the variant reads the carried clock override');
        self::assertSame(60, $record->expiresAt - $record->issuedAt, 'the variant stamps the overridden TTL');
        self::assertSame(2, $record->policyVersion, 'the variant stamps the overridden policy epoch');
        self::assertSame('eu', $record->region, 'the variant stamps the carried region');
    }

    public function testWithTtlOverridesOnlyTheLifetime(): void
    {
        $config = $this->fullConfig();
        $issuer = new Issuer($config, new ArrayStorage());

        $variant = $issuer->withTtl(45);

        self::assertSame(45, $variant->config()->ttlSecs);
        $expected = $this->fields($config);
        $expected['ttlSecs'] = 45;
        self::assertSame($expected, $this->fields($variant->config()));
    }
}
