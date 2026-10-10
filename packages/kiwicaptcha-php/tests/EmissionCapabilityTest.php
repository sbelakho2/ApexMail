<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\EmissionCapabilityExceededException;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\RswModulusIdentity;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\RswFixture;
use PHPUnit\Framework\TestCase;

/**
 * The emission-capability ceiling is a real protocol authority, not a
 * hint: every requested extension is checked against it, arming beyond
 * it fails issuance explicitly, and no writer ever emits a protocol
 * version above the confirmed ceiling. The one documented fallback is
 * the rsw identity, which degrades to the identityless base shape below
 * the feature version.
 */
final class EmissionCapabilityTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private function requireGmp(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw tests need the gmp extension');
        }
    }

    private function issuer(array $config = []): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(...array_merge([
            'secretKey' => Vectors::SECRET,
            'targetBits' => 8,
            'ttlSecs' => 120,
            'minDurationMs' => 0,
            'executionKey' => 'execution-key-0123456789abcdef-012345',
        ], $config)), $storage, now: static fn (): int => self::ISSUED_AT);

        return [$issuer, $storage];
    }

    private function record(Challenge $challenge, ArrayStorage $storage): ChallengeRecord
    {
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return $record;
    }

    public function testACeilingBelowTheBaseProtocolIsRejected(): void
    {
        [$issuer] = $this->issuer();
        foreach ([0, 1] as $ceiling) {
            try {
                $issuer->issue('login', '198.51.100.7', maxProtocolVersionToEmit: $ceiling);
                self::fail("ceiling {$ceiling} must be rejected");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('at least the base protocol version', $e->getMessage());
            }
        }
    }

    public function testArmingBeyondTheConfirmedCeilingFailsExplicitly(): void
    {
        [$issuer] = $this->issuer();

        try {
            $issuer->issueWithDecoyField('login', '198.51.100.7', maxProtocolVersionToEmit: ChallengeRecord::BASE_PROTOCOL_VERSION);
            self::fail('decoy arming below version 3 must fail explicitly');
        } catch (EmissionCapabilityExceededException $e) {
            self::assertStringContainsString('the decoy field requires an emission ceiling', $e->getMessage());
        }

        try {
            $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action', maxProtocolVersionToEmit: ChallengeRecord::DECOY_PROTOCOL_VERSION);
            self::fail('execution arming below version 4 must fail explicitly');
        } catch (EmissionCapabilityExceededException $e) {
            self::assertStringContainsString('the execution program requires an emission ceiling', $e->getMessage());
        }
    }

    public function testNoEmissionEverExceedsTheConfirmedCeiling(): void
    {
        // sha/decoy/execution matrix across every confirmable ceiling.
        $expected = [
            2 => ['base' => 2, 'decoy' => null, 'execution' => null],
            3 => ['base' => 2, 'decoy' => 3, 'execution' => null],
            4 => ['base' => 2, 'decoy' => 3, 'execution' => 4],
            5 => ['base' => 2, 'decoy' => 3, 'execution' => 4],
            6 => ['base' => 2, 'decoy' => 3, 'execution' => 4],
        ];
        foreach ($expected as $ceiling => $row) {
            [$issuer, $storage] = $this->issuer();
            $base = $issuer->issue('login', '198.51.100.7', maxProtocolVersionToEmit: $ceiling);
            self::assertSame($row['base'], $this->record($base, $storage)->protocolVersion, "base at ceiling {$ceiling}");

            try {
                $decoy = $issuer->issueWithDecoyField('login', '198.51.100.7', maxProtocolVersionToEmit: $ceiling);
                self::assertNotNull($row['decoy'], "decoy at ceiling {$ceiling} must have been refused");
                self::assertSame($row['decoy'], $this->record($decoy, $storage)->protocolVersion, "decoy at ceiling {$ceiling}");
            } catch (EmissionCapabilityExceededException) {
                self::assertNull($row['decoy'], "decoy at ceiling {$ceiling} must be admitted");
            }

            try {
                $execution = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action', maxProtocolVersionToEmit: $ceiling);
                self::assertNotNull($row['execution'], "execution at ceiling {$ceiling} must have been refused");
                self::assertSame($row['execution'], $this->record($execution, $storage)->protocolVersion, "execution at ceiling {$ceiling}");
            } catch (EmissionCapabilityExceededException) {
                self::assertNull($row['execution'], "execution at ceiling {$ceiling} must be admitted");
            }
            foreach ([$base, ...(isset($decoy) ? [$decoy] : []), ...(isset($execution) ? [$execution] : [])] as $challenge) {
                self::assertLessThanOrEqual($ceiling, $this->record($challenge, $storage)->protocolVersion, 'no emission may exceed the confirmed ceiling');
            }
            unset($decoy, $execution);
        }
    }

    public function testTheRswIdentityIsTheOnlyDocumentedFallback(): void
    {
        $this->requireGmp();
        $config = [
            'algorithm' => PoWAlgorithm::Rsw,
            'rswModulusN' => RswFixture::MODULUS_N_B64,
            'rswLambda' => RswFixture::LAMBDA_B64,
            'rswT' => Config::MIN_RSW_T,
        ];
        $identity = RswModulusIdentity::fingerprint(RswFixture::MODULUS_N_B64);

        foreach ([2, 4] as $ceiling) {
            [$issuer, $storage] = $this->issuer($config);
            $record = $this->record($issuer->issue('login', '198.51.100.7', maxProtocolVersionToEmit: $ceiling), $storage);
            self::assertSame(ChallengeRecord::BASE_PROTOCOL_VERSION, $record->protocolVersion, "rsw at ceiling {$ceiling} falls back to the base shape");
            self::assertNull($record->rswModulusSha256, 'no identity below the feature version');
        }
        foreach ([ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION, 6] as $ceiling) {
            [$issuer, $storage] = $this->issuer($config);
            $record = $this->record($issuer->issue('login', '198.51.100.7', maxProtocolVersionToEmit: $ceiling), $storage);
            self::assertSame(ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION, $record->protocolVersion, "rsw at ceiling {$ceiling} arms the identity");
            self::assertSame($identity, $record->rswModulusSha256);
        }
    }
}
