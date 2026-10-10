<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Rsw;
use KiwiCaptcha\RswModulusIdentity;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Tests\Support\RswFixture;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The one canonical rsw modulus identity across the repository. The
 * shared cross-language fixture (protocol/rsw-identity-v1/fixtures.json)
 * pins the exact 64 hex characters the rsw-keygen, the Rust crate and
 * the PHP core must all produce from the same modulus. These tests also
 * pin the identity-selection rules of the rotation keyring: A -> A
 * acceptance, A -> B rejection, rotated A historical with B active,
 * unknown-identity rejection, and the legacy base64-text alias inside
 * and outside its migration window.
 */
final class RswModulusIdentityTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** @return array<string, mixed> */
    private static function fixture(): array
    {
        $path = \dirname(__DIR__).'/../../protocol/rsw-identity-v1/fixtures.json';
        $decoded = json_decode((string) file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function requireGmp(): void
    {
        if (!\extension_loaded('gmp')) {
            self::markTestSkipped('the rsw tests need the gmp extension');
        }
    }

    private function issue(int $t = Config::MIN_RSW_T): array
    {
        $storage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $issuer = new Issuer(new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Rsw,
            ttlSecs: 120,
            minDurationMs: 0,
            rswModulusN: RswFixture::MODULUS_N_B64,
            rswLambda: RswFixture::LAMBDA_B64,
            rswT: $t,
        ), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7', maxProtocolVersionToEmit: ChallengeRecord::RSW_IDENTITY_PROTOCOL_VERSION);

        return [$challenge, $storage->find($challenge->nonce), $storage, $issuer];
    }

    private function solveToken(Challenge $challenge, ?string $proof = null, int $counter = 0): string
    {
        $proof ??= RswFixture::sequentialProof($challenge->prefix, $challenge->nonce, $challenge->t);

        return SolutionToken::create($challenge->nonce, $counter, 5000, [], null, null, $proof)->encode();
    }

    private function solveTokenForRecord(ChallengeRecord $record): string
    {
        $proof = RswFixture::sequentialProof($record->prefix, $record->nonce, $record->t);

        return SolutionToken::create($record->nonce, 0, 5000, [], null, null, $proof)->encode();
    }

    public function testTheThreeComponentsAgreeOnTheCanonicalFingerprint(): void
    {
        $fixture = self::fixture();
        self::assertSame(RswFixture::MODULUS_N_B64, $fixture['modulus_n_b64'], 'the fixture and both language suites share one modulus');
        self::assertSame(
            $fixture['rsw_modulus_n_sha256'],
            RswModulusIdentity::fingerprint($fixture['modulus_n_b64']),
            'the PHP canonical fingerprint equals the keygen rsw_modulus_n_sha256',
        );
        self::assertSame(
            $fixture['rsw_modulus_n_sha256'],
            Issuer::rswModulusSha256($fixture['modulus_n_b64']),
            'the Issuer identity is the one canonical primitive',
        );
        self::assertSame(
            hash('sha256', RswModulusIdentity::decodeCanonicalModulus($fixture['modulus_n_b64'])),
            RswModulusIdentity::fingerprint($fixture['modulus_n_b64']),
            'the canonical fingerprint hashes the DECODED 256-byte modulus',
        );
        self::assertSame(
            $fixture['legacy_base64_text_sha256'],
            RswModulusIdentity::legacyBase64TextFingerprint($fixture['modulus_n_b64']),
            'the historical base64-text rule stays available as the clearly named legacy alias',
        );
        self::assertNotSame(
            $fixture['rsw_modulus_n_sha256'],
            $fixture['legacy_base64_text_sha256'],
            'the canonical identity and the legacy alias are distinct values',
        );
        self::assertSame(
            [$fixture['rsw_modulus_n_sha256'], $fixture['legacy_base64_text_sha256']],
            RswModulusIdentity::allFingerprints($fixture['modulus_n_b64']),
        );
    }

    public function testCanonicalDecodeEnforcesTheRoundTripAndLength(): void
    {
        $fixture = self::fixture();
        foreach ([
            'truncated' => substr($fixture['modulus_n_b64'], 0, 40),
            'missing padding' => rtrim($fixture['modulus_n_b64'], '='),
            'base64url spelling' => strtr($fixture['modulus_n_b64'], '+/', '-_'),
            'empty' => '',
        ] as $label => $spelling) {
            try {
                RswModulusIdentity::fingerprint($spelling);
                self::fail("{$label}: a non-canonical modulus must be refused");
            } catch (\InvalidArgumentException) {
            }
        }
        self::assertSame(256, \strlen(RswModulusIdentity::decodeCanonicalModulus($fixture['modulus_n_b64'])));
    }

    public function testTheKeyringAcceptsBothIdentityFormsAndResolvesThem(): void
    {
        $this->requireGmp();
        $fixture = self::fixture();
        $legacyAlias = $fixture['legacy_base64_text_sha256'];
        [$challenge, $record, , ] = $this->issue();
        self::assertSame($fixture['rsw_modulus_n_sha256'], $record->rswModulusSha256);
        self::assertSame(5, $record->protocolVersion);

        // The canonical keyring key resolves the v5 record with the
        // migration mode off (the default).
        $canonicalIssuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8),
            new ArrayStorage(),
            rswVerificationKeys: [$fixture['rsw_modulus_n_sha256'] => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
        );
        self::assertSame(
            RswFixture::MODULUS_N_B64,
            $canonicalIssuer->responseFromRecord($record)?->rswModulus,
            'the canonical keyring entry resolves the v5 record',
        );

        // The legacy-alias key is refused with the mode off and accepted
        // with the explicit migration mode on.
        try {
            new Issuer(
                new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8),
                new ArrayStorage(),
                rswVerificationKeys: [$legacyAlias => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
            );
            self::fail('a legacy-alias keyring key must be refused while the migration mode is off');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('allowLegacyRswIdentity', $e->getMessage());
        }
        $migrationIssuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8),
            new ArrayStorage(),
            rswVerificationKeys: [$legacyAlias => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
            allowLegacyRswIdentity: true,
        );
        self::assertSame(
            RswFixture::MODULUS_N_B64,
            $migrationIssuer->responseFromRecord($record)?->rswModulus,
            'the legacy keyring key resolves while the migration mode is on',
        );

        // A keyring key that is neither form of the paired modulus is
        // refused at construction.
        try {
            new Issuer(
                new Config(secretKey: Vectors::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8),
                new ArrayStorage(),
                rswVerificationKeys: [str_repeat('f', 64) => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
            );
            self::fail('a mismatched keyring identity must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('canonical SHA-256', $e->getMessage());
        }
    }

    public function testAnUnknownIdentityNeverFallsThroughToTheActivePair(): void
    {
        $this->requireGmp();
        $fixture = self::fixture();

        // A verifier whose active pair is B (the secondary fixture pair)
        // cannot verify an A-bound record: the identity A is unknown, and
        // the record is refused rather than verified under B.
        [$challenge, , $storageA, ] = $this->issue();
        $verifier = new Verifier(
            $storageA,
            now: static fn (): int => self::ISSUED_AT,
            rswModulusN: $fixture['secondary']['modulus_n_b64'],
            rswLambda: $fixture['secondary']['lambda_b64'],
        );
        $outcome = $verifier->verify($this->solveToken($challenge), Vectors::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::UnsupportedRswParams, $outcome->error, 'an unknown identity must never resolve through the active pair');

        // The rotation keyring restores it: active B, historical A in the
        // keyring, and a fresh A-bound record verifies.
        [$rotatedChallenge, , $rotatedStorage, ] = $this->issue();
        $rotated = new Verifier(
            $rotatedStorage,
            now: static fn (): int => self::ISSUED_AT,
            rswModulusN: $fixture['secondary']['modulus_n_b64'],
            rswLambda: $fixture['secondary']['lambda_b64'],
            rswVerificationKeys: [$fixture['rsw_modulus_n_sha256'] => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]],
        );
        self::assertTrue($rotated->verify($this->solveToken($rotatedChallenge), Vectors::SECRET, 'login', '198.51.100.7')->isOk());
    }

    public function testABProofComputedForAnABoundRecordNeverPasses(): void
    {
        $this->requireGmp();
        $fixture = self::fixture();
        $bTrapdoor = new Rsw($fixture['secondary']['modulus_n_b64'], $fixture['secondary']['lambda_b64']);
        $keyring = [$fixture['rsw_modulus_n_sha256'] => ['modulus_n' => RswFixture::MODULUS_N_B64, 'lambda' => RswFixture::LAMBDA_B64]];

        // The attacker holds an A-bound challenge and the public modulus
        // B: they compute the sequential squarings under B and submit
        // that final value.
        [$challenge, , $storageB, ] = $this->issue();
        $bProof = $bTrapdoor->expectedProofHex($challenge->prefix, $challenge->nonce, $challenge->t);
        $tokenB = $this->solveToken($challenge, $bProof);

        // A verifier configured with B as its active pair refuses: the
        // authenticated identity A does not resolve under B.
        $bVerifier = new Verifier(
            $storageB,
            now: static fn (): int => self::ISSUED_AT,
            rswModulusN: $fixture['secondary']['modulus_n_b64'],
            rswLambda: $fixture['secondary']['lambda_b64'],
        );
        self::assertSame(VerifyError::UnsupportedRswParams, $bVerifier->verify($tokenB, Vectors::SECRET, 'login', '198.51.100.7')->error);

        // Even a verifier that does own A (through the keyring) must not
        // accept the B proof: the proof is checked under A and fails.
        [$attackChallenge, , $attackStorage, ] = $this->issue();
        $attackProof = $bTrapdoor->expectedProofHex($attackChallenge->prefix, $attackChallenge->nonce, $attackChallenge->t);
        $attackToken = $this->solveToken($attackChallenge, $attackProof);
        $aVerifier = new Verifier(
            $attackStorage,
            now: static fn (): int => self::ISSUED_AT,
            rswModulusN: $fixture['secondary']['modulus_n_b64'],
            rswLambda: $fixture['secondary']['lambda_b64'],
            rswVerificationKeys: $keyring,
        );
        $outcome = $aVerifier->verify($attackToken, Vectors::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk(), 'a B proof must never satisfy an A-bound record');
        self::assertSame(VerifyError::InsufficientWork, $outcome->error);
    }

    public function testTheLegacyAliasResolvesOnlyPreV5Identities(): void
    {
        $this->requireGmp();
        $fixture = self::fixture();
        $legacyAlias = $fixture['legacy_base64_text_sha256'];
        [$challenge, $record, $storage, ] = $this->issue();

        // A legacy v2 record issued before the v5 grammar carries the
        // legacy base64-text identity and resolves through the active
        // pair (the bounded migration window).
        $legacyStorage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $legacyRecord = $this->resign($record->toArray(), 2, $legacyAlias);
        $legacyStorage->store($legacyRecord);
        $legacyToken = $this->solveTokenForRecord($legacyRecord);
        // With the migration mode OFF (the default) the temporary
        // grammar is refused fail-closed...
        $strictVerifier = new Verifier($legacyStorage, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64);
        self::assertSame(
            VerifyError::UnsupportedRswParams,
            $strictVerifier->verify($legacyToken, Vectors::SECRET, 'login', '198.51.100.7')->error,
            'the legacy alias requires the explicit migration mode',
        );
        // ... and accepted while the bounded migration window is enabled.
        $legacyStorage2 = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $legacyStorage2->store($legacyRecord);
        $legacyVerifier = new Verifier($legacyStorage2, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64, allowLegacyRswIdentity: true);
        self::assertTrue($legacyVerifier->verify($legacyToken, Vectors::SECRET, 'login', '198.51.100.7')->isOk(), 'a pre-v5 legacy identity resolves in the migration window');

        // The same legacy alias on a v5 record is not a canonical
        // identity: resolution refuses it (the v5 grammar admits only the
        // canonical fingerprint).
        $v5LegacyIdentity = $this->resign($record->toArray(), 5, $legacyAlias);
        $v5Storage = new ArrayStorage(now: static fn (): int => self::ISSUED_AT);
        $v5Storage->store($v5LegacyIdentity);
        $v5Verifier = new Verifier($v5Storage, now: static fn (): int => self::ISSUED_AT, rswModulusN: RswFixture::MODULUS_N_B64, rswLambda: RswFixture::LAMBDA_B64, allowLegacyRswIdentity: true);
        self::assertSame(
            VerifyError::UnsupportedRswParams,
            $v5Verifier->verify($this->solveTokenForRecord($v5LegacyIdentity), Vectors::SECRET, 'login', '198.51.100.7')->error,
            'a v5 record resolves its canonical fingerprint exactly, never the legacy alias',
        );
    }

    /**
     * Re-sign a record's wire fields under a different protocol version
     * and identity: the test-side mirror of the pre-v5 issuance.
     *
     * @param array<string, mixed> $wire
     */
    private function resign(array $wire, int $protocolVersion, ?string $identity): ChallengeRecord
    {
        $wire['protocol_version'] = $protocolVersion;
        $wire['rsw_modulus_sha256'] = $identity;
        $payload = Issuer::canonicalPayload(
            $protocolVersion,
            $wire['nonce'],
            $wire['scope'],
            $wire['binding_tag'],
            $wire['issued_at'],
            $wire['expires_at'],
            PoWAlgorithm::from($wire['algorithm']),
            $wire['m_kib'],
            $wire['t'],
            $wire['p'],
            $wire['target_bits'],
            $wire['salt'],
            $wire['min_duration_ms'],
            $wire['region'] ?? null,
            $wire['policy_version'] ?? 1,
            $wire['request_binding'] ?? null,
            $wire['issuer'] ?? null,
            $wire['kid'] ?? 1,
            $wire['decoy_field'] ?? null,
            $wire['execution_version'] ?? null,
            $wire['execution_commitment'] ?? null,
            $identity,
        );
        $signature = Issuer::signPayloadV2($payload, Vectors::SECRET);
        $challenge = base64_encode($payload).'.'.$signature;
        $wire['challenge'] = $challenge;
        $wire['prefix'] = $challenge.'|'.$wire['salt'].'|';

        // The rewritten challenge needs a fresh record-metadata MAC.
        return \KiwiCaptcha\Tests\Fixtures\ServerState::seal(ChallengeRecord::fromArray($wire));
    }
}
