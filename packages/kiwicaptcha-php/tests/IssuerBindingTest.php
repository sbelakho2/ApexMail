<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Deployment issuer binding: the issued record carries an optional
 * deployment identity (null = unbound), and the record JSON always
 * includes the `issuer` key (byte parity with the Rust serde schema, 21
 * keys). The issuer is the final field of the signed v2 canonical
 * payload, appended after `request_binding`. A verifier configured with
 * an expected issuer rejects any record whose issuer does not match
 * exactly (WrongIssuer), including unbound records, creating a
 * dev/staging/production compartment even when deployments share secret
 * keys.
 */
final class IssuerBindingTest extends TestCase
{
    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /** @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string} */
    private function issue(?string $issuer): array
    {
        $storage = new ArrayStorage();
        $issuerInstance = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: $issuer),
            $storage,
        );
        $challenge = $issuerInstance->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return [$storage, $record, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    public function testConfigIssuerIsStampedOnTheRecordAndWire(): void
    {
        [, $record] = $this->issue('prod');

        self::assertSame('prod', $record->issuer);
        $data = $record->toArray();
        self::assertSame('prod', $data['issuer']);
        self::assertSame('prod', ChallengeRecord::fromArray($data)->issuer);
    }

    public function testUnboundRecordCarriesNullIssuerInTheWire(): void
    {
        [, $record] = $this->issue(null);

        self::assertNull($record->issuer);
        self::assertArrayHasKey('issuer', $record->toArray(), 'the issuer key is ALWAYS present');
        self::assertNull($record->toArray()['issuer']);
        self::assertNull(ChallengeRecord::fromArray($record->toArray())->issuer);
    }

    public function testFromArrayAcceptsAbsentIssuerAsNull(): void
    {
        // Legacy records (or records written before the issuer field) have
        // no issuer key at all — must decode as unbound. The fuzz corpus has
        // no issuer field, so this default keeps the 659-accepted split.
        $data = $this->issue('prod')[1]->toArray();
        unset($data['issuer']);

        self::assertNull(ChallengeRecord::fromArray($data)->issuer);
    }

    public function testWireKeySetIncludesIssuerAndKidAsTheFinalKeys(): void
    {
        $keys = ChallengeRecord::WIRE_KEYS;

        self::assertCount(23, $keys);
        self::assertSame('issuer', $keys[20], 'issuer is the penultimate wire key, appended after request_binding');
        self::assertSame('kid', $keys[21], 'kid is the final wire key');
        self::assertSame($keys, \array_keys($this->issue('prod')[1]->toArray()));
    }

    public function testIssuerIsThePenultimateFieldOfTheSignedCanonicalPayload(): void
    {
        // Canonical v2 payload: `...|min_duration_ms|region|policy_version|
        // request_binding|issuer|kid`; kid (default 1) is the final
        // segment, appended after the issuer.
        [, $record] = $this->issue('staging');

        $canonical = Issuer::canonicalPayload(
            $record->nonce,
            $record->scope,
            $record->bindingTag,
            $record->issuedAt,
            $record->expiresAt,
            $record->algorithm,
            $record->mKib,
            $record->t,
            $record->p,
            $record->targetBits,
            $record->salt,
            $record->minDurationMs,
            $record->region,
            $record->policyVersion ?? 1,
            $record->requestBinding,
            $record->issuer,
            $record->kid ?? 1,
        );
        self::assertStringEndsWith('|staging|1', $canonical, 'the canonical must end with the issuer segment then the kid');
        self::assertSame('staging', explode('|', $canonical)[16], 'issuer is the 17th canonical field');
        self::assertSame('1', explode('|', $canonical)[17], 'kid is the 18th (final) canonical field');

        $signature = substr($record->challenge, strrpos($record->challenge, '.') + 1);
        self::assertSame(
            Issuer::signPayloadV2($canonical, Vectors::SECRET),
            $signature,
            'the v2 signature covers the issuer and the kid — two deployments issue different signatures',
        );

        // Two records issued under different deployments carry different
        // signatures even with the same secret key.
        [, $recordB] = $this->issue('prod');
        self::assertNotSame($record->challenge, $recordB->challenge);
    }

    public function testVerifierWithMatchingIssuerVerifies(): void
    {
        [$storage, $record, $token] = $this->issue('prod');

        $verifier = new Verifier($storage, expectedIssuer: 'prod');
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('matching issuer must verify, got %s', $outcome->code()));
    }

    public function testVerifierWithDifferentIssuerRejectsAndBurns(): void
    {
        [$storage, $record, $token] = $this->issue('prod');

        $verifier = new Verifier($storage, expectedIssuer: 'staging');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongIssuer, $outcome->error);
        self::assertNull($storage->find($record->nonce), 'a wrong-issuer verification burns the record');
    }

    public function testVerifierRejectsUnboundRecordFailClosed(): void
    {
        // A null record issuer is redeemable by every deployment, so an
        // issuer-configured verifier must fail closed on it.
        [$storage, , $token] = $this->issue(null);

        $verifier = new Verifier($storage, expectedIssuer: 'prod');
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongIssuer, $outcome->error);
    }

    public function testVerifierWithoutIssuerAcceptsAnyDeployment(): void
    {
        [$storage, $record, $token] = $this->issue('prod');

        $verifier = new Verifier($storage);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            '198.51.100.7',
            nowNs: $record->issuedAtNs + 1_000_000,
        );

        self::assertTrue($outcome->isOk(), sprintf('an unconfigured verifier must accept any issuer, got %s', $outcome->code()));
    }

    public function testSharedSecretDoesNotDefeatTheCompartment(): void
    {
        // Two deployments sharing the secret
        // key must still reject each other's challenges via the issuer.
        [$storageA, , $tokenA] = $this->issue('dev');

        $verifier = new Verifier($storageA, expectedIssuer: 'prod');
        $outcome = $verifier->verify($tokenA, Vectors::SECRET, 'login', '198.51.100.7');

        self::assertSame(VerifyError::WrongIssuer, $outcome->error, 'shared keys must not cross the issuer compartment');
    }

    public function testIssueWithProfileCarriesTheConfigIssuer(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: 'eu-prod'),
            $storage,
        );
        $challenge = $issuer->issueWithProfile('login', '198.51.100.7', \KiwiCaptcha\ChallengeProfile::sha(8));

        self::assertSame('eu-prod', $storage->find($challenge->nonce)?->issuer);
    }

    public function testWrongIssuerErrorValue(): void
    {
        self::assertSame('wrong_issuer', VerifyError::WrongIssuer->value);
        self::assertSame('challenge was issued by a different deployment', VerifyError::WrongIssuer->description());
    }

    public function testIssuerSurvivesTheRedisJsonWrappedRoundTrip(): void
    {
        // Storage-layer sanity: the issuer is a base canonical key (not
        // a runtime field), so it must survive the wrapped-JSON round
        // trip even though the canonical record parser strips state and
        // consumed_result.
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $client = new \KiwiCaptcha\Tests\Fixtures\FakePredisClient();
        $storage = new \KiwiCaptcha\Storage\RedisStorage($client);
        [, $record] = $this->issue('prod');
        $storage->store($record);

        $loaded = $storage->find($record->nonce);
        self::assertNotNull($loaded);
        self::assertSame('prod', $loaded->issuer);
    }
}
