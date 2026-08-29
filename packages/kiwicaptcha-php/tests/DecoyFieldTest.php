<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\MalformedRecordException;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The decoy (honeypot) field surface — the PHP mirror of the Rust
 * `issue_challenge_with_decoy` / `decoy_field` extension.
 *
 * The contract, pinned byte-for-byte against the Rust crate:
 *  - armed: the canonical v2 signing input gains exactly one segment,
 *    `|<decoy_field>`, appended after the kid, 19 segments with the
 *    decoy last. The name comes from the shared server-side pool.
 *  - unarmed: the canonical input is byte-identical to the pre-extension
 *    18-field format, and neither JSON surface, client-facing challenge
 *    nor stored record, carries the `decoy_field` key; it is absent, not
 *    null.
 *  - the decoy is authenticated: stripping, renaming or splicing it
 *    breaks the v2 signature the verifier re-checks.
 *  - stored values must match `[A-Za-z0-9_-]{1,64}`, the malformed-record
 *    fail-closed.
 *  - legacy records and tokens with no decoy key anywhere keep
 *    verifying.
 */
final class DecoyFieldTest extends TestCase
{
    use VerifyFixtureTrait;

    /** The pre-extension canonical vector, pinned (ProtocolV2Test pins the same bytes). */
    private const LEGACY_CANONICAL = 'v2|nonce123|login|tag456|111|222|sha256|0|1|1|8|c2FsdA==|5||1|||1';

    private function shaConfig(): Config
    {
        return new Config(
            secretKey: Vectors::SECRET,
            algorithm: PoWAlgorithm::Sha256,
            mKib: 0,
            t: 1,
            p: 1,
            targetBits: 8,
            argon2TargetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
        );
    }

    private function issuer(ArrayStorage $storage): Issuer
    {
        return new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);
    }

    /** The canonical signing input carried (base64-encoded) inside the challenge string. */
    private function decodedCanonical(Challenge $challenge): string
    {
        $payload = explode('.', $challenge->challenge, 2)[0];
        $decoded = base64_decode($payload, true);
        self::assertNotFalse($decoded);

        return $decoded;
    }

    /** Brute-force the winning counter for an 8-bit challenge (fast). */
    private function solveCounter(Challenge $challenge): int
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return $counter - 1;
    }

    // ── (a) armed issuance: pool name, 19 segments, decoy last ──────

    public function testArmedIssuanceSignsAPoolNameAsTheFinalCanonicalSegment(): void
    {
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);

        $decoy = $challenge->decoyField;
        self::assertNotNull($decoy, 'an armed issuance must carry a decoy field name');
        self::assertContains($decoy, Issuer::DECOY_FIELD_POOL, "the decoy name must come from the server-side pool (got {$decoy})");
        self::assertTrue(Config::isValidDecoyFieldName($decoy));

        // The stored record carries the same armed name.
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame($decoy, $record->decoyField);

        // The canonical signing input: 18 base fields + the decoy segment,
        // decoy last (after the kid), matching the Rust mirror.
        $canonical = $this->decodedCanonical($challenge);
        $segments = explode('|', $canonical);
        self::assertCount(19, $segments, 'v2 canonical input: 18 base fields + the decoy segment');
        self::assertSame($decoy, $segments[18], 'the decoy name must be the FINAL canonical segment');
        self::assertSame((string) ($record->kid ?? 1), $segments[17], 'the kid stays immediately before the decoy');
        self::assertStringEndsWith('|'.$decoy, $canonical);

        // Two armed issuances pick independently (a fresh `CSPRNG` draw per
        // challenge; across a handful of issuances at least two names
        // appear — the picks must not collapse to a constant).
        $seen = [];
        for ($i = 0; $i < 40 && \count($seen) < 2; $i++) {
            $issued = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
            $seen[$issued->decoyField] = true;
        }
        self::assertGreaterThanOrEqual(2, \count($seen), 'per-issuance decoy picks must vary across challenges');
    }

    // ── (b) unarmed: byte-identical to the pre-change canonical ─────

    public function testUnarmedCanonicalIsByteIdenticalToThePreExtensionVector(): void
    {
        // The pinned pre-extension canonical (18 fields, kid last).
        self::assertSame(self::LEGACY_CANONICAL, Issuer::canonicalPayload(
            'nonce123',
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            'c2FsdA==',
            5,
        ));

        // An explicit null decoy renders nothing extra — byte-identical
        // to the legacy call without the argument.
        self::assertSame(self::LEGACY_CANONICAL, Issuer::canonicalPayload(
            'nonce123',
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            'c2FsdA==',
            5,
            null,
            1,
            null,
            null,
            1,
            null,
        ));

        // An armed decoy appends exactly ONE segment after the kid.
        self::assertSame(
            self::LEGACY_CANONICAL.'|company_website',
            Issuer::canonicalPayload(
                'nonce123',
                'login',
                'tag456',
                111,
                222,
                PoWAlgorithm::Sha256,
                0,
                1,
                1,
                8,
                'c2FsdA==',
                5,
                null,
                1,
                null,
                null,
                1,
                'company_website',
            ),
        );
    }

    public function testUnarmedIssuanceKeepsTheLegacyCanonicalShape(): void
    {
        // The plain path (and the explicit false arm) issues NO decoy: the
        // canonical string keeps the exact pre-extension shape (18 fields,
        // kid last), and neither JSON surface carries the key.
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);

        foreach ([
            'plain issue()' => $issuer->issue('login', Vectors::CLIENT_IP),
            'issueWithDecoyField(armed: false)' => $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP, false),
        ] as $label => $challenge) {
            self::assertNull($challenge->decoyField, "{$label}: no decoy on the client challenge");

            $record = $storage->find($challenge->nonce);
            self::assertNotNull($record);
            self::assertNull($record->decoyField, "{$label}: no decoy on the stored record");

            $canonical = $this->decodedCanonical($challenge);
            $segments = explode('|', $canonical);
            self::assertCount(18, $segments, "{$label}: the base v2 canonical input stays 18 fields (no decoy segment)");
            self::assertSame((string) ($record->kid ?? 1), $segments[17], "{$label}: kid stays the final field when no decoy is armed");

            self::assertArrayNotHasKey('decoy_field', $challenge->toArray(), "{$label}: the challenge key is absent when no decoy is armed");
            self::assertArrayNotHasKey('decoy_field', $record->toArray(), "{$label}: the record key is absent when no decoy is armed");
        }
    }

    // ── (c) verification: armed passes; tampering is BadSignature ───

    public function testArmedChallengeVerifiesEndToEnd(): void
    {
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $counter = $this->solveCounter($challenge);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, ['wd' => false])->encode();

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('a decoy-armed challenge must verify transparently, got %s', $outcome->code()));
    }

    /**
     * @param array<string, mixed> $recordData
     */
    private function verifyWithMutatedRecord(array $recordData, string $nonce, string $token): VerifyError
    {
        $storage = new ArrayStorage();
        $storage->store(ChallengeRecord::fromArray($recordData));
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        $error = $outcome->error;
        self::assertNotNull($error, 'a decoy-tampered record must fail verification');

        return $error;
    }

    public function testTheDecoyIsCoveredByTheSignature(): void
    {
        // Any change to the authenticated decoy name breaks the signature:
        // renaming it, stripping it from an armed record, or splicing one
        // onto an unarmed record all fail the v2 verification.
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);

        $armed = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $armedRecord = $storage->find($armed->nonce);
        self::assertNotNull($armedRecord);
        $counter = $this->solveCounter($armed);
        $armedToken = SolutionToken::create($armed->nonce, $counter, 5000, [])->encode();

        // Sanity: the armed record verifies as issued.
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify(
            $armedToken,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $armedRecord->issuedAtNs + 1_000_000,
        );
        self::assertTrue($outcome->isOk(), sprintf('the armed record must verify as issued, got %s', $outcome->code()));

        // Renamed to a different pool name.
        $other = Issuer::DECOY_FIELD_POOL[0] === $armed->decoyField
            ? Issuer::DECOY_FIELD_POOL[1]
            : Issuer::DECOY_FIELD_POOL[0];
        $renamed = $armedRecord->toArray();
        $renamed['decoy_field'] = $other;
        self::assertSame(VerifyError::BadSignature, $this->verifyWithMutatedRecord($renamed, $armed->nonce, $armedToken));

        // Stripped (the client-cannot-remove-it property).
        $stripped = $armedRecord->toArray();
        unset($stripped['decoy_field']);
        self::assertSame(VerifyError::BadSignature, $this->verifyWithMutatedRecord($stripped, $armed->nonce, $armedToken));

        // Spliced onto an unarmed, unsigned-for-decoy record.
        $plain = $issuer->issue('login', Vectors::CLIENT_IP);
        $plainRecord = $storage->find($plain->nonce);
        self::assertNotNull($plainRecord);
        $plainCounter = $this->solveCounter($plain);
        $plainToken = SolutionToken::create($plain->nonce, $plainCounter, 5000, [])->encode();
        $spliced = $plainRecord->toArray();
        $spliced['decoy_field'] = Issuer::DECOY_FIELD_POOL[0];
        self::assertSame(VerifyError::BadSignature, $this->verifyWithMutatedRecord($spliced, $plain->nonce, $plainToken));
    }

    // ── (d) alphabet validation on stored values ────────────────────

    public function testFromArrayRejectsNonConformingDecoyNames(): void
    {
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertNotNull($record->decoyField);

        // The issuer's decoy alphabet ([A-Za-z0-9_-], 1..=64): the
        // separator `|`, an identifier-shaped `.`, whitespace, NUL, the
        // empty string and an over-long name are all malformed — none can
        // alter the canonical segment structure. Mirrors the Rust
        // validate_record rejection set.
        foreach (['company|website', 'company.website', 'company website', "name\0", '', str_repeat('x', 65), 'café'] as $bad) {
            $data = $record->toArray();
            $data['decoy_field'] = $bad;
            try {
                ChallengeRecord::fromArray($data);
                self::fail("decoy name ".var_export($bad, true).' must be malformed');
            } catch (MalformedRecordException $e) {
                self::assertStringContainsString('decoy_field', $e->getMessage());
                self::assertStringContainsString('[A-Za-z0-9_-]', $e->getMessage());
            }
        }

        // The armed record itself stays valid, and the boundary shapes
        // pass: a 64-byte name, the full alphabet, null and absent.
        self::assertSame($record->decoyField, ChallengeRecord::fromArray($record->toArray())->decoyField);
        $edge = $record->toArray();
        $edge['decoy_field'] = str_repeat('a', 64);
        self::assertSame(str_repeat('a', 64), ChallengeRecord::fromArray($edge)->decoyField);
        $edge['decoy_field'] = 'A-Z_0-9-allowed';
        self::assertSame('A-Z_0-9-allowed', ChallengeRecord::fromArray($edge)->decoyField);
        $null = $record->toArray();
        $null['decoy_field'] = null;
        self::assertNull(ChallengeRecord::fromArray($null)->decoyField, 'an explicit JSON null decodes to null (serde Option semantics)');
    }

    public function testVerifierFailsClosedOnANonConformingStoredDecoyName(): void
    {
        // A hand-rolled record (never through fromArray) with a bad decoy
        // name: the verifier's structural validation rejects it as
        // MalformedRecord — the Rust validate_record fail-closed mirror.
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $armed = $storage->find($challenge->nonce);
        self::assertNotNull($armed);

        foreach (['company|website', 'company.website', str_repeat('x', 65), ''] as $bad) {
            $record = new ChallengeRecord(
                nonce: $armed->nonce,
                scope: $armed->scope,
                bindingTag: $armed->bindingTag,
                issuedAt: $armed->issuedAt,
                expiresAt: $armed->expiresAt,
                algorithm: $armed->algorithm,
                mKib: $armed->mKib,
                t: $armed->t,
                p: $armed->p,
                targetBits: $armed->targetBits,
                salt: $armed->salt,
                prefix: $armed->prefix,
                challenge: $armed->challenge,
                minDurationMs: $armed->minDurationMs,
                issuedAtNs: $armed->issuedAtNs,
                protocolVersion: $armed->protocolVersion,
                region: $armed->region,
                policyVersion: $armed->policyVersion,
                requestBinding: $armed->requestBinding,
                issuer: $armed->issuer,
                kid: $armed->kid,
                hostname: $armed->hostname,
                decoyField: $bad,
            );
            $freshStorage = new ArrayStorage();
            $freshStorage->store($record);
            $token = SolutionToken::create($record->nonce, 1, 5000, [])->encode();
            $verifier = new Verifier($freshStorage, now: static fn (): int => Vectors::NOW);
            $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $record->issuedAtNs + 1_000_000);
            self::assertSame(VerifyError::MalformedRecord, $outcome->error, "decoy name ".var_export($bad, true).' must fail closed as a malformed record');
        }
    }

    // ── (e) JSON: the key is omitted when null on both surfaces ─────

    public function testJsonSerializationOmitsTheDecoyKeyWhenNullOnBothSurfaces(): void
    {
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);

        // Armed: both surfaces carry the optional string key.
        $armed = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $armedRecord = $storage->find($armed->nonce);
        self::assertNotNull($armedRecord);
        self::assertSame($armed->decoyField, $armed->toArray()['decoy_field'] ?? null);
        self::assertSame($armed->decoyField, $armedRecord->toArray()['decoy_field'] ?? null);
        self::assertStringContainsString(
            '"decoy_field":"'.$armed->decoyField.'"',
            json_encode($armedRecord->toArray(), JSON_UNESCAPED_SLASHES),
        );

        // Unarmed: absent on both — never a JSON null key.
        $plain = $issuer->issue('login', Vectors::CLIENT_IP);
        $plainRecord = $storage->find($plain->nonce);
        self::assertNotNull($plainRecord);
        self::assertArrayNotHasKey('decoy_field', $plain->toArray());
        self::assertArrayNotHasKey('decoy_field', $plainRecord->toArray());
        self::assertStringNotContainsString(
            'decoy_field',
            json_encode($plainRecord->toArray(), JSON_UNESCAPED_SLASHES),
            'the record key must be absent (not JSON null) when no decoy is armed — the old byte format',
        );
        self::assertStringNotContainsString(
            'decoy_field',
            json_encode($plain->toArray(), JSON_UNESCAPED_SLASHES),
        );
    }

    public function testRedisRoundTripPreservesTheDecoyAndOmitsTheKeyWhenNull(): void
    {
        // Armed: the stored envelope JSON carries the optional string key
        // and find() decodes it back; the armed record then verifies
        // end-to-end through the Redis path (single-snapshot read ->
        // fromArray -> signature over the 19-segment canonical).
        $client = new FakePredisClient();
        $storage = new RedisStorage($client);
        $issuer = new Issuer($this->shaConfig(), $storage, now: static fn (): int => Vectors::NOW);

        $armed = $issuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $raw = $client->store['kiwicaptcha:'.$armed->nonce] ?? null;
        self::assertNotNull($raw);
        self::assertStringContainsString('"decoy_field":"'.$armed->decoyField.'"', $raw);

        $found = $storage->find($armed->nonce);
        self::assertNotNull($found);
        self::assertSame($armed->decoyField, $found->decoyField);

        $counter = $this->solveCounter($armed);
        $token = SolutionToken::create($armed->nonce, $counter, 5000, [])->encode();
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $found->issuedAtNs + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('the Redis round-tripped armed record must verify, got %s', $outcome->code()));

        // Unarmed: the stored envelope JSON never contains the key.
        $plainClient = new FakePredisClient();
        $plainStorage = new RedisStorage($plainClient);
        $plainIssuer = new Issuer($this->shaConfig(), $plainStorage, now: static fn (): int => Vectors::NOW);
        $plain = $plainIssuer->issue('login', Vectors::CLIENT_IP);
        $plainRaw = $plainClient->store['kiwicaptcha:'.$plain->nonce] ?? null;
        self::assertNotNull($plainRaw);
        self::assertStringNotContainsString('decoy_field', $plainRaw);
    }

    // ── (f) cross-compat: legacy records/tokens keep verifying ──────

    public function testLegacyV1RecordAndTokenStillVerify(): void
    {
        // The pinned Rust v1 vector (no decoy key anywhere) keeps
        // verifying unchanged — the wire-compatibility guarantee.
        $storage = new ArrayStorage();
        $storage->store($this->recordFromVector(Vectors::SHA));

        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW, acceptLegacyV1: true);
        $outcome = $verifier->verify($this->tokenFor(Vectors::SHA), Vectors::SECRET, 'login', Vectors::CLIENT_IP);

        self::assertTrue($outcome->isOk(), sprintf('the legacy v1 vector must keep verifying, got %s', $outcome->code()));
    }

    public function testLegacyV2RecordWithoutTheDecoyKeyStillVerifies(): void
    {
        // A v2 record whose JSON never carried the decoy key (the exact
        // pre-extension stored shape) decodes with a null decoy and
        // verifies against its token with the legacy 18-field canonical
        // bytes.
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issue('login', Vectors::CLIENT_IP);
        $issued = $storage->find($challenge->nonce);
        self::assertNotNull($issued);

        $data = $issued->toArray();
        self::assertArrayNotHasKey('decoy_field', $data, 'the unarmed record JSON never carries the key');
        $legacy = ChallengeRecord::fromArray($data);
        self::assertNull($legacy->decoyField);

        $freshStorage = new ArrayStorage();
        $freshStorage->store($legacy);
        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $verifier = new Verifier($freshStorage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $legacy->issuedAtNs + 1_000_000);

        self::assertTrue($outcome->isOk(), sprintf('a legacy-shape v2 record must keep verifying, got %s', $outcome->code()));
    }
}
