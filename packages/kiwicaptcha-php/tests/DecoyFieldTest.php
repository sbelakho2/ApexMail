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
 *  - armed: protocol v3, the decoy-capable canonical. The signing input
 *    gains exactly one segment, `|<decoy_field>`, appended after the
 *    kid, 19 segments with the decoy last; the stored record's
 *    protocol_version is 3. The name comes from the shared
 *    combinatorial grammar, see {@see Issuer::composeDecoyName()}:
 *    a 27,840-prefix space with a per-issuance 16-hex `CSPRNG` suffix,
 *    an armed space of 27,840 * 2^64 names.
 *  - unarmed: protocol v2, byte-identical to the pre-extension 18-field
 *    format, and neither JSON surface, client-facing challenge nor
 *    stored record, carries the `decoy_field` key; it is absent, not
 *    null.
 *  - the decoy is authenticated: stripping, renaming or splicing it
 *    breaks the signature the verifier re-checks. The protocol-vs-decoy
 *    grammar is total. A protocol-v2 record
 *    that carries decoy_field is rejected explicitly, since the v2
 *    canonical never includes the segment. A protocol-v3 record without
 *    one is rejected too, because the decoy is mandatory on v3. The
 *    capability is therefore inferable from protocol_version, and a
 *    stored version flip can never change the effective protocol.
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

    // ── (a) armed issuance: armed name, 19 segments, decoy last ─────

    public function testArmedIssuanceSignsAnArmedNameAsTheFinalCanonicalSegment(): void
    {
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);

        $decoy = $challenge->decoyField;
        self::assertNotNull($decoy, 'an armed issuance must carry a decoy field name');
        self::assertTrue(Issuer::isGrammarDecoyName($decoy), "the decoy name must be a grammar prefix plus suffix (got {$decoy})");
        self::assertTrue(Issuer::isGrammarDecoyPrefix(substr((string) $decoy, 0, -17)), 'the name must start with a grammar prefix');
        self::assertTrue(Config::isValidDecoyFieldName($decoy));
        self::assertLessThanOrEqual(47, \strlen($decoy), 'the armed name (prefix + suffix) must be at most 47 bytes');

        // The stored record carries the same armed name, under protocol
        // v3 (the decoy-capable canonical).
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame($decoy, $record->decoyField);
        self::assertSame(3, $record->protocolVersion, 'an armed issuance writes protocol v3 (the decoy-capable canonical)');

        // The canonical signing input: 18 base fields + the decoy segment,
        // decoy last (after the kid), matching the Rust mirror.
        $canonical = $this->decodedCanonical($challenge);
        $segments = explode('|', $canonical);
        self::assertCount(19, $segments, 'the v3 canonical input: 18 base fields + the decoy segment');
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
        // kid last), the record stays protocol v2, and neither JSON
        // surface carries the key.
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
            self::assertSame(2, $record->protocolVersion, "{$label}: unarmed issuance stays protocol v2, byte-identical to the pre-decoy format");

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
        self::assertSame($record->decoyField, $outcome->decoyField(), 'the valid outcome exposes the authenticated decoy name from the verified record');
    }

    public function testStoredSuccessReplayExposesTheAuthenticatedDecoyName(): void
    {
        // The stored-result acceptance carries the record, so it populates
        // the authenticated decoy name exactly like the fresh path — the
        // validator consumes VerifyOutcome::decoyField(), never a
        // nonce-hash reconstruction.
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertNotNull($record->decoyField);

        $counter = $this->solveCounter($challenge);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $identity = 'op-'.hash('sha256', 'decoy-replay');
        $verifier = new Verifier($storage, now: static fn (): int => Vectors::NOW);
        $fresh = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 1_000_000,
            operationIdentity: $identity,
        );
        self::assertTrue($fresh->isOk(), sprintf('the fresh derivation must verify, got %s', $fresh->code()));
        self::assertSame($record->decoyField, $fresh->decoyField());

        $replay = $verifier->verify(
            $token,
            Vectors::SECRET,
            'login',
            Vectors::CLIENT_IP,
            nowNs: $record->issuedAtNs + 5_000_000,
            operationIdentity: $identity,
        );
        self::assertTrue($replay->isOk() && $replay->fromStoredResult, sprintf('the identity-proven replay must resolve the stored success, got %s', $replay->code()));
        self::assertSame($record->decoyField, $replay->decoyField(), 'the stored-result replay exposes the authenticated decoy name from the replayed record');
        self::assertNull($replay->solveDurationMs(), 'a stored-result replay reports no solve duration (the retry\'s receipt is not the solve\'s endpoint)');
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
        // renaming it fails the verification as BadSignature. Stripping it
        // from an armed v3 record is now refused by the grammar itself —
        // the decoy is mandatory on v3, so the stripped record is
        // decoyless-v3 MalformedRecord (the parser gate refuses it, and
        // the hand-rolled equivalent fails the verifier's structural
        // validation before any signature work). Splicing a decoy onto an
        // unarmed v2 record is rejected by the protocol grammar too — the
        // v2 canonical never includes the segment, so the v2-plus-decoy
        // combination cannot come from a conforming issuer
        // (MalformedRecord, see testV2RecordCarryingADecoyIsRejected).
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

        // Renamed to a different grammar name.
        $other = $armed->decoyField === 'secondary_contact_phone'
            ? 'billing_company_url'
            : 'secondary_contact_phone';
        $renamed = $armedRecord->toArray();
        $renamed['decoy_field'] = $other;
        self::assertSame(VerifyError::BadSignature, $this->verifyWithMutatedRecord($renamed, $armed->nonce, $armedToken));

        // Stripped (the client-cannot-remove-it property): the parser
        // gate refuses the decoyless v3 combination outright.
        $stripped = $armedRecord->toArray();
        unset($stripped['decoy_field']);
        try {
            ChallengeRecord::fromArray($stripped);
            self::fail('a stripped (decoyless) v3 record must be refused by fromArray');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version 3', $e->getMessage());
        }
        // The hand-rolled equivalent (bypassing the parser) fails the
        // verifier's structural validation as MalformedRecord — the
        // stored version could never verify as a plain-18-field v3.
        $handRolled = new ChallengeRecord(
            nonce: $armedRecord->nonce,
            scope: $armedRecord->scope,
            bindingTag: $armedRecord->bindingTag,
            issuedAt: $armedRecord->issuedAt,
            expiresAt: $armedRecord->expiresAt,
            algorithm: $armedRecord->algorithm,
            mKib: $armedRecord->mKib,
            t: $armedRecord->t,
            p: $armedRecord->p,
            targetBits: $armedRecord->targetBits,
            salt: $armedRecord->salt,
            prefix: $armedRecord->prefix,
            challenge: $armedRecord->challenge,
            minDurationMs: $armedRecord->minDurationMs,
            issuedAtNs: $armedRecord->issuedAtNs,
            protocolVersion: 3,
            region: $armedRecord->region,
            policyVersion: $armedRecord->policyVersion,
            requestBinding: $armedRecord->requestBinding,
            issuer: $armedRecord->issuer,
            kid: $armedRecord->kid,
            hostname: $armedRecord->hostname,
            decoyField: null,
        );
        $freshStorage = new ArrayStorage();
        $freshStorage->store($handRolled);
        $verifier2 = new Verifier($freshStorage, now: static fn (): int => Vectors::NOW);
        $outcome2 = $verifier2->verify($armedToken, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $armedRecord->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MalformedRecord, $outcome2->error, 'a stripped v3 record fails closed as MalformedRecord — never a plain-canonical verification');
    }

    public function testV2RecordCarryingADecoyIsRejected(): void
    {
        // The v2 canonical never includes the decoy segment: a
        // protocol-v2 record that carries decoy_field is rejected
        // explicitly on both acceptance surfaces — the strict parser
        // (ChallengeRecord::fromArray) and the verifier's malformed-record
        // path. An armed issuance writes protocol v3, so the capability
        // becomes inferable from protocol_version.
        $storage = new ArrayStorage();
        $issuer = $this->issuer($storage);

        $plain = $issuer->issue('login', Vectors::CLIENT_IP);
        $plainRecord = $storage->find($plain->nonce);
        self::assertNotNull($plainRecord);
        $spliced = $plainRecord->toArray();
        $spliced['decoy_field'] = 'secondary_contact_phone';

        try {
            ChallengeRecord::fromArray($spliced);
            self::fail('a protocol-v2 record carrying decoy_field must be rejected by fromArray');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version 2', $e->getMessage());
            self::assertStringContainsString('decoy_field', $e->getMessage());
        }

        // The verifier's malformed-record path rejects the same
        // combination on a hand-rolled record (never through fromArray).
        $bad = new ChallengeRecord(
            nonce: $plainRecord->nonce,
            scope: $plainRecord->scope,
            bindingTag: $plainRecord->bindingTag,
            issuedAt: $plainRecord->issuedAt,
            expiresAt: $plainRecord->expiresAt,
            algorithm: $plainRecord->algorithm,
            mKib: $plainRecord->mKib,
            t: $plainRecord->t,
            p: $plainRecord->p,
            targetBits: $plainRecord->targetBits,
            salt: $plainRecord->salt,
            prefix: $plainRecord->prefix,
            challenge: $plainRecord->challenge,
            minDurationMs: $plainRecord->minDurationMs,
            issuedAtNs: $plainRecord->issuedAtNs,
            protocolVersion: 2,
            region: $plainRecord->region,
            policyVersion: $plainRecord->policyVersion,
            requestBinding: $plainRecord->requestBinding,
            issuer: $plainRecord->issuer,
            kid: $plainRecord->kid,
            hostname: $plainRecord->hostname,
            decoyField: 'secondary_contact_phone',
        );
        $freshStorage = new ArrayStorage();
        $freshStorage->store($bad);
        $token = SolutionToken::create($bad->nonce, 1, 5000, [])->encode();
        $verifier = new Verifier($freshStorage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $bad->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a v2 record carrying a decoy fails closed as MalformedRecord');
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
        // pass: a 64-byte name, the full alphabet. An explicit JSON null
        // on an armed (v3) record is a decoyless v3 record, so the
        // combination is refused; the null
        // Option semantics survive on v2 (see the v2-based check below).
        self::assertSame($record->decoyField, ChallengeRecord::fromArray($record->toArray())->decoyField);
        $edge = $record->toArray();
        $edge['decoy_field'] = str_repeat('a', 64);
        self::assertSame(str_repeat('a', 64), ChallengeRecord::fromArray($edge)->decoyField);
        $edge['decoy_field'] = 'A-Z_0-9-allowed';
        self::assertSame('A-Z_0-9-allowed', ChallengeRecord::fromArray($edge)->decoyField);
        $null = $record->toArray();
        $null['decoy_field'] = null;
        try {
            ChallengeRecord::fromArray($null);
            self::fail('a protocol-v3 record with an explicit JSON null decoy must be refused');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version 3', $e->getMessage());
        }
        // The same explicit JSON null on an unarmed v2 record decodes to
        // null (serde Option semantics — v2 => no decoy).
        $v2 = $record->toArray();
        $v2['protocol_version'] = 2;
        unset($v2['decoy_field']);
        self::assertNull(ChallengeRecord::fromArray($v2)->decoyField, 'a decoyless v2 record (absent key) decodes to null');
        $v2Null = $v2;
        $v2Null['decoy_field'] = null;
        self::assertNull(ChallengeRecord::fromArray($v2Null)->decoyField, 'an explicit JSON null decodes to null on v2 (serde Option semantics)');
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
            'the record key must be absent (not JSON null) when no decoy is armed — the legacy byte format',
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

    public function testV3RecordWithoutADecoyIsRejected(): void
    {
        // The protocol-vs-decoy grammar is total: the
        // decoy is mandatory on v3, so a signed v2 record with its stored
        // version flipped to 3 (the same canonical bytes, the same valid
        // signature) must be rejected on both acceptance surfaces — the
        // strict parser (ChallengeRecord::fromArray) and the verifier's
        // malformed-record path. The authenticated canonical shape
        // itself establishes the protocol capability.
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issue('login', Vectors::CLIENT_IP);
        $issued = $storage->find($challenge->nonce);
        self::assertNotNull($issued);
        self::assertSame(2, $issued->protocolVersion, 'fixture is an unarmed v2 record');

        // fromArray: the version flip is refused explicitly.
        $flipped = $issued->toArray();
        $flipped['protocol_version'] = 3;
        try {
            ChallengeRecord::fromArray($flipped);
            self::fail('a protocol-v3 record without a decoy must be rejected by fromArray');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version 3', $e->getMessage());
            self::assertStringContainsString('decoy_field', $e->getMessage());
        }

        // The verifier's malformed-record path rejects the same
        // combination on a hand-rolled record (never through fromArray).
        $v3 = new ChallengeRecord(
            nonce: $issued->nonce,
            scope: $issued->scope,
            bindingTag: $issued->bindingTag,
            issuedAt: $issued->issuedAt,
            expiresAt: $issued->expiresAt,
            algorithm: $issued->algorithm,
            mKib: $issued->mKib,
            t: $issued->t,
            p: $issued->p,
            targetBits: $issued->targetBits,
            salt: $issued->salt,
            prefix: $issued->prefix,
            challenge: $issued->challenge,
            minDurationMs: $issued->minDurationMs,
            issuedAtNs: $issued->issuedAtNs,
            protocolVersion: 3,
            region: $issued->region,
            policyVersion: $issued->policyVersion,
            requestBinding: $issued->requestBinding,
            issuer: $issued->issuer,
            kid: $issued->kid,
            hostname: $issued->hostname,
            decoyField: null,
        );
        $freshStorage = new ArrayStorage();
        $freshStorage->store($v3);
        $token = SolutionToken::create($challenge->nonce, $this->solveCounter($challenge), 5000, [])->encode();
        $verifier = new Verifier($freshStorage, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $v3->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a decoyless v3 record fails closed as MalformedRecord — the stored version flip can never verify');
    }

    public function testProtocolVersionAcceptanceIsOneTwoAndThree(): void
    {
        // The wire contract: protocol versions 1 (legacy migration
        // window, the genuine v1 vector — covered by
        // testLegacyV1RecordAndTokenStillVerify), 2 (unarmed) and 3 (the
        // decoy-capable canonical, where the decoy is mandatory — a v3
        // record without one is MalformedRecord, see
        // testV3RecordWithoutADecoyIsRejected) exist; anything else is a
        // corrupt or foreign record. The strict parser stays the serde
        // mirror (any u8 parses — the version value is not a serde-level
        // constraint), the verifier's malformed-record path applies the
        // acceptance gate.
        $storage = new ArrayStorage();
        $challenge = $this->issuer($storage)->issue('login', Vectors::CLIENT_IP);
        $issued = $storage->find($challenge->nonce);
        self::assertNotNull($issued);
        $counter = $this->solveCounter($challenge);
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        // v2 (unarmed) verifies; v3 without a decoy is refused by the
        // strict parser AND the verifier's grammar gate (the serde
        // mirror itself accepts any u8, but the grammar is a
        // fromArray-level rejection like the v2-plus-decoy mirror).
        $data = $issued->toArray();
        $data['protocol_version'] = 2;
        self::assertSame(2, ChallengeRecord::fromArray($data)->protocolVersion, 'protocol version 2 must parse');
        $fresh = new ArrayStorage();
        $fresh->store(ChallengeRecord::fromArray($data));
        $verifier = new Verifier($fresh, now: static fn (): int => Vectors::NOW);
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $issued->issuedAtNs + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('protocol version 2 must verify (the unarmed 18-field canonical), got %s', $outcome->code()));

        $flipped = $issued->toArray();
        $flipped['protocol_version'] = 3;
        try {
            ChallengeRecord::fromArray($flipped);
            self::fail('a decoyless v3 record must be refused by fromArray');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('decoy_field', $e->getMessage());
        }
        // The hand-rolled equivalent (bypassing the parser) fails the
        // verifier's malformed-record path.
        $v3 = new ChallengeRecord(
            nonce: $issued->nonce,
            scope: $issued->scope,
            bindingTag: $issued->bindingTag,
            issuedAt: $issued->issuedAt,
            expiresAt: $issued->expiresAt,
            algorithm: $issued->algorithm,
            mKib: $issued->mKib,
            t: $issued->t,
            p: $issued->p,
            targetBits: $issued->targetBits,
            salt: $issued->salt,
            prefix: $issued->prefix,
            challenge: $issued->challenge,
            minDurationMs: $issued->minDurationMs,
            issuedAtNs: $issued->issuedAtNs,
            protocolVersion: 3,
            region: $issued->region,
            policyVersion: $issued->policyVersion,
            requestBinding: $issued->requestBinding,
            issuer: $issued->issuer,
            kid: $issued->kid,
            hostname: $issued->hostname,
            decoyField: null,
        );
        $freshV3 = new ArrayStorage();
        $freshV3->store($v3);
        $verifier3 = new Verifier($freshV3, now: static fn (): int => Vectors::NOW);
        $outcome3 = $verifier3->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $issued->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::MalformedRecord, $outcome3->error, 'a decoyless v3 record fails closed as MalformedRecord');

        // The serde-mirror parser accepts any u8 for protocol_version
        // except the grammar-locked shape: v4 requires the execution
        // triplet, so a bare version flip to 4 is rejected at parse time
        // (the same total grammar as the v2/v3 decoy split). Unknown
        // versions (0, 5..255) still parse and fail closed at the
        // verifier.
        foreach ([0, 5, 255] as $version) {
            $data = $issued->toArray();
            $data['protocol_version'] = $version;
            self::assertSame($version, ChallengeRecord::fromArray($data)->protocolVersion, 'the serde-mirror parser accepts any u8');

            $fresh = new ArrayStorage();
            $fresh->store(ChallengeRecord::fromArray($data));
            $verifier = new Verifier($fresh, now: static fn (): int => Vectors::NOW);
            $outcome = $verifier->verify($token, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $issued->issuedAtNs + 1_000_000);
            self::assertSame(VerifyError::MalformedRecord, $outcome->error, "protocol version {$version} must fail closed as MalformedRecord");
        }
        // A bare flip to 4 (no execution triplet on a decoy-armed
        // record) is refused by the parser: the v4 canonical requires
        // the execution commitment segments.
        try {
            $data = $issued->toArray();
            $data['protocol_version'] = 4;
            ChallengeRecord::fromArray($data);
            self::fail('a bare version flip to 4 must be rejected by the parser');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version 4', $e->getMessage());
        }
    }

    // ── (g) combinatorial grammar: prefix space, suffix, validity ─────

    /**
     * The deterministic grammar prefix for a linear index into the
     * 27,840-prefix space (`SLOT1` * `SLOT2` * `SLOT3`).
     */
    private function grammarPrefixAt(int $idx): string
    {
        $slot2Size = \count(Issuer::DECOY_GRAMMAR_SLOT2_CATEGORY);
        $slot3Size = \count(Issuer::DECOY_GRAMMAR_SLOT3_FORM);
        $s1 = intdiv($idx, $slot2Size * $slot3Size);
        $s2 = intdiv($idx % ($slot2Size * $slot3Size), $slot3Size);
        $s3 = $idx % $slot3Size;

        return Issuer::composeDecoyPrefix($s1, $s2, $s3);
    }

    public function testGrammarPrefixSpaceIsLargeAndEveryPrefixValid(): void
    {
        // The combinatorial prefix space: `SLOT1` * `SLOT2` * `SLOT3` = 32 * 29 * 30 = 27,840 distinct prefixes
        // (each triple joins to a unique string), thousands+, and every
        // member complies with the [A-Za-z0-9_-]{1,64} validation shape
        // (the longest prefix is 30 bytes).
        self::assertSame(27_840, Issuer::decoyGrammarSpaceSize());
        $seen = [];
        for ($i = 0; $i < Issuer::decoyGrammarSpaceSize(); $i++) {
            $prefix = $this->grammarPrefixAt($i);
            self::assertTrue(Config::isValidDecoyFieldName($prefix), "{$prefix} must comply with the validation shape");
            self::assertLessThanOrEqual(64, \strlen($prefix), "{$prefix} must be at most 64 bytes");
            self::assertTrue(Issuer::isGrammarDecoyPrefix($prefix));
            $seen[$prefix] = true;
        }
        self::assertCount(Issuer::decoyGrammarSpaceSize(), $seen, 'every triple must compose a unique prefix');

        // A 20,000-draw sample (seeded, deterministic) must not collapse
        // into a small distinct set: the effective prefix space is the
        // grammar space, not an accidentally tiny subset.
        mt_srand(42);
        $drawn = [];
        for ($i = 0; $i < 20_000; $i++) {
            $drawn[$this->grammarPrefixAt(mt_rand(0, Issuer::decoyGrammarSpaceSize() - 1))] = true;
        }
        self::assertGreaterThanOrEqual(1_000, \count($drawn), '20,000 draws must hit more than 1,000 distinct prefixes (got '.\count($drawn).')');
    }

    public function testConsecutiveDrawCollisionsAreBoundedByThePrefixSpace(): void
    {
        // Fixed-seed statistical test: 10,000 consecutive pairs drawn
        // uniformly from the 27,840-prefix space. The expected number of
        // equal consecutive pairs is ~10,000 / 27,840 ~ 0.36. The bound
        // is < 2 collisions, i.e. a deterministic pass at the ~1/N
        // collision probability per pair.
        mt_srand(7);
        $collisions = 0;
        $previous = null;
        for ($i = 0; $i < 10_000; $i++) {
            $current = $this->grammarPrefixAt(mt_rand(0, Issuer::decoyGrammarSpaceSize() - 1));
            if ($previous !== null && $previous === $current) {
                $collisions++;
            }
            $previous = $current;
        }
        self::assertLessThan(2, $collisions, "10,000 consecutive pairs must collide < 2 times (got {$collisions})");
    }

    public function testArmedNameSuffixIs16LowercaseHexFrom8RandomBytes(): void
    {
        // The suffix generator: exactly 16 lowercase hex characters, the
        // bin2hex of 8 `CSPRNG` bytes — the 64 random bits that make an
        // armed name unguessable and accidental collision impossible.
        $suffix = Issuer::decoyNameSuffix();
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/D', $suffix, "the suffix must be 16 lowercase hex chars (got {$suffix})");

        // Two consecutive draws must differ: the suffix is a fresh draw
        // per call, so identical suffixes across a handful of draws would
        // indicate a broken RNG, not a collision.
        $seen = [];
        for ($i = 0; $i < 20 && \count($seen) < 2; $i++) {
            $seen[Issuer::decoyNameSuffix()] = true;
        }
        self::assertGreaterThanOrEqual(2, \count($seen), 'consecutive suffixes must vary');
    }

    public function testTwoConsecutiveArmedNamesDifferInTheSuffix(): void
    {
        // The statistical core of the collision guarantee: two consecutive
        // armed compositions differ with overwhelming probability, and
        // when they differ it is the suffix that differs (the prefix may
        // repeat, the suffix never does at this sample scale — 2^-64 per
        // pair).
        $seenSuffixes = [];
        for ($i = 0; $i < 40; $i++) {
            $name = Issuer::composeDecoyName(0, 0, 0);
            self::assertTrue(Issuer::isGrammarDecoyName($name), "{$name} must be an armed grammar name");
            self::assertLessThanOrEqual(47, \strlen($name), "{$name} must be at most 47 bytes (the 64-byte validation bound)");
            $seenSuffixes[substr($name, -16)] = true;
        }
        self::assertCount(40, $seenSuffixes, '40 consecutive armed compositions must carry 40 distinct 64-bit suffixes');
    }

    public function testGrammarVocabulariesArePinnedAndBounded(): void
    {
        // The vocabularies are position-specific, lowercase-only words of
        // 2..=10 bytes, each vocabulary holding 25-35 words, and the
        // pinned literals here are the exact arrays the Rust crate
        // mirrors (the cross-language test in tests/cross_language.rs
        // compares the live Rust arrays against these same constants).
        $expectedSlot1 = [
            'secondary', 'alternate', 'billing', 'office', 'personal', 'company',
            'home', 'backup', 'department', 'business', 'primary', 'work',
            'emergency', 'mobile', 'regional', 'corporate', 'team', 'project',
            'default', 'temporary', 'external', 'internal', 'private', 'shared',
            'general', 'local', 'main', 'national', 'seasonal', 'guest',
            'middle', 'assistant',
        ];
        $expectedSlot2 = [
            'contact', 'address', 'phone', 'email', 'website', 'fax', 'company',
            'account', 'profile', 'order', 'invoice', 'support', 'service',
            'sales', 'location', 'region', 'branch', 'division', 'directory',
            'registry', 'record', 'file', 'entry', 'channel', 'portal',
            'platform', 'list', 'archive', 'history',
        ];
        $expectedSlot3 = [
            'phone', 'url', 'number', 'line', 'code', 'name', 'extension',
            'email', 'address', 'link', 'id', 'key', 'value', 'info', 'details',
            'notes', 'lookup', 'search', 'query', 'reference', 'alias', 'handle',
            'username', 'label', 'tag', 'entry', 'record', 'index', 'field',
            'form',
        ];
        self::assertSame($expectedSlot1, Issuer::DECOY_GRAMMAR_SLOT1_QUALIFIER);
        self::assertSame($expectedSlot2, Issuer::DECOY_GRAMMAR_SLOT2_CATEGORY);
        self::assertSame($expectedSlot3, Issuer::DECOY_GRAMMAR_SLOT3_FORM);
        foreach ([$expectedSlot1, $expectedSlot2, $expectedSlot3] as $vocab) {
            self::assertGreaterThanOrEqual(25, \count($vocab));
            self::assertLessThanOrEqual(35, \count($vocab));
            foreach ($vocab as $word) {
                self::assertMatchesRegularExpression('/^[a-z]{2,10}$/D', $word, "vocabulary words must be lowercase [a-z]{2,10} (got {$word})");
            }
        }
        // The legacy 10-name pool words all remain generatable vocabulary
        // entries (the words stay; only the enumerable selection is gone).
        foreach (['company', 'website', 'fax', 'number', 'secondary', 'phone', 'office', 'extension', 'alternate', 'email', 'home', 'address', 'line', 'middle', 'name', 'assistant', 'department', 'code', 'backup'] as $legacy) {
            self::assertTrue(
                \in_array($legacy, Issuer::DECOY_GRAMMAR_SLOT1_QUALIFIER, true)
                || \in_array($legacy, Issuer::DECOY_GRAMMAR_SLOT2_CATEGORY, true)
                || \in_array($legacy, Issuer::DECOY_GRAMMAR_SLOT3_FORM, true),
                "the legacy pool word {$legacy} must remain a vocabulary entry"
            );
        }
        self::assertTrue(Issuer::isGrammarDecoyPrefix('secondary_contact_phone'));
        self::assertTrue(Issuer::isGrammarDecoyPrefix('billing_company_url'));
        self::assertFalse(Issuer::isGrammarDecoyPrefix('secondary_contact'));
        self::assertFalse(Issuer::isGrammarDecoyPrefix('secondary_contact_phone_extra'));
        self::assertFalse(Issuer::isGrammarDecoyPrefix('Secondary_Contact_Phone'));
        self::assertFalse(Issuer::isGrammarDecoyPrefix('company|website'));
        // The full armed shape: a prefix plus the 16-hex suffix. A bare
        // prefix is a plausible real field name, so only the suffix makes
        // an armed name; a prefix without it is not an armed name.
        self::assertTrue(Issuer::isGrammarDecoyName('secondary_contact_phone_a3f9c21d8e5b7401'));
        self::assertTrue(Issuer::isGrammarDecoyName('billing_address_line_0000000000000000'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone_000000000000000'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone_00000000000000000'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone_ABCDEF0123456789'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone_000000000000000g'));
        self::assertFalse(Issuer::isGrammarDecoyName('secondary_contact_phone_extra_0000000000000000'));
    }

    public function testIssueWithDecoyFieldOverridePinsTheArmedName(): void
    {
        // The fixture/test seam: an explicit name override is used
        // verbatim (so the browser fixture can force a deliberate
        // same-name collision with an application field), and the same
        // alphabet validation applies to it.
        $storage = new ArrayStorage();
        $pinned = 'billing_address_line_a3f9c21d8e5b7401';
        $challenge = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP, true, null, null, $pinned);
        self::assertSame($pinned, $challenge->decoyField);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame($pinned, $record->decoyField, 'the pinned name is signed into the record like any other armed name');
        self::assertStringEndsWith('|'.$pinned, $this->decodedCanonical($challenge));

        foreach (['', str_repeat('x', 65), 'company|website', 'company.website'] as $bad) {
            try {
                $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP, true, null, null, $bad);
                self::fail('an invalid pinned decoy name must be refused');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('decoy name override', $e->getMessage());
            }
        }
        // The override is a seam: the default path still draws the
        // random armed name.
        $fresh = $this->issuer($storage)->issueWithDecoyField('login', Vectors::CLIENT_IP);
        self::assertNotSame($pinned, $fresh->decoyField);
        self::assertTrue(Issuer::isGrammarDecoyName($fresh->decoyField));
    }

    public function testRedisCommandCountIsIdenticalForArmedAndUnarmed(): void
    {
        // The zero-extra-round-trip invariant: the decoy name is drawn
        // in-process from the grammar (`random_int`, no storage), so an
        // armed issuance and verification perform the same Redis command
        // sequence and round trips as the unarmed path. Proven with the
        // fake-client counters on both paths.
        $issueArmed = new FakePredisClient();
        $armedStorage = new RedisStorage($issueArmed);
        $armedIssuer = new Issuer($this->shaConfig(), $armedStorage, now: static fn (): int => Vectors::NOW);
        $armed = $armedIssuer->issueWithDecoyField('login', Vectors::CLIENT_IP);
        self::assertNotNull($armed->decoyField);

        $issuePlain = new FakePredisClient();
        $plainStorage = new RedisStorage($issuePlain);
        $plainIssuer = new Issuer($this->shaConfig(), $plainStorage, now: static fn (): int => Vectors::NOW);
        $plain = $plainIssuer->issue('login', Vectors::CLIENT_IP);

        self::assertSame(
            \count($issuePlain->calls),
            \count($issueArmed->calls),
            'armed issuance must issue exactly the same number of Redis commands as unarmed issuance'
        );
        self::assertSame(
            $issuePlain->gets,
            $issueArmed->gets,
            'armed issuance must issue the same number of GETs as unarmed issuance'
        );

        $counter = $this->solveCounter($armed);
        $armedToken = SolutionToken::create($armed->nonce, $counter, 5000, [])->encode();
        $verifyArmed = new FakePredisClient();
        $verifyArmed->store = $issueArmed->store;
        $armedVerifier = new Verifier(new RedisStorage($verifyArmed), now: static fn (): int => Vectors::NOW);
        $armedOutcome = $armedVerifier->verify($armedToken, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $armed->minDurationMs + 1);
        self::assertTrue($armedOutcome->isOk(), sprintf('the armed Redis verification must pass, got %s', $armedOutcome->code()));

        $plainCounter = $this->solveCounter($plain);
        $plainToken = SolutionToken::create($plain->nonce, $plainCounter, 5000, [])->encode();
        $verifyPlain = new FakePredisClient();
        $verifyPlain->store = $issuePlain->store;
        $plainVerifier = new Verifier(new RedisStorage($verifyPlain), now: static fn (): int => Vectors::NOW);
        $plainOutcome = $plainVerifier->verify($plainToken, Vectors::SECRET, 'login', Vectors::CLIENT_IP, nowNs: $plain->minDurationMs + 1);
        self::assertTrue($plainOutcome->isOk(), sprintf('the unarmed Redis verification must pass, got %s', $plainOutcome->code()));

        self::assertSame(
            \count($verifyPlain->calls),
            \count($verifyArmed->calls),
            'armed verification must issue exactly the same number of Redis commands as unarmed verification'
        );
        self::assertSame(
            $verifyPlain->gets,
            $verifyArmed->gets,
            'armed verification must issue the same number of GETs as unarmed verification'
        );
        self::assertSame(
            \count($verifyPlain->evals),
            \count($verifyArmed->evals),
            'armed verification must issue the same number of Lua transitions as unarmed verification'
        );
    }
}
