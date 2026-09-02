<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use PHPUnit\Framework\TestCase;

/**
 * ExecutionChallengeV1: the deterministic browser-execution dimension.
 *
 * Covers generation determinism, the program blob grammar, the
 * digest binding, the record wire shape, the no-program path, the
 * armed end-to-end issuance and verification path, and the fixed
 * opcode set with its canonical trace.
 */
final class ExecutionChallengeTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';
    private const NONCE = 'xAfSYcl6VyvtYZcQUhvXxin2pojnG5TmZoHg7K6NG3s=';
    private const SCOPE = 'login';
    private const ACTION = 'login-action';
    private const VERSION = 1;

    private function config(?string $executionKey = self::KEY): Config
    {
        return new Config(
            secretKey: self::KEY,
            targetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
            executionKey: $executionKey,
        );
    }

    /**
     * Brute-force a counter whose SHA-256(prefix || counter || salt)
     * meets the issued target bits — the same derivation the browser
     * solver performs.
     */
    private function winningCounter(\KiwiCaptcha\Challenge $challenge): int
    {
        $salt = base64_decode($challenge->salt, true);
        for ($counter = 0; $counter < 1_000_000; $counter++) {
            $hash = hash('sha256', $challenge->prefix.$counter.$salt, true);
            $zeros = 0;
            foreach (str_split($hash) as $byte) {
                $b = \ord($byte);
                if ($b === 0) {
                    $zeros += 8;
                    continue;
                }
                while (($b & 0x80) === 0) {
                    $zeros++;
                    $b <<= 1;
                }
                break;
            }
            if ($zeros >= $challenge->targetBits) {
                return $counter;
            }
        }
        self::fail('no winning counter found within the search bound');
    }

    public function testGenerationIsDeterministicPerContext(): void
    {
        $programA = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        $programB = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);

        self::assertSame($programA, $programB, 'same context must produce the identical program');
        self::assertSame(
            ExecutionChallengeGenerator::expectedDigest($programA, self::NONCE),
            ExecutionChallengeGenerator::expectedDigest($programB, self::NONCE),
            'same context must produce the identical expected digest',
        );

        $other = ExecutionChallengeGenerator::generate(self::KEY, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', self::SCOPE, self::ACTION, self::VERSION);
        self::assertNotSame($programA, $other, 'a different nonce must produce a different program');
    }

    public function testDifferentContextFieldsChangeTheProgram(): void
    {
        $base = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        foreach ([
            'scope' => ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, 'signup', self::ACTION, self::VERSION),
            'action' => ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, 'other-action', self::VERSION),
            'key' => ExecutionChallengeGenerator::generate('fedcba9876543210fedcba9876543210', self::NONCE, self::SCOPE, self::ACTION, self::VERSION),
        ] as $label => $program) {
            self::assertNotSame($base, $program, sprintf('changing %s must change the program', $label));
        }
    }

    public function testGenerationRefusesANoncanonicalVersionByte(): void
    {
        // The version argument during generation is the canonical
        // numeric byte, exactly 1: a different byte is refused before
        // any program is minted (the strict parser would reject the
        // blob anyway, so issuance never produces an unparseable
        // program). No string-cast ever reaches the blob.
        foreach ([0, 2, 255] as $bad) {
            try {
                ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, $bad);
                self::fail('a noncanonical version byte must be refused');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('canonical numeric byte', $e->getMessage());
            }
        }
        try {
            ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, '1');
            self::fail('a string version must never reach the generator (no string-cast)');
        } catch (\TypeError) {
        }
    }

    public function testProgramBlobGrammarAndBounds(): void
    {
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        self::assertTrue(ExecutionChallengeGenerator::isValidProgram($program));

        $decoded = ExecutionChallengeGenerator::decode($program);
        self::assertNotNull($decoded);
        self::assertSame(1, $decoded['format']);
        self::assertSame(self::SCOPE, $decoded['scope'], 'the program embeds the scope it was generated for');
        self::assertSame(self::ACTION, $decoded['action'], 'the program embeds the action it was generated for');
        self::assertSame(1, $decoded['op_version']);
        $count = \count($decoded['ops']);
        self::assertGreaterThanOrEqual(ExecutionChallengeGenerator::MIN_OPS, $count);
        self::assertLessThanOrEqual(ExecutionChallengeGenerator::MAX_OPS, $count);
        foreach ($decoded['ops'] as $op) {
            self::assertGreaterThanOrEqual(0, $op['op']);
            self::assertLessThan(ExecutionChallengeGenerator::OP_COUNT, $op['op']);
            self::assertIsArray($op['operands']);
        }

        // The canonical trace is a pure function of the program.
        self::assertSame(
            ExecutionChallengeGenerator::canonicalTrace($decoded),
            ExecutionChallengeGenerator::canonicalTrace($decoded),
        );
        self::assertNotSame('', ExecutionChallengeGenerator::canonicalTrace($decoded));
    }

    public function testMalformedProgramsAreRejected(): void
    {
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(''));
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram('not-base64!'));
        // Valid base64 of a truncated / wrong-format blob.
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode("\x02\x01x")));
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode("\x01\x05login")));
        // A blob that is not canonical base64 (non-zero trailing bits).
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode('a').'b'));
        // Over the wire ceiling.
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode(str_repeat("\x01", ExecutionChallengeGenerator::MAX_PROGRAM_BASE64))));
    }

    public function testExpectedDigestShapeAndNonceBinding(): void
    {
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        $digest = ExecutionChallengeGenerator::expectedDigest($program, self::NONCE);

        self::assertIsString($digest);
        self::assertSame(64, \strlen($digest));
        self::assertSame(1, preg_match('/^[0-9a-f]{64}$/D', $digest));
        self::assertNotSame(
            $digest,
            ExecutionChallengeGenerator::expectedDigest($program, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
            'the digest binds the nonce: a digest computed for another challenge context must differ',
        );
        self::assertNull(ExecutionChallengeGenerator::expectedDigest('garbage', self::NONCE));
    }

    public function testArmedIssuanceRidesTheRecordAndTheResponse(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        self::assertNotNull($challenge->executionProgram);
        self::assertTrue(ExecutionChallengeGenerator::isValidProgram($challenge->executionProgram));
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame($challenge->executionProgram, $record->executionProgram);
        self::assertNull($record->decoyField, 'the execution dimension does not arm the decoy surface');

        // The v4 shape: an armed issuance writes protocol v4
        // and the stored record carries the authenticated commitment
        // triplet (version 1 + hex SHA-256 of the program), mirroring
        // the signed canonical.
        self::assertSame(4, $record->protocolVersion, 'an execution-armed issuance writes protocol v4');
        self::assertSame(1, $record->executionVersion);
        self::assertSame(Issuer::executionCommitment($record->executionProgram), $record->executionCommitment, 'the stored commitment is the hex SHA-256 of the stored program');
        self::assertSame(64, \strlen($record->executionCommitment));
        self::assertSame(1, preg_match('/^[0-9a-f]{64}$/D', $record->executionCommitment));

        // The wire shapes: the response key is present when armed and
        // absent when unarmed; the record JSON round-trips the full
        // triplet.
        self::assertArrayHasKey('execution_program', $challenge->toArray());
        $reparsed = ChallengeRecord::fromArray($record->toArray());
        self::assertSame($record->executionProgram, $reparsed->executionProgram);
        self::assertSame($record->executionVersion, $reparsed->executionVersion);
        self::assertSame($record->executionCommitment, $reparsed->executionCommitment);

        $unarmed = $issuer->issue(self::SCOPE, '198.51.100.7');
        self::assertNull($unarmed->executionProgram);
        self::assertArrayNotHasKey('execution_program', $unarmed->toArray());
        $unarmedRecord = $storage->find($unarmed->nonce);
        self::assertNull($unarmedRecord->executionProgram);
        self::assertNull($unarmedRecord->executionVersion, 'an unarmed record never carries execution_version');
        self::assertNull($unarmedRecord->executionCommitment, 'an unarmed record never carries execution_commitment');
        self::assertArrayNotHasKey('execution_version', $unarmedRecord->toArray());
        self::assertArrayNotHasKey('execution_commitment', $unarmedRecord->toArray());
    }

    public function testArmingWithoutExecutionKeyRefuses(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(null), $storage);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('execution_key');
        $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true);
    }

    public function testConfigRequiresExecutionKeyLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Config(secretKey: self::KEY, executionKey: 'short');
    }

    public function testGenerateRejectsInvalidScopes(): void
    {
        foreach (['', ' ', 'login action', 'login|action', 'h\u00e9llo', str_repeat('a', 129), str_repeat('a', 256)] as $scope) {
            try {
                ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, $scope, self::ACTION, 1);
                self::fail('scope '.json_encode($scope).' must be rejected');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('execution scope must be 1-128', $e->getMessage());
            }
        }
    }

    public function testGenerateAcceptsTheBoundary128ByteScope(): void
    {
        $scope = str_repeat('a', 128);
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, $scope, self::ACTION, 1);
        $decoded = ExecutionChallengeGenerator::decode($program);
        self::assertNotNull($decoded);
        self::assertSame($scope, $decoded['scope']);
    }

    public function testArmedEndToEndVerifyWithCorrectDigest(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        self::assertNotNull($program);
        $trace = ExecutionChallengeGenerator::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        self::assertNotNull($digest);
        $token = SolutionToken::create(
            $challenge->nonce,
            $this->winningCounter($challenge),
            5000,
            [],
            $digest,
            base64_encode($trace),
        )->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    public function testArmedRecordWithoutDigestIsExecutionMismatch(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::ExecutionMismatch, $outcome->error);
    }

    public function testWrongDigestIsExecutionMismatch(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        $expected = ExecutionChallengeGenerator::expectedDigest($challenge->executionProgram, $challenge->nonce);
        $wrong = str_repeat('0', 64);
        self::assertNotSame($expected, $wrong);
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $wrong)->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::ExecutionMismatch, $outcome->error);
    }

    public function testDigestFromAnotherChallengeIsExecutionMismatch(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challengeA = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);
        $challengeB = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);
        self::assertNotSame($challengeA->nonce, $challengeB->nonce);

        // The digest of challenge B presented for challenge A.
        $digestB = ExecutionChallengeGenerator::expectedDigest($challengeB->executionProgram, $challengeB->nonce);
        $token = SolutionToken::create($challengeA->nonce, 42, 5000, [], $digestB)->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::ExecutionMismatch, $outcome->error);
    }

    public function testSubstitutedProgramFailsTheCommitmentEquivalence(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);
        $digest = ExecutionChallengeGenerator::expectedDigest($challenge->executionProgram, $challenge->nonce);

        // A storage-level attacker swaps the record's program for a
        // different one. The signed canonical carries the original
        // program's commitment, so the equivalence gate rejects the
        // substituted program as MalformedRecord — before any execution
        // work (the digest-based defense alone is no longer the
        // boundary; the commitment is authenticated).
        $record = $storage->find($challenge->nonce);
        $tampered = ExecutionChallengeGenerator::generate(self::KEY, $challenge->nonce, self::SCOPE, 'tampered-action', self::VERSION);
        $record = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
            region: $record->region,
            policyVersion: $record->policyVersion,
            requestBinding: $record->requestBinding,
            issuer: $record->issuer,
            kid: $record->kid,
            hostname: $record->hostname,
            decoyField: $record->decoyField,
            executionProgram: $tampered,
            // The stored commitment still mirrors the original program
            // (the attacker cannot re-sign the canonical), so the
            // equivalence check SHA256(stored program) == commitment
            // fails deterministically.
            executionVersion: $record->executionVersion,
            executionCommitment: $record->executionCommitment,
        );
        $storage->store($record);

        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $digest)->encode();
        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a substituted program fails the commitment equivalence as MalformedRecord');
    }

    public function testNoProgramPathRejectsAStrayDigest(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issue(self::SCOPE, '198.51.100.7');
        self::assertNull($challenge->executionProgram);

        // An unarmed challenge accepts the legacy four-segment token.
        // A token carrying a stray digest segment is stray execution
        // evidence and is rejected with the deterministic
        // ExecutionMismatch — never silently ignored.
        // The signed canonical carries no commitment, so no digest can
        // be legitimate for it.
        // Each verify consumes its own one-shot record, so two
        // challenges are issued.
        $challengePlain = $issuer->issue(self::SCOPE, '198.51.100.7');
        $challengeWithDigest = $issuer->issue(self::SCOPE, '198.51.100.7');
        $token = SolutionToken::create($challengePlain->nonce, $this->winningCounter($challengePlain), 5000, [])->encode();
        $tokenWithDigest = SolutionToken::create($challengeWithDigest->nonce, $this->winningCounter($challengeWithDigest), 5000, [], str_repeat('a', 64))->encode();
        self::assertNotSame($token, $tokenWithDigest);

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        $outcome2 = $verifier->verify($tokenWithDigest, self::KEY, self::SCOPE, '198.51.100.7');
        self::assertSame(VerifyError::ExecutionMismatch, $outcome2->error, 'a stray digest on an unarmed challenge is deterministic invalid');
    }

    public function testMalformedRecordProgramIsRejected(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        $record = $storage->find($challenge->nonce);
        $record = new ChallengeRecord(
            nonce: $record->nonce,
            scope: $record->scope,
            bindingTag: $record->bindingTag,
            issuedAt: $record->issuedAt,
            expiresAt: $record->expiresAt,
            algorithm: $record->algorithm,
            mKib: $record->mKib,
            t: $record->t,
            p: $record->p,
            targetBits: $record->targetBits,
            salt: $record->salt,
            prefix: $record->prefix,
            challenge: $record->challenge,
            minDurationMs: $record->minDurationMs,
            issuedAtNs: $record->issuedAtNs,
            protocolVersion: $record->protocolVersion,
            region: $record->region,
            policyVersion: $record->policyVersion,
            requestBinding: $record->requestBinding,
            issuer: $record->issuer,
            kid: $record->kid,
            hostname: $record->hostname,
            decoyField: $record->decoyField,
            executionProgram: base64_encode("\x02garbage"),
            executionVersion: $record->executionVersion,
            executionCommitment: $record->executionCommitment,
        );
        $storage->store($record);

        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();
        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::MalformedRecord, $outcome->error);
    }

    public function testFromArrayRejectsMalformedExecutionProgram(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);
        $data = $storage->find($challenge->nonce)->toArray();

        foreach (['not-base64', base64_encode("\x02short")] as $bad) {
            $mutated = $data;
            $mutated['execution_program'] = $bad;
            try {
                ChallengeRecord::fromArray($mutated);
                self::fail('a malformed execution_program must throw');
            } catch (\KiwiCaptcha\MalformedRecordException $e) {
                self::assertStringContainsString('execution_program', $e->getMessage());
            }
        }

        // A well-formed program passes the parser.
        $data['execution_program'] = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        // The commitment must match the substituted program (the exact
        // armed/unarmed equivalence is enforced on the parse path too).
        $data['execution_commitment'] = Issuer::executionCommitment($data['execution_program']);
        $record = ChallengeRecord::fromArray($data);
        self::assertSame($data['execution_program'], $record->executionProgram);

        // A well-formed program whose hash does not equal the signed
        // commitment is rejected on the parse path.
        $data['execution_commitment'] = str_repeat('0', 64);
        try {
            ChallengeRecord::fromArray($data);
            self::fail('a program not matching its commitment must throw');
        } catch (\KiwiCaptcha\MalformedRecordException $e) {
            self::assertStringContainsString('execution_commitment', $e->getMessage());
        }
    }

    public function testTokenRoundTripWithAndWithoutDigest(): void
    {
        $plain = SolutionToken::create(self::NONCE, 7, 1234, ['wd' => true]);
        $encoded = $plain->encode();
        self::assertSame(4, \count(explode('.', base64_decode($encoded))));

        $digest = str_repeat('f', 64);
        $armed = SolutionToken::create(self::NONCE, 7, 1234, ['wd' => true], $digest);
        $armedEncoded = $armed->encode();
        self::assertSame(5, \count(explode('.', base64_decode($armedEncoded))));
        self::assertSame($digest, SolutionToken::decode($armedEncoded)->executionDigest);
        self::assertNull(SolutionToken::decode($encoded)->executionDigest);

        // Telemetry containing dots keeps the digest as the final segment.
        $dotted = SolutionToken::create(self::NONCE, 7, 1234, ['ua' => 'Mozilla/5.0 (X11; Linux x86_64)'], $digest);
        $decoded = SolutionToken::decode($dotted->encode());
        self::assertSame($digest, $decoded->executionDigest);
        self::assertSame(['ua' => 'Mozilla/5.0 (X11; Linux x86_64)'], $decoded->telemetry);

        // A malformed digest tail (not 64 lowercase hex) is not the wire
        // language: it parses as part of the telemetry and fails the JSON
        // object requirement.
        $bad = SolutionToken::create(self::NONCE, 7, 1234, [], 'XYZ');
        $this->expectException(\KiwiCaptcha\DecodeError::class);
        SolutionToken::decode($bad->encode());
    }

    public function testExecutedTraceIsStableAcrossDecodes(): void
    {
        // The trace and digest are pure functions of the program bytes:
        // decoding the same base64 repeatedly yields the identical trace.
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION);
        $a = ExecutionChallengeGenerator::decode($program);
        $b = ExecutionChallengeGenerator::decode($program);
        self::assertSame(
            ExecutionChallengeGenerator::canonicalTrace($a),
            ExecutionChallengeGenerator::canonicalTrace($b),
        );
    }

    public function testAllOpcodesExecuteDeterministically(): void
    {
        // Every opcode of the fixed set appears across a deterministic
        // corpus (nonces derived from sha256 over a label, so the same
        // programs run on every PHP version and every CI cell — the
        // corpus is large enough that the rarest filler opcodes
        // (uniform over 0..27 in the filler slots) are certainly
        // drawn), and every trace entry is a valid value (decimal,
        // "1"/"0", or base64 — never containing the ';' separator).
        $seen = [];
        for ($i = 0; $i < 96; $i++) {
            $nonce = base64_encode(hash('sha256', 'opcode-coverage-'.$i, true));
            $program = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, self::VERSION);
            $decoded = ExecutionChallengeGenerator::decode($program);
            self::assertNotNull($decoded);
            $trace = ExecutionChallengeGenerator::canonicalTrace($decoded);
            self::assertStringNotContainsString("\0", $trace);
            foreach ($decoded['ops'] as $op) {
                $seen[$op['op']] = true;
            }
        }
        self::assertCount(ExecutionChallengeGenerator::OP_COUNT, $seen, 'every fixed opcode must be reachable by the generator');
    }

    public function testRustMirrorVectorsAreReproduced(): void
    {
        // Pinned vectors generated by the Rust mirror
        // (packages/kiwicaptcha/src/execution.rs): the PHP core must
        // reproduce the identical program blob and expected digest, so a
        // Rust-issued program verifies byte-identically in PHP (and vice
        // versa — the Rust test pins the PHP-generated vectors in
        // tests/execution_interop.rs). The blob was regenerated when the
        // dataset-key alphabet moved to `x[0-9a-z_]{0,15}` ;
        // both mirrors pin the same bytes.
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, 'login', 'login-action', 1);
        self::assertSame(
            'AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEggUIQ9yVnBzZVR5dk1UeExtcysKCgoLYB8PclZwc2VUeXZNVHhMbXMrHw9yVnBzZVR5dk1UeExtcysaEOoOQzlzSkI0dnRXTGNEWFYI2Afyoq4QE7qNKBsSC7AZEFAPMVdiRXN3L1hhbEpHUlJQCbeTGhDgEGRTSGsyNEZBbDNXYjg1QzMUJA==',
            $program,
            'the PHP generator must reproduce the Rust program byte-for-byte',
        );
        $decoded = ExecutionChallengeGenerator::decode($program);
        self::assertNotNull($decoded);
        self::assertSame(
            '595d6df929e025c559ac3393c3a006283574d33f366dbdb70501ae88f177a1b9',
            ExecutionChallengeGenerator::digestOverTrace(
                $program,
                self::NONCE,
                ExecutionChallengeGenerator::executedTraceFor($decoded),
            ),
            'the PHP executed-trace digest must reproduce the Rust digest',
        );
    }

    public function testDatasetKeysMatchTheSafeAlphabetGrammar(): void
    {
        // The generator-level property test: every dataset key drawn
        // into a generated program must match the deliberately boring
        // safe grammar `x[0-9a-z_]{0,15}` — the literal `x` followed by
        // 0..15 characters of [0-9a-z_]. The grammar guarantees no key
        // can carry the `|` canonical separator, DOM punctuation,
        // whitespace or uppercase.
        $seen = 0;
        for ($i = 0; $i < 64; $i++) {
            $nonce = base64_encode(random_bytes(32));
            $program = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, self::VERSION);
            $decoded = ExecutionChallengeGenerator::decode($program);
            self::assertNotNull($decoded);
            foreach ($decoded['ops'] as $op) {
                if ($op['op'] !== ExecutionChallengeGenerator::OP_DOM_DATASET_SET) {
                    continue;
                }
                $seen++;
                $key = $op['operands']['s'];
                self::assertIsString($key);
                self::assertSame(1, preg_match(ExecutionChallengeGenerator::DATASET_KEY_PATTERN, $key), sprintf('dataset key "%s" must match x[0-9a-z_]{0,15}', $key));
                self::assertGreaterThanOrEqual(1, \strlen($key));
                self::assertLessThanOrEqual(16, \strlen($key));
            }
        }
        self::assertGreaterThan(0, $seen, 'the sampled programs must actually exercise dataset keys');
    }

    public function testStrictParserRejectsTrailingBytesAndBadContextBytes(): void
    {
        // The parser strictness: exact EOF after the op list
        // (a trailing byte is invalid), op_version exactly 1, and the
        // embedded scope/action must match the canonical identifier
        // grammar.
        $good = ExecutionChallengeGenerator::decode(
            ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION)
        );
        self::assertNotNull($good);
        $goodBytes = base64_decode(ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, self::VERSION), true);

        // Trailing byte after the op list: the blob is now one byte
        // longer, the parser must refuse it.
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode($goodBytes."\x00")), 'a trailing byte after the op list must be rejected');
        self::assertNull(ExecutionChallengeGenerator::decode(base64_encode($goodBytes."\x00")));

        // op_version 2 (no arbitrary byte): a blob whose op-version byte
        // (index scopeLen + actionLen + 2) is not 1 must be rejected.
        $scopeLen = \ord($goodBytes[1]);
        $actionLen = \ord($goodBytes[2 + $scopeLen]);
        $badVersion = $goodBytes;
        $badVersion[2 + $scopeLen + $actionLen + 1] = "\x02";
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode($badVersion)), 'an op version other than 1 must be rejected');
        self::assertNull(ExecutionChallengeGenerator::decode(base64_encode($badVersion)));

        // Scope with an out-of-grammar byte (a space): the embedded
        // scope must match [A-Za-z0-9._:-].
        $badScope = $goodBytes;
        $badScope[2] = "\x20";
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode($badScope)), 'a scope byte outside the identifier grammar must be rejected');

        // Action with a '|' byte: the canonical separator can never be
        // smuggled through the embedded action.
        $badAction = $goodBytes;
        $badAction[2 + $scopeLen + 1] = "\x7c";
        self::assertFalse(ExecutionChallengeGenerator::isValidProgram(base64_encode($badAction)), 'an action byte outside the identifier grammar must be rejected');
    }
}
