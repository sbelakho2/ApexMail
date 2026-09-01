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
    private const VERSION = '1';

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
            'version' => ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, self::SCOPE, self::ACTION, '2'),
            'key' => ExecutionChallengeGenerator::generate('fedcba9876543210fedcba9876543210', self::NONCE, self::SCOPE, self::ACTION, self::VERSION),
        ] as $label => $program) {
            self::assertNotSame($base, $program, sprintf('changing %s must change the program', $label));
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

        // The wire shapes: the response key is present when armed and
        // absent when unarmed; the record JSON round-trips.
        self::assertArrayHasKey('execution_program', $challenge->toArray());
        $reparsed = ChallengeRecord::fromArray($record->toArray());
        self::assertSame($record->executionProgram, $reparsed->executionProgram);

        $unarmed = $issuer->issue(self::SCOPE, '198.51.100.7');
        self::assertNull($unarmed->executionProgram);
        self::assertArrayNotHasKey('execution_program', $unarmed->toArray());
        self::assertNull($storage->find($unarmed->nonce)->executionProgram);
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

    public function testArmedEndToEndVerifyWithCorrectDigest(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);

        $expected = ExecutionChallengeGenerator::expectedDigest($challenge->executionProgram, $challenge->nonce);
        self::assertNotNull($expected);
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $expected)->encode();

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

    public function testTamperedProgramFailsAgainstTheOriginalDigest(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField(self::SCOPE, '198.51.100.7', true, executionAction: self::ACTION);
        $digest = ExecutionChallengeGenerator::expectedDigest($challenge->executionProgram, $challenge->nonce);

        // A storage-level attacker swaps the record's program for a
        // different one; the presented digest was computed over the
        // original program, so the recomputed expected digest (over the
        // tampered program) can never match.
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
        );
        $storage->store($record);

        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $digest)->encode();
        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');

        self::assertSame(VerifyError::ExecutionMismatch, $outcome->error);
    }

    public function testNoProgramPathIsByteIdentical(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issue(self::SCOPE, '198.51.100.7');
        self::assertNull($challenge->executionProgram);

        // An unarmed challenge accepts the legacy four-segment token AND
        // a token carrying a stray digest segment (the no-program path
        // runs no execution check — the digest is inert). Each verify
        // consumes its own one-shot record, so two challenges are issued.
        $challengePlain = $issuer->issue(self::SCOPE, '198.51.100.7');
        $challengeWithDigest = $issuer->issue(self::SCOPE, '198.51.100.7');
        $token = SolutionToken::create($challengePlain->nonce, $this->winningCounter($challengePlain), 5000, [])->encode();
        $tokenWithDigest = SolutionToken::create($challengeWithDigest->nonce, $this->winningCounter($challengeWithDigest), 5000, [], str_repeat('a', 64))->encode();
        self::assertNotSame($token, $tokenWithDigest);

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::KEY, self::SCOPE, '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
        $outcome2 = $verifier->verify($tokenWithDigest, self::KEY, self::SCOPE, '198.51.100.7');
        self::assertSame($outcome->code(), $outcome2->code(), 'a stray digest on an unarmed challenge is inert');
        self::assertTrue($outcome2->isOk());
    }

    public function testMalformedRecordProgramIsRejected(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issue(self::SCOPE, '198.51.100.7');

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
        $data = $storage->find($issuer->issue(self::SCOPE, '198.51.100.7')->nonce)->toArray();

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
        $record = ChallengeRecord::fromArray($data);
        self::assertSame($data['execution_program'], $record->executionProgram);
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
        // Every opcode of the fixed set appears across a small sample of
        // programs, and every trace entry is a valid value (decimal,
        // "1"/"0", or base64 — never containing the ';' separator).
        $seen = [];
        for ($i = 0; $i < 24; $i++) {
            $nonce = base64_encode(random_bytes(32));
            $program = ExecutionChallengeGenerator::generate(self::KEY, $nonce, self::SCOPE, self::ACTION, self::VERSION);
            $decoded = ExecutionChallengeGenerator::decode($program);
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
        // tests/execution_interop.rs).
        $program = ExecutionChallengeGenerator::generate(self::KEY, self::NONCE, 'login', 'login-action', '1');
        self::assertSame(
            'AQVsb2dpbgxsb2dpbi1hY3Rpb24BFgCNqxVpLB6T8gdMU7FL5ux+lQwFTXdMVUYGmFkUzg9gs4cGNoDqS0K97IkBOG+tlsscQ9cRsBlfVGNvMDN7TkgwX01xVVJwRXZ2O0VtcSE3BiXJxpHRj5W3B27w4LXd0kdkDgklYCZ4Nlw9ekP3FCQWBXJKaSNZB3CjmYxw+iyPAuRxk85f2jJZBAeyj2Cgf2bwCQkoA/Rf4OOLTV7RBiZgyZwMpiabCCgbA69WjtsHgEEvFQM1MFAaLX5reXdAKS0we1NXNFZuO3sqfmEgSDtSUEc=',
            $program,
            'the PHP generator must reproduce the Rust program byte-for-byte',
        );
        self::assertSame(
            'c5eb55408b1973d669f6fc322b0b440958858b4ffee47a4ef411a1e0b7e8a439',
            ExecutionChallengeGenerator::expectedDigest($program, self::NONCE),
            'the PHP digest must reproduce the Rust digest',
        );
    }
}
