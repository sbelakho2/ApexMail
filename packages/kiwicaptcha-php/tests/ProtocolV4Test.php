<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\TestSupport\ExecutionTraceFixture;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use PHPUnit\Framework\TestCase;

/**
 * Protocol v4 : the execution-capable canonical and the
 * armed/unarmed exact equivalence.
 *
 * The v4 canonical is the decoy-capable canonical plus the
 * `|execution_version|execution_commitment` segments, both present only
 * when the record carries an execution program, signed inside the HMAC
 * canonical (byte-exact reconstruction in PHP and Rust).
 * The commitment is the hex SHA-256 of the stored program, so
 * stripping, substituting or injecting a program always invalidates
 * the challenge.
 * The stored program must satisfy commitment absent <=> program
 * absent, present <=> present, and SHA256(stored program) == the
 * signed commitment (constant-time).
 */
final class ProtocolV4Test extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const KEY = '0123456789abcdef0123456789abcdef';

    private function config(): Config
    {
        return new Config(
            secretKey: self::SECRET,
            targetBits: 8,
            ttlSecs: 120,
            minDurationMs: 0,
            executionKey: self::KEY,
        );
    }

    /** Brute-force the winning counter for an 8-bit SHA-256 challenge. */
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

    public function testArmedIssuanceWritesProtocolV4WithTheSignedCommitment(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action');

        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        self::assertSame(4, $record->protocolVersion, 'armed issuance writes protocol v4');
        self::assertNotNull($record->executionProgram);
        self::assertSame(1, $record->executionVersion, 'execution_version is the canonical byte 1');
        self::assertSame(64, \strlen($record->executionCommitment));
        self::assertSame(1, preg_match('/^[0-9a-f]{64}$/D', $record->executionCommitment));
        self::assertSame(
            hash('sha256', $record->executionProgram),
            $record->executionCommitment,
            'the commitment is the hex SHA-256 of the stored program',
        );

        // The commitment is inside the signed canonical: the challenge
        // string is base64(canonical).signature, so the canonical is
        // client-decodable and must end with |1|<commitment>.
        $canonical = base64_decode(substr($record->challenge, 0, strpos($record->challenge, '.')), true);
        self::assertNotFalse($canonical);
        self::assertStringEndsWith(
            '|'.$record->executionVersion.'|'.$record->executionCommitment,
            $canonical,
            'the signed canonical carries the execution_version|execution_commitment segments',
        );
        // And the verifier's byte-exact reconstruction equals it.
        self::assertSame($canonical, Issuer::canonicalPayload(
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
            $record->decoyField,
            $record->executionVersion,
            $record->executionCommitment,
        ), 'the canonical payload reconstruction is byte-exact');

        // The unarmed twin stays byte-identical to the pre-execution
        // format: protocol v2, no execution keys, canonical ending |kid.
        $unarmed = $issuer->issue('login', '198.51.100.7');
        $unarmedRecord = $storage->find($unarmed->nonce);
        self::assertSame(2, $unarmedRecord->protocolVersion);
        self::assertNull($unarmedRecord->executionProgram);
        self::assertNull($unarmedRecord->executionVersion);
        self::assertNull($unarmedRecord->executionCommitment);
        $unarmedCanonical = base64_decode(substr($unarmedRecord->challenge, 0, strpos($unarmedRecord->challenge, '.')), true);
        self::assertStringEndsWith('|1', $unarmedCanonical, 'the unarmed canonical keeps the plain 18-field shape (kid final)');
    }

    public function testIssuanceVersionMatrix(): void
    {
        // Execution + decoy: protocol v4, canonical carries both the
        // decoy segment and the execution segments.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $both = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'a', armDecoyField: true);
        $bothRecord = $storage->find($both->nonce);
        self::assertSame(4, $bothRecord->protocolVersion);
        self::assertNotNull($bothRecord->decoyField);
        $bothCanonical = base64_decode(substr($bothRecord->challenge, 0, strpos($bothRecord->challenge, '.')), true);
        self::assertStringEndsWith(
            '|'.$bothRecord->decoyField.'|1|'.$bothRecord->executionCommitment,
            $bothCanonical,
            'v4 with a decoy: |decoy|execution_version|execution_commitment',
        );

        // Decoy only: protocol v3, no execution segments.
        $decoy = $issuer->issueWithDecoyField('login', '198.51.100.7');
        $decoyRecord = $storage->find($decoy->nonce);
        self::assertSame(3, $decoyRecord->protocolVersion);
        self::assertNull($decoyRecord->executionProgram);
        $decoyCanonical = base64_decode(substr($decoyRecord->challenge, 0, strpos($decoyRecord->challenge, '.')), true);
        self::assertStringEndsWith('|'.$decoyRecord->decoyField, $decoyCanonical, 'a decoy-only record stays protocol v3');
    }

    public function testArmedChallengeVerifiesEndToEnd(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action');
        $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $digest, base64_encode($trace))->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('expected valid, got %s', $outcome->code()));
    }

    public function testStripTheStoredProgramInvalidatesTheChallenge(): void
    {
        // Armed/unarmed exact equivalence, direction 1: the signed
        // commitment is present, so the stored program MUST be present.
        // Stripping the program leaves a commitment without a program —
        // a structural violation (MalformedRecord), never a silent
        // downgrade.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action');
                $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $digest, base64_encode($trace))->encode();

        $record = $storage->find($challenge->nonce);
        $stripped = new ChallengeRecord(
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
            executionProgram: null,
            executionVersion: $record->executionVersion,
            executionCommitment: $record->executionCommitment,
        );
        $storage->store($stripped);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a commitment without its program is malformed — never a silent unarmed downgrade');
    }

    public function testStripTheCommitmentInvalidatesTheChallenge(): void
    {
        // Direction 2: the stored program is present, so the signed
        // commitment MUST be present. Stripping the commitment leaves a
        // program without its authenticated mirror — malformed.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action');
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();

        $record = $storage->find($challenge->nonce);
        $stripped = new ChallengeRecord(
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
            executionProgram: $record->executionProgram,
            executionVersion: null,
            executionCommitment: null,
        );
        $storage->store($stripped);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a program without its signed commitment is malformed');
    }

    public function testSubstituteAndRecommitBreaksTheSignature(): void
    {
        // The strongest attack: swap the program and recompute the
        // commitment consistently. The canonical bytes change, so the
        // HMAC over the original canonical fails — BadSignature. The
        // commitment is inside the signed canonical, so no storage-level
        // rewrite can ever re-commit a substitute.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'login-action');
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();

        $record = $storage->find($challenge->nonce);
        $substituted = new ChallengeRecord(
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
            executionProgram: ExecutionChallengeGenerator::generate(self::KEY, $record->nonce, 'login', 'other-action', 1),
            executionVersion: 1,
            // Consistent with the substituted program — but NOT with the
            // signed canonical, which commits to the original program.
            executionCommitment: Issuer::executionCommitment(ExecutionChallengeGenerator::generate(self::KEY, $record->nonce, 'login', 'other-action', 1)),
        );
        $storage->store($substituted);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::BadSignature, $outcome->error, 'a consistent substitute still breaks the HMAC over the signed canonical');
    }

    public function testInjectAProgramIntoAnUnarmedRecordIsMalformed(): void
    {
        // Direction 3: the signed canonical carries NO commitment, so
        // injecting a program (with a self-consistent commitment) is a
        // structural violation — the v2 canonical never includes the
        // segments.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();

        $record = $storage->find($challenge->nonce);
        $program = ExecutionChallengeGenerator::generate(self::KEY, $record->nonce, 'login', 'default', 1);
        $injected = new ChallengeRecord(
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
            executionProgram: $program,
            executionVersion: 1,
            executionCommitment: Issuer::executionCommitment($program),
        );
        $storage->store($injected);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'an injected execution surface on an unarmed record is malformed');
    }

    public function testVersionFlipToFourStaysMalformed(): void
    {
        // A signed v3 record with its stored version flipped to 4 keeps
        // the plain canonical bytes (no execution segments) — the v4
        // grammar requires the execution triplet, so the flip is
        // refused before any signature work.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithDecoyField('login', '198.51.100.7');
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode();

        $record = $storage->find($challenge->nonce);
        $flipped = new ChallengeRecord(
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
            protocolVersion: 4,
            region: $record->region,
            policyVersion: $record->policyVersion,
            requestBinding: $record->requestBinding,
            issuer: $record->issuer,
            kid: $record->kid,
            hostname: $record->hostname,
            decoyField: $record->decoyField,
            executionProgram: null,
            executionVersion: null,
            executionCommitment: null,
        );
        $storage->store($flipped);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'a stored version flip to 4 cannot manufacture the execution capability');
    }

    public function testNonCanonicalExecutionVersionIsMalformed(): void
    {
        // execution_version is the canonical numeric byte 1, 2 or 3
        // (the compat window). A hand-rolled record carrying a version
        // outside that set is corrupt and fails the verifier's record
        // gate as MalformedRecord.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'a');
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
            executionProgram: $record->executionProgram,
            executionVersion: 9,
            executionCommitment: $record->executionCommitment,
        );
        $storage->store($record);

        $outcome = (new Verifier($storage, now: static fn (): int => time()))->verify(
            SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [])->encode(),
            self::SECRET,
            'login',
            '198.51.100.7',
        );
        self::assertSame(VerifyError::MalformedRecord, $outcome->error, 'execution_version must be one of the canonical versions 1, 2 or 3');
    }

    public function testV4AcceptedByTheCurrentVerifierAndRejectedByOldGenerations(): void
    {
        // The current verifier accepts versions 1..4; the parent
        // revision (max protocol 2) and the decoy generation (max
        // protocol 3) reject a v4 record as unknown — the explicit
        // capability rule the two-phase rollout protects.
        $storage = new ArrayStorage();
        $issuer = new Issuer($this->config(), $storage);
        $challenge = $issuer->issueWithExecutionField('login', '198.51.100.7', true, executionAction: 'a', armDecoyField: true);
                $program = ExecutionChallengeGenerator::decode($challenge->executionProgram);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $digest = ExecutionChallengeGenerator::digestOverTrace($challenge->executionProgram, $challenge->nonce, $trace);
        $token = SolutionToken::create($challenge->nonce, $this->winningCounter($challenge), 5000, [], $digest, base64_encode($trace))->encode();

        $verifier = new Verifier($storage, now: static fn (): int => time());
        $outcome = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('the current verifier accepts its own v4 record, got %s', $outcome->code()));

        $simulator = new \KiwiCaptcha\Tests\Fixtures\ProtocolV2OnlyVerifier($verifier, $storage);
        self::assertSame(VerifyError::MalformedRecord, $simulator->verify($token, self::SECRET, 'login', '198.51.100.7')->error, 'a v2-only binary rejects v4 as unknown');
        self::assertSame(VerifyError::MalformedRecord, $simulator->verify($token, self::SECRET, 'login', '198.51.100.7', null, 3)->error, 'a v3-only binary rejects v4 as unknown');
        self::assertSame(VerifyError::MalformedRecord, $simulator->gate($storage->find($challenge->nonce), 3), 'the v3-only structural gate refuses v4');
    }
}
