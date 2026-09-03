<?php

declare(strict_types=1);

/**
 * CI cross-language harness (reverse direction): reads a Rust-issued
 * record (env KC_RUST_RECORD, algorithm KC_RUST_ALGO=sha256|argon2id),
 * solves it in pure PHP, and verifies it with the PHP verifier.
 *
 * The KC_RUST_REGION env optionally sets the verifier's expected region;
 * a record issued for another region (or unbound) then fails with
 * wrong_region, exercising the region interop in both directions.
 *
 * A Rust-issued protocol v4 record (execution_armed) is verified with
 * the real execution evidence the PHP core recomputes from the stored
 * program: the executed trace via the test fixture ExecutionTraceFixture::executedTraceFor, and the digest via
 * digestOverTrace over that trace. The evidence rides the solution
 * token as the digest:trace pair, exactly like the browser driver. The
 * verifier demands both halves of the evidence for an armed record.
 *
 * The v4 record file additionally carries the serialized digest:trace
 * token the Rust test built, a top-level `solution_token` sibling of
 * the record JSON (the record itself keeps the exact serde key set).
 * The fixture decodes it and asserts its digest and trace equal the
 * values PHP recomputed, pinning the two evidence constructions to the
 * same bytes.
 *
 * The KC_RUST_EXPECT_TAMPER env (1) flips the first hex digit of the
 * recomputed digest and asserts the verifier rejects the submission
 * with the deterministic execution_mismatch, the negative v4
 * direction.
 *
 * Run: php tests/CrossLanguageVerify.php
 */

require __DIR__.'/../vendor/autoload.php';

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\ExecutionTraceFixture;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;

$path = getenv('KC_RUST_RECORD');
if ($path === false || $path === '') {
    fwrite(STDERR, "KC_RUST_RECORD not set\n");
    exit(2);
}

$data = json_decode((string) file_get_contents($path), true);
// The reverse v4 record file carries the Rust-serialized digest:trace
// token as a top-level sibling of the record JSON. Pop the sibling
// before the strict fromArray parse, which rejects every unknown key.
$rustToken = null;
if (\array_key_exists('solution_token', $data)) {
    $rustToken = $data['solution_token'];
    unset($data['solution_token']);
}
$record = ChallengeRecord::fromArray($data);
$storage = new ArrayStorage();
$storage->store($record);

$counter = 0;
if ($record->algorithm === \KiwiCaptcha\PoWAlgorithm::Argon2id) {
    // Solve with libsodium (t>=3, p==1 are guaranteed by Rust issuance).
    do {
        $hash = sodium_crypto_pwhash(
            32,
            $record->prefix.$counter,
            base64_decode($record->salt, true),
            $record->t,
            $record->mKib * 1024,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
    --$counter;
} else {
    do {
        $hash = hash('sha256', $record->prefix.$counter.base64_decode($record->salt, true), true);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
    --$counter;
}

// A Rust-issued execution-armed record is protocol v4 and carries the
// authenticated program. The PHP core recomputes the real execution
// evidence, exactly like the browser driver: the program parses, the
// executed trace is produced via the test fixture ExecutionTraceFixture::executedTraceFor, the digest via
// digestOverTrace over that trace, and the digest:trace pair rides the
// solution token. A v4 record must never verify with a digest-only
// token: the verifier demands both halves of the evidence.
$tamper = getenv('KC_RUST_EXPECT_TAMPER') === '1';
$digest = null;
$trace = null;
if ($record->executionProgram !== null) {
    if ($record->protocolVersion !== 4) {
        fwrite(STDERR, "an execution-armed record must be protocol v4\n");
        exit(4);
    }
    if ($rustToken === null) {
        fwrite(STDERR, "an execution-armed record file must carry the Rust-serialized solution_token\n");
        exit(8);
    }
    $program = ExecutionChallengeGenerator::decode($record->executionProgram);
    if ($program === null) {
        fwrite(STDERR, "the Rust-issued execution program must parse in PHP\n");
        exit(5);
    }
    $trace = ExecutionTraceFixture::executedTraceFor($program);
    $digest = ExecutionChallengeGenerator::digestOverTrace($record->executionProgram, $record->nonce, $trace);
    if ($digest === null) {
        fwrite(STDERR, "the digest over the executed trace must compute in PHP\n");
        exit(5);
    }
    // The Rust side serialized its token over its own executed trace.
    // Decoding it pins the two evidence constructions to the same
    // bytes: the digests match only when both sides executed the
    // identical trace over the identical program.
    try {
        $rustDecoded = SolutionToken::decode($rustToken);
    } catch (DecodeError $e) {
        fwrite(STDERR, 'the Rust-serialized solution_token must decode in PHP: '.$e->getMessage()."\n");
        exit(8);
    }
    if ($rustDecoded->executionDigest === null || $rustDecoded->executionTrace === null
        || !hash_equals($digest, $rustDecoded->executionDigest)) {
        fwrite(STDERR, "the Rust-serialized solution_token digest must equal the PHP recomputation\n");
        exit(8);
    }
    $standard = strtr($rustDecoded->executionTrace, '-_', '+/');
    $standard = str_pad($standard, (int) ceil(\strlen($standard) / 4) * 4, '=');
    $rustTrace = (string) base64_decode($standard, true);
    if (!hash_equals($trace, $rustTrace)) {
        fwrite(STDERR, "the Rust-serialized solution_token trace must equal the PHP executed trace\n");
        exit(8);
    }
} elseif ($tamper) {
    fwrite(STDERR, "KC_RUST_EXPECT_TAMPER=1 requires an execution-armed record\n");
    exit(3);
}
if ($tamper) {
    // The negative v4 direction: a flipped digest nibble keeps the wire
    // shape canonical (still 64 hex) but must fail the execution
    // binding with the deterministic execution_mismatch.
    $digest[0] = $digest[0] === '0' ? '1' : '0';
}

$region = getenv('KC_RUST_REGION');
$token = SolutionToken::create($record->nonce, $counter, 5000, [], $digest, $trace !== null ? base64_encode($trace) : null)->encode();
$outcome = (new Verifier($storage, region: $region !== false && $region !== '' ? $region : null))
    ->verify($token, '0123456789abcdef0123456789abcdef', 'login', '198.51.100.7', $record->issuedAtNs + 1_000_000);
if ($tamper) {
    if ($outcome->isOk()) {
        fwrite(STDERR, "PHP_ACCEPTED_RUST_TAMPERED_V4 FAILED: the tampered digest must not verify\n");
        exit(6);
    }
    if ($outcome->code() !== VerifyError::ExecutionMismatch->value) {
        fwrite(STDERR, 'PHP_REJECTED_RUST_TAMPERED_V4 WRONG_CODE: '.$outcome->code()."\n");
        exit(7);
    }
    echo "PHP_REJECTS_RUST_TAMPERED_V4_EXECUTION OK (execution_mismatch)\n";
    exit(0);
}
if (!$outcome->isOk()) {
    fwrite(STDERR, 'PHP_VERIFIES_RUST FAILED: '.$outcome->code()."\n");
    exit(1);
}
if ($record->executionProgram !== null) {
    echo "PHP_VERIFIES_RUST_V4_EXECUTION OK\n";
} else {
    echo 'PHP_VERIFIES_RUST OK ('.($record->algorithm === \KiwiCaptcha\PoWAlgorithm::Argon2id ? 'argon2id' : 'sha256').")\n";
}
