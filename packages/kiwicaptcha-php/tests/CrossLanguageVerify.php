<?php

declare(strict_types=1);

/**
 * CI cross-language harness (reverse direction): reads a RUST-ISSUED record
 * (KC_RUST_RECORD env, KC_RUST_ALGO=sha256|argon2id), solves it in pure PHP,
 * and verifies it with the PHP verifier.
 *
 * Run: KC_RUST_RECORD=/tmp/rust_record.json [KC_RUST_ALGO=sha256] php tests/CrossLanguageVerify.php
 */

require __DIR__.'/../vendor/autoload.php';

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;

$path = getenv('KC_RUST_RECORD');
if ($path === false || $path === '') {
    fwrite(STDERR, "KC_RUST_RECORD not set\n");
    exit(2);
}

$record = ChallengeRecord::fromArray(json_decode((string) file_get_contents($path), true));
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
            $record->mKib * 1024 * 1024,
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

$token = SolutionToken::create($record->nonce, $counter, 5000, [])->encode();
$outcome = (new Verifier($storage))->verify($token, '0123456789abcdef0123456789abcdef', 'login', '198.51.100.7', $record->issuedAtNs + 1_000_000);
if (!$outcome->isOk()) {
    fwrite(STDERR, 'PHP_VERIFIES_RUST FAILED: '.$outcome->code()."\n");
    exit(1);
}
echo 'PHP_VERIFIES_RUST OK ('.($record->algorithm === \KiwiCaptcha\PoWAlgorithm::Argon2id ? 'argon2id' : 'sha256').")\n";
