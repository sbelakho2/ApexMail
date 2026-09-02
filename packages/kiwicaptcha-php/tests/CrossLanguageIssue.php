<?php

declare(strict_types=1);

/**
 * CI cross-language harness: PHP issues a challenge and writes the
 * language-neutral record JSON to the KC_PHP_RECORD env var. The Rust
 * job then loads it, solves it, and verifies it with verify_solution.
 *
 * The record JSON carries the full canonical wire schema (including
 * `region`, always present; null when unbound, `policy_version`,
 * `request_binding` and `issuer`). The KC_PHP_REGION env optionally
 * binds the issued records to a region so the cross-language region
 * interop is exercised too.
 *
 * The KC_PHP_NOW env optionally pins the issuance unix clock (seconds);
 * the Rust-side harness verifies with its own clock, and the future
 * skew bound requires the clocks to agree (default: the real clock).
 *
 * The KC_PHP_EXECUTION env (1) arms the ExecutionChallengeV1 dimension:
 * the issuance is protocol v4 and the record JSON carries the
 * authenticated execution triplet (execution_program + the signed
 * execution_version/execution_commitment).
 * The Rust job then exercises the v4 cross-language canonical
 * reconstruction and the commitment equivalence.
 * The KC_PHP_EXECUTION_ACTION env pins the program action (default
 * "login-action"); the fixed execution key mirrors the Rust harness
 * secret.
 *
 * Run: php tests/CrossLanguageIssue.php
 */

require __DIR__.'/../vendor/autoload.php';

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;

$target = getenv('KC_PHP_RECORD');
if ($target === false || $target === '') {
    fwrite(STDERR, "KC_PHP_RECORD not set\n");
    exit(2);
}

$nowEnv = getenv('KC_PHP_NOW');
$now = $nowEnv !== false && $nowEnv !== '' ? (int) $nowEnv : null;

$algo = getenv('KC_PHP_ALGO') ?: 'sha256';
$config = $algo === 'argon2id'
    ? new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        algorithm: \KiwiCaptcha\PoWAlgorithm::Argon2id,
        mKib: 64,
        t: 3,
        p: 1,
        targetBits: 4,
        argon2TargetBits: 4,
        ttlSecs: 120,
        minDurationMs: 0,
        executionKey: '0123456789abcdef0123456789abcdef',
    )
    : new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        targetBits: 8,
        ttlSecs: 120,
        minDurationMs: 0,
        executionKey: '0123456789abcdef0123456789abcdef',
    );
$storage = new ArrayStorage();
$region = getenv('KC_PHP_REGION');
$issuer = new Issuer(
    $config,
    $storage,
    now: $now !== null ? static fn (): int => $now : null,
    region: $region !== false && $region !== '' ? $region : null,
);
$execution = getenv('KC_PHP_EXECUTION') === '1';
$action = getenv('KC_PHP_EXECUTION_ACTION');
$challenge = $execution
    ? $issuer->issueWithExecutionField(
        'login',
        '198.51.100.7',
        true,
        executionAction: $action !== false && $action !== '' ? $action : 'login-action',
        armDecoyField: getenv('KC_PHP_EXECUTION_DECOY') === '1',
    )
    : $issuer->issue('login', '198.51.100.7');
$record = $storage->find($challenge->nonce);
if ($execution) {
    // The v4 equivalence is enforced on the writing side too: the
    // emitted record must carry the full authenticated triplet.
    if ($record->protocolVersion !== 4 || $record->executionVersion !== 1 || $record->executionCommitment === null) {
        fwrite(STDERR, "PHP v4 issuance must write protocol 4 with the execution triplet\n");
        exit(3);
    }
}
file_put_contents($target, json_encode($record->toArray(), JSON_UNESCAPED_SLASHES));

echo "PHP_ISSUED {$algo} nonce={$challenge->nonce}\n";
