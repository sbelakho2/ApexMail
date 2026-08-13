<?php

declare(strict_types=1);

/**
 * CI cross-language harness: PHP ISSUES a challenge and writes the
 * language-neutral record JSON to KC_PHP_RECORD (env). The Rust job then
 * loads it, solves it, and verifies it with verify_solution.
 *
 * The record JSON carries the full 21-key schema (including `region`,
 * always present — null when unbound, `policy_version`, `request_binding`
 * (audits #42/#41) and `issuer` (audit #67)). KC_PHP_REGION optionally
 * binds the issued records to a region so the cross-language region interop
 * is exercised too.
 *
 * KC_PHP_NOW optionally pins the issuance unix clock (seconds) — the
 * Rust-side harness verifies with its own clock, and audit #76's future
 * skew bound requires the clocks to agree (default: the real clock).
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
    )
    : new Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8, ttlSecs: 120, minDurationMs: 0);
$storage = new ArrayStorage();
$region = getenv('KC_PHP_REGION');
$issuer = new Issuer(
    $config,
    $storage,
    now: $now !== null ? static fn (): int => $now : null,
    region: $region !== false && $region !== '' ? $region : null,
);
$challenge = $issuer->issue('login', '198.51.100.7');
$record = $storage->find($challenge->nonce);
file_put_contents($target, json_encode($record->toArray(), JSON_UNESCAPED_SLASHES));

echo "PHP_ISSUED {$algo} nonce={$challenge->nonce}\n";
