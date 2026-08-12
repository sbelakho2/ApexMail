<?php

declare(strict_types=1);

/**
 * CI cross-language harness: PHP ISSUES a challenge and writes the
 * language-neutral record JSON to KC_PHP_RECORD (env). The Rust job then
 * loads it, solves it, and verifies it with verify_solution.
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
$issuer = new Issuer($config, $storage);
$challenge = $issuer->issue('login', '198.51.100.7');
$record = $storage->find($challenge->nonce);
file_put_contents($target, json_encode($record->toArray(), JSON_UNESCAPED_SLASHES));

echo "PHP_ISSUED {$algo} nonce={$challenge->nonce}\n";
