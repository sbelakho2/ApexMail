<?php

/**
 * The version-6 fail-harness corpus emitter: prints one JSON object per
 * line, {"program": <base64>, "nonce": <string>}, for a deterministic
 * slice of the synthetic corpus. The programs are minted by the real
 * PHP generator at the real-platform rung, so the emulator and oracle
 * legs attack exactly the records a real deployment issues.
 *
 * Usage: php corpus.php <offset> <n>
 */

declare(strict_types=1);

require dirname(__DIR__, 3) . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ExecutionChallengeGenerator;

$offset = (int) ($argv[1] ?? 0);
$n = (int) ($argv[2] ?? 1000);
$key = 'fedcba9876543210fedcba9876543210';
$out = fopen('php://stdout', 'wb');
for ($i = $offset; $i < $offset + $n; $i++) {
    $nonce = base64_encode(hash('sha256', 'v6-envelope-' . $i, true));
    fwrite($out, json_encode([
        'i' => $i,
        'program' => ExecutionChallengeGenerator::generate($key, $nonce, 'login', 'login-action', 6),
        'nonce' => $nonce,
    ]) . "\n");
}
fclose($out);
