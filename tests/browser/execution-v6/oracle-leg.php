<?php

/**
 * The version-6 oracle leg of the fail harness: the existing
 * browserless forgery oracle (the pure state-machine solver behind
 * BrowserlessForgerySolver, unchanged) forges a trace for every
 * synthetic version-6 program and the real PHP envelope walker judges
 * it. Prints one summary JSON line:
 * {leg, attempted, rejected, rejectionRate, wallMs, msPerAttempt}.
 *
 * Usage: php oracle-leg.php <offset> <n>
 */

declare(strict_types=1);

require dirname(__DIR__, 3) . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\BrowserlessForgerySolver;

$offset = (int) ($argv[1] ?? 0);
$n = (int) ($argv[2] ?? 1000);
$key = 'fedcba9876543210fedcba9876543210';
$heights = [1, 10, 17, 255];

$attempted = 0;
$rejected = 0;
$start = microtime(true);
for ($i = $offset; $i < $offset + $n; $i++) {
    $nonce = base64_encode(hash('sha256', 'v6-envelope-' . $i, true));
    $program = ExecutionChallengeGenerator::generate($key, $nonce, 'login', 'login-action', 6);
    $decoded = ExecutionChallengeGenerator::decode($program);
    $trace = BrowserlessForgerySolver::solve($decoded, $heights[$i % 4]);
    $attempted++;
    if (ExecutionChallengeGenerator::verifyExecutedTrace($program, $nonce, $trace) === null) {
        $rejected++;
    }
}
$wallMs = (microtime(true) - $start) * 1000.0;
echo json_encode([
    'leg' => 'oracle',
    'attempted' => $attempted,
    'rejected' => $rejected,
    'rejectionRate' => round($rejected / max(1, $attempted), 6),
    'wallMs' => (int) $wallMs,
    'msPerAttempt' => round($wallMs / max(1, $attempted), 3),
]), "\n";
