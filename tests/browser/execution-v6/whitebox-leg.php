<?php

/**
 * The version-6 white-box leg of the fail harness: the full-knowledge
 * forger (WhiteBoxEnvelopeForger, the published envelopes reimplemented
 * from the open-source verifier) forges a trace for every synthetic
 * version-6 program and the real PHP envelope walker judges it. Prints
 * one summary JSON line:
 * {leg, attempted, passed, rejected, passRate, rejectionRate, wallMs, msPerAttempt}.
 *
 * This leg is the honest full-knowledge measurement. The oracle leg
 * rejects 100 percent only because the naive solver emits pure-sim
 * placeholders; a forger who reads the envelopes passes every program.
 * The pass rate here is the true number: version 6 is supplementary
 * evidence that costs one source reading, NOT a browser boundary.
 *
 * Usage: php whitebox-leg.php <offset> <n>
 */

declare(strict_types=1);

require dirname(__DIR__, 3) . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Tests\Support\WhiteBoxEnvelopeForger;

$offset = (int) ($argv[1] ?? 0);
$n = (int) ($argv[2] ?? 1000);
$key = 'fedcba9876543210fedcba9876543210';
$heights = [1, 10, 17, 255];

$attempted = 0;
$passed = 0;
$start = microtime(true);
for ($i = $offset; $i < $offset + $n; $i++) {
    $nonce = base64_encode(hash('sha256', 'v6-envelope-' . $i, true));
    $program = ExecutionChallengeGenerator::generate($key, $nonce, 'login', 'login-action', 6);
    $decoded = ExecutionChallengeGenerator::decode($program);
    $trace = WhiteBoxEnvelopeForger::forge($decoded, $heights[$i % 4]);
    $attempted++;
    if (ExecutionChallengeGenerator::verifyExecutedTrace($program, $nonce, $trace) !== null) {
        $passed++;
    }
}
$wallMs = (microtime(true) - $start) * 1000.0;
$rejected = $attempted - $passed;
echo json_encode([
    'leg' => 'whitebox',
    'attempted' => $attempted,
    'passed' => $passed,
    'rejected' => $rejected,
    'passRate' => round($passed / max(1, $attempted), 6),
    'rejectionRate' => round($rejected / max(1, $attempted), 6),
    'wallMs' => (int) $wallMs,
    'msPerAttempt' => round($wallMs / max(1, $attempted), 3),
]), "\n";
