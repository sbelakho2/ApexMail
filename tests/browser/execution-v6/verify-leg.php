<?php

/**
 * The version-6 verify leg of the fail harness. It reads the attempt
 * lines an emulator leg printed ({"i","ok","trace","error","ms"} per
 * line), walks every produced trace through the real PHP envelope
 * walker, and prints one summary JSON line:
 * {leg, attempted, produced, crashed, rejected, rejectionRate, msPerAttempt}.
 *
 * A crashed attempt (no trace) counts as rejected: the emulation could
 * not produce a submittable execution evidence at all, which is the
 * fail-closed outcome the dimension promises.
 *
 * Usage: node emulator-leg.mjs <engine> < attempts.jsonl | php verify-leg.php <engine>
 */

declare(strict_types=1);

require dirname(__DIR__, 3) . '/packages/kiwicaptcha-php/vendor/autoload.php';

use KiwiCaptcha\ExecutionChallengeGenerator;

$leg = (string) ($argv[1] ?? 'emulator');
$key = 'fedcba9876543210fedcba9876543210';
$msTotal = 0.0;
$attempted = 0;
$produced = 0;
$crashed = 0;
$rejected = 0;
$firstError = null;

$stream = fopen('php://stdin', 'rb');
while (($line = fgets($stream)) !== false) {
    $line = trim($line);
    if ($line === '') {
        continue;
    }
    $record = json_decode($line, true);
    $attempted++;
    $msTotal += (float) ($record['ms'] ?? 0);
    if (!$record['ok'] || !is_string($record['trace']) || $record['trace'] === '') {
        $crashed++;
        $rejected++;
        $firstError ??= $record['error'];
        continue;
    }
    $produced++;
    // The corpus nonce is derivable from the corpus index (the same
    // deterministic slice corpus.php emitted), so the verify leg can
    // judge each attempt without a second pass file.
    $nonce = base64_encode(hash('sha256', 'v6-envelope-' . (int) $record['i'], true));
    $program = ExecutionChallengeGenerator::generate($key, $nonce, 'login', 'login-action', 6);
    if (ExecutionChallengeGenerator::verifyExecutedTrace($program, $nonce, $record['trace']) === null) {
        $rejected++;
    }
}
fclose($stream);

echo json_encode([
    'leg' => $leg,
    'attempted' => $attempted,
    'produced' => $produced,
    'crashed' => $crashed,
    'rejected' => $rejected,
    'rejectionRate' => $attempted > 0 ? round($rejected / $attempted, 6) : null,
    'msPerAttempt' => $attempted > 0 ? round($msTotal / $attempted, 3) : null,
    'firstError' => $firstError,
]), "\n";
