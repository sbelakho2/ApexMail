<?php

declare(strict_types=1);

/**
 * Prints the sha256 of the concatenated big-endian u16 fixture scores
 * (protocol/risk-v1/fixtures.json, base_risk 100, contract weights).
 *
 * The Rust side (`packages/kiwicaptcha-risk/examples/fixture_hash.rs`)
 * prints the identical hash; CI's risk-parity job compares the two.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;

$path = dirname(__DIR__) . '/../../protocol/risk-v1/fixtures.json';
$raw = @file_get_contents($path);
if ($raw === false) {
    fwrite(STDERR, sprintf("fixtures.json not found at %s\n", $path));
    exit(1);
}
$fixtures = json_decode($raw, true);
if (!is_array($fixtures) || ($fixtures['protocol'] ?? null) !== 'risk-v1') {
    fwrite(STDERR, "fixtures.json must be a risk-v1 document\n");
    exit(1);
}

$weights = RiskWeights::fromArray($fixtures['weights']);
$scorer = new RiskScorer();
$base = (int) $fixtures['base_risk'];

$blob = '';
foreach ($fixtures['fixtures'] as $fixture) {
    $blob .= pack('n', $scorer->score($base, SignalVector::fromArray($fixture['signals']), $weights));
}

echo hash('sha256', $blob), "\n";
