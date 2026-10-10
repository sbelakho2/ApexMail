<?php

declare(strict_types=1);

/**
 * Prints the sha256 of the cross-language risk-v1 protocol parity blob.
 *
 * The blob order is fixed and mirrored byte-for-byte by the Rust side
 * (`packages/kiwicaptcha-risk/examples/fixture_hash.rs`); CI's
 * risk-parity job compares the two hashes:
 *
 *   1. every fixtures.json case's big-endian u16 contract score;
 *   2. the five hkdf-sha256 identity keys of identity_vectors.master_key
 *      in source, subnet, session, principal, event order (32 raw bytes
 *      each);
 *   3. canonical IP bytes and masked networks for the fixed probe list
 *      (IPv4, IPv6, IPv4-mapped IPv6 normalized to IPv4);
 *   4. the identity_vectors derivations as raw 16-byte pseudonyms:
 *      session (from the decoded cookie bytes), principal, source and
 *      subnet (at the fixture epochs);
 *   5. every namespace_vectors derived namespace (utf-8 bytes).
 *
 * Steps 2-5 make this a real protocol parity hash: HKDF keys, canonical
 * IP encoding, IPv4-mapped normalization, subnet masking, the ephemeral
 * pseudonyms and the deployment namespace are all compared across the
 * two implementations, not only the score vector.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use KiwiCaptcha\Risk\DeploymentNamespace;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\RiskWeights;
use KiwiCaptcha\Risk\SignalVector;

/** The canonical probe list, mirrored by the Rust tool. */
const PROBE_IPS = [
    '203.0.113.27',
    '192.0.2.1',
    '2001:db8:abcd:12ff:ffff:ffff:ffff:ffff',
    '::ffff:203.0.113.27',
];

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

$blob = '';

// 1. Contract scores over the shared signal fixtures.
$weights = RiskWeights::fromArray($fixtures['weights']);
$scorer = new RiskScorer();
$base = (int) $fixtures['base_risk'];
foreach ($fixtures['fixtures'] as $fixture) {
    $blob .= pack('n', $scorer->score($base, SignalVector::fromArray($fixture['signals']), $weights));
}

// 2. HKDF identity keys from the shared master.
$identity = $fixtures['identity_vectors'];
$keys = RiskKeys::fromMaster($identity['master_key']);
$blob .= $keys->source . $keys->subnet . $keys->session . $keys->principal . $keys->event;

// 3. Canonical IP encodings and masked networks.
$factory = new RiskIdentityFactory($keys);
foreach (PROBE_IPS as $probe) {
    $blob .= $factory->canonicalIp($probe) . $factory->maskIp($probe);
}

// 4. The identity golden vectors as raw pseudonym bytes.
$blob .= (string) hex2bin($factory->sessionId($identity['session']['cookie_hex']));
$blob .= (string) hex2bin($factory->principalId($identity['principal']['material_utf8']));
$blob .= (string) hex2bin($factory->sourceId($identity['source']['ip'], (int) $identity['source']['epoch'] * 900));
$blob .= (string) hex2bin($factory->subnetId($identity['subnet']['ip'], (int) $identity['subnet']['epoch'] * 900));
// The IPv6 source /64 vectors: expected, same-/64 sibling and a
// different /64. Hashing all three pins the masking rule (not only one
// derived value) across the two implementations.
$v6Epoch = (int) $identity['source_ipv6']['epoch'] * 900;
foreach (['ip', 'sibling_ip', 'other_ip'] as $v6Key) {
    $blob .= (string) hex2bin($factory->sourceId($identity['source_ipv6'][$v6Key], $v6Epoch));
}

// 5. Deployment namespace derivations from the shared vectors.
foreach ($fixtures['namespace_vectors'] as $vector) {
    $blob .= DeploymentNamespace::derive($vector['raw'], (int) $vector['version']);
}

echo hash('sha256', $blob), "\n";
