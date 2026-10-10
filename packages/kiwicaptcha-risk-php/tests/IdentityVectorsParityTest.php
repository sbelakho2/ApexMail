<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\IdentityVector;
use KiwiCaptcha\Risk\IdentityVectorInput;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use PHPUnit\Framework\TestCase;

/**
 * The risk-v2 identity contract and the shared cross-language corpus
 * (change.md 3.1.1), mirrored test for test by the Rust lane
 * (tests/identity_vectors.rs).
 *
 * Two enforced surfaces. First, protocol/risk-v2/identity.json: this
 * test re-derives every dimension straight from the file's declared
 * context string, epoch policy, key assignment and granularity, and
 * must reproduce the vector the package computes, so the file is the
 * machine-checked source of truth rather than documentation. Second,
 * protocol/risk-v2/identity-fixtures.json: the identical vectors the
 * Rust mirror asserts, byte for byte, null for null.
 *
 * `RISK_IDENTITY_VECTORS_PATH` overrides the corpus location,
 * `RISK_IDENTITY_CONTRACT_PATH` the contract file and
 * `RISK_ASN_DATASET_PATH` the dataset both resolve through.
 */
final class IdentityVectorsParityTest extends TestCase
{
    private function contractPath(): string
    {
        $env = getenv('RISK_IDENTITY_CONTRACT_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v2/identity.json';
    }

    private function vectorsPath(): string
    {
        $env = getenv('RISK_IDENTITY_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v2/identity-fixtures.json';
    }

    private function datasetPath(): string
    {
        $env = getenv('RISK_ASN_DATASET_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname($this->vectorsPath()) . '/../asn/sample-asn.tsv';
    }

    /** @return array<string, mixed> */
    private function load(string $path): array
    {
        self::assertFileExists($path, "identity vectors file not found at {$path}");
        $doc = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($doc);

        return $doc;
    }

    /** @return array<string, string> the 32-byte keys by hkdf info */
    private function keysByInfo(RiskKeys $keys): array
    {
        return [
            'source' => $keys->source,
            'subnet' => $keys->subnet,
            'session' => $keys->session,
            'principal' => $keys->principal,
            'target' => $keys->target,
        ];
    }

    /**
     * Re-derives one dimension exactly as the contract file declares
     * it, through the factory's shared pseudonym primitive rather than
     * the derivation methods under test.
     *
     * @param array<string, mixed> $spec
     */
    private function contractDerivation(
        array $spec,
        RiskIdentityFactory $factory,
        array $keysByInfo,
        string $ip,
        string $bucket,
        ?string $cookieHex,
        ?string $principal,
        ?string $agent,
        ?string $normalizedTarget,
        int $now,
    ): ?string {
        $context = $spec['hmac_context'];
        $key = $keysByInfo[$spec['hkdf_info']];
        $epoch = 0;
        if ($spec['epoch_policy']['mode'] === 'rotated') {
            $epoch = intdiv($now, $spec['epoch_policy']['window_secs']);
        }
        switch ($context) {
            case 'src':
                return $factory->pseudonym($key, $context, $epoch, \KiwiCaptcha\Issuer::canonicalSourceFamily($ip));
            case 'net':
                return $factory->pseudonym($key, $context, $epoch, $factory->maskIp(
                    $ip,
                    $spec['granularity']['ipv4_prefix'],
                    $spec['granularity']['ipv6_prefix'],
                ));
            case 'asn':
                return $factory->pseudonym($key, $context, $epoch, $bucket);
            case 'sess':
                if ($cookieHex === null) {
                    return null;
                }

                return $factory->pseudonym($key, $context, $epoch, hex2bin($cookieHex));
            case 'prin':
                return $principal === null ? null : $factory->pseudonym($key, $context, $epoch, $principal);
            case 'agent':
                return $agent === null ? null : $factory->pseudonym($key, $context, $epoch, $agent);
            case 'tgt':
                if ($normalizedTarget === null || $normalizedTarget === '') {
                    return null;
                }
                // The fixed target slot carries the pipeline version and
                // the digest stays whole at 32 bytes.
                $message = "kiwi-risk-id-v1\0{$context}\0" . pack('J', TargetIdentifierNormalizer::VERSION) . $normalizedTarget;

                return hash_hmac('sha256', $message, $key);
        }

        self::fail("unknown hmac context in the contract: {$context}");
    }

    public function testTheContractFileDeclaresTheSevenDimensionsInOrder(): void
    {
        $contract = $this->load($this->contractPath());
        self::assertSame('kiwicaptcha.identity-v2/1', $contract['contract']);
        self::assertSame(IdentityVector::DIMENSIONS, $contract['dimension_order']);
        foreach (IdentityVector::DIMENSIONS as $name) {
            $spec = $contract['dimensions'][$name];
            self::assertIsString($spec['hmac_context'], "{$name} declares a context");
            self::assertIsString($spec['hkdf_info'], "{$name} declares a key");
            self::assertIsArray($spec['granularity'], "{$name} declares granularity");
            self::assertIsArray($spec['epoch_policy'], "{$name} declares an epoch policy");
            self::assertIsInt($spec['cardinality_bound'], "{$name} declares a cardinality bound");
            self::assertSame($name === 'target' ? 32 : 16, $spec['output_bytes'], "{$name} declares its pseudonym length");
        }
        // The rotated windows and fixed TTLs the engine carries by
        // default are the contract's: read from the same constants the
        // engine and the identity factory use, never a second literal.
        self::assertSame(RiskIdentityFactory::ASN_EPOCH_SECS, $contract['dimensions']['asn']['epoch_policy']['window_secs']);
        self::assertSame(900, $contract['dimensions']['source']['epoch_policy']['window_secs']);
        self::assertSame(900, $contract['dimensions']['subnet']['epoch_policy']['window_secs']);
        self::assertSame(1800, $contract['dimensions']['source']['ttl_secs']['fast']);
        self::assertSame(86400, $contract['dimensions']['source']['ttl_secs']['slow']);
        self::assertSame(1800, $contract['dimensions']['session']['ttl_secs']['fast']);
        self::assertSame(86400, $contract['dimensions']['principal']['ttl_secs']['fast']);
        self::assertNull($contract['dimensions']['agent']['ttl_secs']);
    }

    public function testTheContractFileReproducesEveryDerivedDimension(): void
    {
        $contract = $this->load($this->contractPath());
        $corpus = $this->load($this->vectorsPath());
        $keys = RiskKeys::fromMaster($corpus['master_key']);
        $keysByInfo = $this->keysByInfo($keys);
        $factory = new RiskIdentityFactory($keys);
        $dataset = AsnDataset::open($this->datasetPath());

        $checked = 0;
        foreach ($corpus['vectors'] as $vector) {
            $input = new IdentityVectorInput(
                clientIp: $vector['client_ip'],
                sessionCookieHex: $vector['session_cookie_hex'] ?? null,
                principalId: $vector['principal_id'] ?? null,
                agentKeyId: $vector['agent_key_id'] ?? null,
                targetNormalized: $vector['target_normalized'] ?? null,
                asnDataset: $dataset,
                nowUnixSecs: $vector['now_unix_secs'],
            );
            $derived = IdentityVector::derive($input, $factory);
            foreach (IdentityVector::DIMENSIONS as $name) {
                $expected = $this->contractDerivation(
                    $contract['dimensions'][$name],
                    $factory,
                    $keysByInfo,
                    $vector['client_ip'],
                    $dataset->bucketId($vector['client_ip']),
                    $vector['session_cookie_hex'] ?? null,
                    $vector['principal_id'] ?? null,
                    $vector['agent_key_id'] ?? null,
                    $vector['target_normalized'] ?? null,
                    $vector['now_unix_secs'],
                );
                self::assertSame(
                    $expected,
                    $derived->dimension($name),
                    sprintf('vector %s dimension %s diverges from the contract file', $vector['name'], $name),
                );
                $checked++;
            }
        }
        self::assertGreaterThanOrEqual(12 * 7, $checked);
    }

    public function testSharedVectorsReproduceByteIdentically(): void
    {
        $corpus = $this->load($this->vectorsPath());
        $dataset = AsnDataset::open($this->datasetPath());
        self::assertSame(
            $corpus['asn_dataset']['sha256'],
            $dataset->datasetInfo()->sha256,
            'the corpus pins the dataset digest it was generated from',
        );
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster($corpus['master_key']));

        $byName = [];
        foreach ($corpus['vectors'] as $vector) {
            // The target dimension rides the versioned normalization
            // pipeline: the corpus's raw value must normalize to the
            // corpus's normalized value before the pseudonym derives.
            $normalized = null;
            if (isset($vector['target_raw'])) {
                $normalized = TargetIdentifierNormalizer::normalize($vector['target_raw']);
                self::assertSame(
                    $vector['target_normalized'],
                    $normalized,
                    sprintf('vector %s: the normalization pipeline diverges from the corpus', $vector['name']),
                );
            }
            $input = new IdentityVectorInput(
                clientIp: $vector['client_ip'],
                sessionCookieHex: $vector['session_cookie_hex'] ?? null,
                principalId: $vector['principal_id'] ?? null,
                agentKeyId: $vector['agent_key_id'] ?? null,
                targetNormalized: $normalized,
                asnDataset: $dataset,
                nowUnixSecs: $vector['now_unix_secs'],
            );
            $derived = IdentityVector::derive($input, $factory);
            foreach (IdentityVector::DIMENSIONS as $name) {
                self::assertSame(
                    $vector['expected'][$name],
                    $derived->dimension($name),
                    sprintf('vector %s dimension %s diverges from the shared corpus', $vector['name'], $name),
                );
            }
            self::assertSame(
                $vector['expected_asn_bucket'],
                $dataset->bucketId($vector['client_ip']),
                sprintf('vector %s: the stated bucket diverges from the dataset', $vector['name']),
            );
            $byName[$vector['name']] = $derived;
        }

        // The mapped and compatible v6 spellings derive the identical
        // vectors to their plain v4 counterparts, and a sibling host
        // in the same /64 shares source, subnet and asn.
        self::assertEquals($byName['canonical_ipv4_all_dimensions'], $byName['v4_mapped_v6_spelling']);
        self::assertEquals($byName['boundary_epoch_zero'], $byName['v4_compatible_spelling']);
        $ipv6 = $byName['plain_ipv6_unicode_target'];
        $sibling = $byName['v6_sibling_same_64'];
        self::assertSame($ipv6->source, $sibling->source);
        self::assertSame($ipv6->subnet, $sibling->subnet);
        self::assertSame($ipv6->asn, $sibling->asn);
        // Epoch 0 covers the whole first window, epoch 1 differs on
        // the rotated dimensions and the fixed ones stay put.
        $zero = $byName['boundary_epoch_zero'];
        self::assertEquals($zero, $byName['boundary_epoch_zero_late_in_window']);
        $one = $byName['boundary_epoch_one'];
        self::assertNotSame($zero->source, $one->source);
        self::assertNotSame($zero->subnet, $one->subnet);
        self::assertSame($zero->asn, $one->asn, '900 s stays inside the asn window');
        self::assertSame($zero->session, $one->session);
        self::assertSame($zero->principal, $one->principal);
    }
}
