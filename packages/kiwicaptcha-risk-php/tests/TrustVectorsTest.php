<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;
use PHPUnit\Framework\TestCase;

/**
 * Shared context-bound-trust vectors (protocol/risk-v1/
 * trust-vectors.json): every row pins the bucket id its IP resolves to
 * and the credit decision the policy derives from the recorded raw
 * trust; the Rust mirror (tests/trust_vectors.rs) derives the identical
 * outputs. `RISK_TRUST_VECTORS_PATH` overrides the corpus location.
 */
final class TrustVectorsTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_TRUST_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v1/trust-vectors.json';
    }

    /** @return array<string, mixed> */
    private function corpus(): array
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Trust vectors file not found at %s (set RISK_TRUST_VECTORS_PATH)', $path));
        $doc = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($doc);
        self::assertSame('risk-v1', $doc['protocol']);
        self::assertSame(AsnDataset::BUCKET_ID_VERSION, $doc['bucket_id_version'], 'the corpus was generated under a different bucket grammar');
        self::assertSame(ContextBoundTrust::SATURATION, $doc['trust_saturation']);

        return $doc;
    }

    private function dataset(array $doc): AsnDataset
    {
        return AsnDataset::open(dirname(__DIR__) . '/../..' . '/' . $doc['dataset_path']);
    }

    public function testSharedVectorsDecideIdentically(): void
    {
        $doc = $this->corpus();
        $dataset = $this->dataset($doc);
        $count = 0;
        foreach ($doc['vectors'] as $vector) {
            $bucket = $dataset->bucketId($vector['ip']);
            self::assertSame(
                $vector['expected_bucket'],
                $bucket,
                sprintf('vector "%s" must resolve its bucket', $vector['note']),
            );
            $decision = ContextBoundTrust::decision($bucket, $vector['raw_trust'] ?? 0);
            self::assertSame(
                $vector['expected_credit'],
                $decision->credit,
                sprintf('vector "%s" credit', $vector['note']),
            );
            self::assertSame(
                $vector['expected_is_home'],
                $decision->isHome,
                sprintf('vector "%s" home verdict', $vector['note']),
            );
            // Cross-bucket isolation: an absent foreign bucket earns
            // nothing and the home decision is reproducible.
            self::assertSame(0, ContextBoundTrust::decision('u4/1', 0)->credit);
            $count++;
        }
        self::assertGreaterThanOrEqual(10, $count, 'the vector families must stay rich');
    }

    public function testNormalizationMatchesTheFixedPointRule(): void
    {
        self::assertSame(0, ContextBoundTrust::normalize(0));
        self::assertSame(0, ContextBoundTrust::normalize(1));
        self::assertSame(0, ContextBoundTrust::normalize(9));
        self::assertSame(1, ContextBoundTrust::normalize(10));
        self::assertSame(250, ContextBoundTrust::normalize(2500));
        self::assertSame(999, ContextBoundTrust::normalize(9999));
        self::assertSame(1000, ContextBoundTrust::normalize(ContextBoundTrust::SATURATION));
        self::assertSame(1000, ContextBoundTrust::normalize(ContextBoundTrust::SATURATION + 1));
        self::assertSame(1000, ContextBoundTrust::normalize(\PHP_INT_MAX));
    }

    public function testAnAbsentOrZeroBucketEarnsNothing(): void
    {
        $absent = ContextBoundTrust::decision('u4/51968', 0);
        self::assertFalse($absent->isHome);
        self::assertSame(0, $absent->credit);
        self::assertSame(0, $absent->rawTrust);

        $home = ContextBoundTrust::decision('a64496', 4000);
        self::assertTrue($home->isHome);
        self::assertSame(400, $home->credit);
    }
}
