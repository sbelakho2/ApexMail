<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Asn\AsnBucket;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Asn\AsnDatasetException;
use PHPUnit\Framework\TestCase;

/**
 * The ASN dataset loader over the versioned sample fixture
 * (protocol/asn/sample-asn.tsv) and the shared cross-language vectors
 * (protocol/risk-v1/asn-vectors.json): the Rust mirror
 * (tests/asn_vectors.rs and src/asn.rs) resolves the identical bucket
 * ids with the identical row accounting. `RISK_ASN_VECTORS_PATH` and
 * `RISK_ASN_DATASET_PATH` override the fixture locations.
 */
final class AsnDatasetTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_ASN_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/risk-v1/asn-vectors.json';
    }

    private function datasetPath(): string
    {
        $env = getenv('RISK_ASN_DATASET_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        return dirname(__DIR__) . '/../../protocol/asn/sample-asn.tsv';
    }

    /** @return array<string, array<string, mixed>> */
    private function corpus(): array
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('ASN vectors file not found at %s (set RISK_ASN_VECTORS_PATH)', $path));
        $doc = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($doc);
        self::assertSame('risk-v1', $doc['protocol']);
        self::assertSame(AsnDataset::FORMAT_VERSION, $doc['dataset_format_version'], 'the corpus was generated under a different format version');
        self::assertSame(AsnDataset::BUCKET_ID_VERSION, $doc['bucket_id_version'], 'the corpus was generated under a different bucket grammar');

        return $doc;
    }

    public function testSharedVectorsResolveIdentically(): void
    {
        $doc = $this->corpus();
        $dataset = AsnDataset::open($this->datasetPath());

        // The corpus pins the exact bytes the resolutions were generated
        // from: a drifted fixture fails here instead of silently passing.
        $info = $dataset->datasetInfo();
        self::assertSame($doc['dataset_sha256'], $info->sha256);
        self::assertSame($doc['dataset_byte_len'], $info->byteLen);
        self::assertSame($doc['expected_valid_rows'], $info->validRows);
        self::assertSame($doc['expected_malformed_rows'], $info->malformedRows);

        $count = 0;
        foreach ($doc['vectors'] as $vector) {
            $lookup = $dataset->lookup($vector['ip']);
            self::assertSame(
                $vector['expected_bucket'],
                $lookup->bucket,
                sprintf('vector "%s" must resolve its bucket', $vector['note']),
            );
            if (substr($vector['expected_bucket'], 0, 1) === 'a') {
                self::assertSame((int) substr($vector['expected_bucket'], 1), $lookup->asn, $vector['note']);
            } else {
                self::assertNull($lookup->asn, sprintf('vector "%s" must resolve no ASN', $vector['note']));
            }
            // Deterministic: a repeated lookup is the identical resolution.
            self::assertEquals($lookup, $dataset->lookup($vector['ip']), $vector['note']);
            self::assertTrue(AsnBucket::isValid($vector['expected_bucket']));
            $count++;
        }
        self::assertGreaterThanOrEqual(20, $count, 'the vector families must stay rich');
    }

    public function testMappedFormsResolveAsTheirIpv4Twins(): void
    {
        $dataset = AsnDataset::open($this->datasetPath());

        self::assertSame($dataset->bucketId('203.0.113.7'), $dataset->bucketId('::ffff:203.0.113.7'));
        self::assertSame($dataset->bucketId('192.0.2.44'), $dataset->bucketId('::192.0.2.44'));
    }

    public function testGapFamiliesShareBucketsExactlyPerPrefix(): void
    {
        $dataset = AsnDataset::open($this->datasetPath());

        self::assertSame($dataset->bucketId('203.0.113.150'), $dataset->bucketId('203.0.113.199'));
        self::assertNotSame($dataset->bucketId('203.0.113.150'), $dataset->bucketId('203.1.113.1'));
        self::assertSame($dataset->bucketId('2001:db8:3::1'), $dataset->bucketId('2001:db8:5::1'));
        self::assertNotSame($dataset->bucketId('2001:db8:3::1'), $dataset->bucketId('2600::1'));
    }

    public function testBucketGrammarIsCanonical(): void
    {
        self::assertTrue(AsnBucket::isValid('a1'));
        self::assertTrue(AsnBucket::isValid('a64496'));
        self::assertTrue(AsnBucket::isValid('a4294967294'));
        self::assertFalse(AsnBucket::isValid('a0'));
        self::assertFalse(AsnBucket::isValid('a4294967295'));
        self::assertFalse(AsnBucket::isValid('a042'));
        self::assertTrue(AsnBucket::isValid('u4/0'));
        self::assertTrue(AsnBucket::isValid('u4/65535'));
        self::assertFalse(AsnBucket::isValid('u4/65536'));
        self::assertFalse(AsnBucket::isValid('u4/0042'));
        self::assertTrue(AsnBucket::isValid('u6/20010db8'));
        self::assertTrue(AsnBucket::isValid('u6/00000000'));
        self::assertFalse(AsnBucket::isValid('u6/20010DBG'));
        self::assertFalse(AsnBucket::isValid('u6/20010db'));
        self::assertFalse(AsnBucket::isValid(''));
        self::assertFalse(AsnBucket::isValid('b1'));

        self::assertSame('a64496', AsnBucket::forKnownAsn(64496));
        self::assertSame('u4/51968', AsnBucket::forUnlistedV4("\xcb\x00"));
        self::assertSame('u6/20010db8', AsnBucket::forUnlistedV6("\x20\x01\x0d\xb8"));
        $this->expectException(\InvalidArgumentException::class);
        AsnBucket::forKnownAsn(0);
    }

    public function testDatasetInfoCarriesDigestAndAge(): void
    {
        $dataset = AsnDataset::open($this->datasetPath());
        $info = $dataset->datasetInfo();

        self::assertSame($this->datasetPath(), $info->path);
        self::assertSame(64, \strlen($info->sha256));
        self::assertSame(AsnDataset::FORMAT_VERSION, $info->formatVersion);
        $now = time();
        self::assertGreaterThan(0, $info->mtimeUnixSecs);
        self::assertGreaterThanOrEqual($info->mtimeUnixSecs, $now);
        self::assertSame(max(0, $now - $info->mtimeUnixSecs), $info->ageSecs($now));
    }

    public function testABackdatedMtimeYieldsAMeasurableAge(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'kiwi-asn-age-');
        self::assertIsString($path);
        file_put_contents($path, "10.0.0.0\t10.0.0.255\t100\n");
        touch($path, time() - 86400);
        $dataset = AsnDataset::open($path);
        self::assertGreaterThanOrEqual(86000, $dataset->datasetInfo()->ageSecs(time()));
        unlink($path);
    }

    public function testOpenRefusesMissingAndEmptyDatasets(): void
    {
        try {
            AsnDataset::open('/nonexistent/asn.tsv');
            self::fail('a missing dataset must be refused');
        } catch (AsnDatasetException $e) {
            self::assertSame(AsnDatasetException::UNREADABLE, $e->kind());
        }

        $path = tempnam(sys_get_temp_dir(), 'kiwi-asn-empty-');
        self::assertIsString($path);
        file_put_contents($path, "# only a comment\n\n");
        try {
            AsnDataset::open($path);
            self::fail('an empty dataset must be refused');
        } catch (AsnDatasetException $e) {
            self::assertSame(AsnDatasetException::EMPTY, $e->kind());
        }
        unlink($path);
    }

    public function testMalformedRowsAreSkippedAndCounted(): void
    {
        // Every documented malformed family: an unparsable IP on either
        // end, a reversed range, a mixed family, a non-numeric ASN and
        // AS 0. One valid row keeps the table servable.
        $body = "10.0.0.0\t10.0.0.255\t100\n"
            . "not-an-ip\t10.0.1.1\t100\n"
            . "10.0.2.0\tnot-an-ip\t100\n"
            . "10.0.3.5\t10.0.3.1\t100\n"
            . "2001:db8::\t10.0.4.1\t100\n"
            . "10.0.5.0\t10.0.5.255\tzero\n"
            . "10.0.6.0\t10.0.6.255\t0\n";
        $path = tempnam(sys_get_temp_dir(), 'kiwi-asn-malformed-');
        self::assertIsString($path);
        file_put_contents($path, $body);
        $dataset = AsnDataset::open($path);
        $info = $dataset->datasetInfo();
        self::assertSame(1, $info->validRows);
        self::assertSame(6, $info->malformedRows);
        self::assertSame('a100', $dataset->bucketId('10.0.0.9'));
        self::assertSame('u4/2560', $dataset->bucketId('10.0.1.9'));
        unlink($path);
    }

    public function testHotReloadSwapsAtomicallyAndRejectsBadInputs(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'kiwi-asn-reload-');
        self::assertIsString($path);
        $a = "10.0.0.0\t10.0.0.255\t100\n";
        $b = "10.0.0.0\t10.0.0.255\t200\n";
        file_put_contents($path, $a);
        $dataset = AsnDataset::open($path);
        self::assertSame('a100', $dataset->bucketId('10.0.0.9'));

        // A successful reload swaps the table and reports the new digest.
        file_put_contents($path, $b);
        $digestB = hash('sha256', $b);
        $info = $dataset->reload($digestB);
        self::assertSame($digestB, $info->sha256);
        self::assertSame('a200', $dataset->bucketId('10.0.0.9'));

        // A digest mismatch is rejected and the serving table survives.
        file_put_contents($path, $a);
        try {
            $dataset->reload($digestB);
            self::fail('a changed file under a pinned digest must be refused');
        } catch (AsnDatasetException $e) {
            self::assertSame(AsnDatasetException::DIGEST_MISMATCH, $e->kind());
        }
        self::assertSame('a200', $dataset->bucketId('10.0.0.9'));

        // An all-malformed file is refused; the serving table survives.
        file_put_contents($path, "garbage row\n");
        try {
            $dataset->reload();
            self::fail('an all-malformed file must be refused');
        } catch (AsnDatasetException $e) {
            self::assertSame(AsnDatasetException::EMPTY, $e->kind());
        }
        self::assertSame('a200', $dataset->bucketId('10.0.0.9'));

        // An absent file is refused the same way.
        unlink($path);
        try {
            $dataset->reload();
            self::fail('a missing file must be refused');
        } catch (AsnDatasetException $e) {
            self::assertSame(AsnDatasetException::UNREADABLE, $e->kind());
        }
        self::assertSame('a200', $dataset->bucketId('10.0.0.9'));
    }

    public function testLookupRefusesInvalidIpsFailClosed(): void
    {
        $dataset = AsnDataset::open($this->datasetPath());
        foreach (['not-an-ip', '203.0.113.027', ''] as $bad) {
            try {
                $dataset->lookup($bad);
                self::fail(sprintf('"%s" must be refused as an IP', $bad));
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
