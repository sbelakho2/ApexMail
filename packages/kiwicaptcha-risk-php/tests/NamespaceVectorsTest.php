<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\DeploymentNamespace;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The shared golden vectors (protocol/risk-v1/fixtures.json): the PHP
 * derivation and the Rust `namespace` module must produce the identical
 * encoded namespace AND the identical full Redis key set for every input,
 * in both key versions. The Rust side asserts the same rows in
 * `packages/kiwicaptcha-risk/src/namespace.rs`, so a divergence in either
 * language fails that language's suite against the one shared asset.
 */
final class NamespaceVectorsTest extends TestCase
{
    public function testGoldenVectorsMatchTheSharedAsset(): void
    {
        $path = \dirname(__DIR__).'/../../protocol/risk-v1/fixtures.json';
        if (!is_file($path)) {
            self::markTestSkipped('fixtures.json not present (monorepo layout expected at protocol/risk-v1/)');
        }
        $fixtures = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($fixtures);
        $vectors = $fixtures['namespace_vectors'] ?? null;
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors);

        foreach ($vectors as $vector) {
            self::assertIsArray($vector);
            $raw = $vector['raw'];
            $version = $vector['version'];
            self::assertIsString($raw);
            self::assertIsInt($version);

            self::assertSame(
                $vector['derived'],
                DeploymentNamespace::derive($raw, $version),
                sprintf('derived namespace mismatch for "%s" v%d', $raw, $version),
            );

            $keys = RedisRiskStateStore::keysFor(
                $raw,
                $version,
                1700000000,
                'aa11',
                'bb22',
                'cc33',
                1700000900,
                'dd44',
                'ee55',
                'ff66',
                null,
                null,
                '0123abcd',
            );
            self::assertSame(
                $vector['observation_keys'],
                $keys,
                sprintf('full key set mismatch for "%s" v%d', $raw, $version),
            );
            self::assertSame(
                $vector['outcome_ledger_key'],
                sprintf('{kiwi:%s}:outcome:dec-1', DeploymentNamespace::derive($raw, $version)),
                sprintf('outcome ledger key mismatch for "%s" v%d', $raw, $version),
            );
        }
    }
}
