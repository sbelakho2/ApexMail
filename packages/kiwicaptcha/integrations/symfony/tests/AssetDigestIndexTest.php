<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Asset\AssetDigestCacheWarmer;
use BelConsulting\KiwiCaptchaBundle\Asset\AssetDigestIndex;
use PHPUnit\Framework\TestCase;

/**
 * The warmup-generated asset-digest map: correct digests, a generated
 * PHP file, and automatic invalidation when an asset's size/mtime
 * changes under a warm cache.
 */
final class AssetDigestIndexTest extends TestCase
{
    private const ASSETS_DIR = __DIR__.'/../Resources/public';

    private string $workDir;
    private string $assetsDir;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir().'/kiwi-digest-index-'.bin2hex(random_bytes(6));
        $this->assetsDir = $this->workDir.'/assets';
        mkdir($this->assetsDir, 0o755, true);
        copy(self::ASSETS_DIR.'/widget-locales.js', $this->assetsDir.'/widget-locales.js');
        copy(self::ASSETS_DIR.'/widget-driver.js', $this->assetsDir.'/widget-driver.js');
    }

    protected function tearDown(): void
    {
        @unlink($this->assetsDir.'/widget-locales.js');
        @unlink($this->assetsDir.'/widget-driver.js');
        @unlink($this->workDir.'/index.php');
        @rmdir($this->assetsDir);
        @rmdir($this->workDir);
    }

    public function testWarmupWritesTheGeneratedMapWithExactDigests(): void
    {
        $cacheFile = $this->workDir.'/index.php';
        $index = new AssetDigestIndex($this->assetsDir, $cacheFile);
        (new AssetDigestCacheWarmer($index))->warmUp($this->workDir);

        self::assertFileExists($cacheFile, 'the warmer must write the generated digest file');
        $expected = hash_file('sha256', $this->assetsDir.'/widget-locales.js');
        self::assertSame($expected, $index->digest('widget-locales.js'));
        self::assertSame('sha256', \strlen((string) $index->digest('widget-locales.js')) === 64 ? 'sha256' : '?');

        // A second index over the generated file answers identically
        // without re-hashing (the map is trusted while size/mtime hold).
        $reloaded = new AssetDigestIndex($this->assetsDir, $cacheFile);
        self::assertSame($expected, $reloaded->digest('widget-locales.js'));
    }

    public function testChangedAssetInvalidatesAndRewritesTheEntry(): void
    {
        $cacheFile = $this->workDir.'/index.php';
        $index = new AssetDigestIndex($this->assetsDir, $cacheFile);
        $before = $index->digest('widget-driver.js');

        $mutated = (string) file_get_contents($this->assetsDir.'/widget-driver.js')."\n// changed\n";
        file_put_contents($this->assetsDir.'/widget-driver.js', $mutated);
        // Ensure a distinct mtime even on coarse filesystems.
        touch($this->assetsDir.'/widget-driver.js', time() + 2);
        clearstatcache();

        $reloaded = new AssetDigestIndex($this->assetsDir, $cacheFile);
        $after = $reloaded->digest('widget-driver.js');
        self::assertNotSame($before, $after, 'a changed asset must be re-hashed');
        self::assertSame(hash('sha256', $mutated), $after);
        // The rewritten generated file reflects the new digest.
        $persisted = include $cacheFile;
        self::assertSame($after, $persisted['widget-driver.js']['sha256']);
    }

    public function testMissingAssetsAreSimplyAbsent(): void
    {
        $index = new AssetDigestIndex($this->assetsDir);
        self::assertNull($index->digest('widget-risk.js'));
        self::assertNull($index->size('widget-risk.js'));
        self::assertNull($index->read('widget-risk.js'));
    }
}
