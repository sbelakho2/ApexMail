<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Asset;

/**
 * The shared asset-digest index for asset_mode "files".
 *
 * Every PHP-FPM request boots a fresh container, so re-reading and
 * SHA-256ing the widget assets on every render is pure per-request
 * CPU: about 470 KB across the eight files, plus about 575 KB for the
 * /api.js loader body. The index stores each file's sha256, size and mtime
 * in a small generated PHP file written at cache warmup and lazily
 * refreshed when a file changes, so the runtime and controllers only
 * read the digest they need.
 *
 * The index is self-validating: an entry is trusted only while the
 * file's size and mtime match the recorded ones. Anything newer or
 * missing is re-hashed once, and the index file is rewritten
 * atomically so concurrent workers never read a torn map. A read-only
 * or absent cache file degrades to per-process hashing with no
 * correctness impact.
 */
final class AssetDigestIndex
{
    /** @var array<string, array{sha256: string, size: int, mtime: int}>|null */
    private ?array $entries = null;

    public function __construct(
        private readonly string $assetsDir,
        ?string $cacheFile = null,
    ) {
        // No kernel.cache_dir dependency: bare ContainerBuilders and
        // kernel-less tests do not define that parameter. The default
        // lives in the system temp directory, keyed by the assets path
        // so two deployments never share a map, and the cache warmer
        // writes it at deploy time.
        $this->cacheFile = $cacheFile ?? rtrim(sys_get_temp_dir(), '/').'/kiwicaptcha-asset-digests-'.substr(hash('sha256', $assetsDir), 0, 16).'.php';
    }

    private readonly string $cacheFile;

    /**
     * The lowercase 64-hex sha256 of one asset file, or null when the
     * file is missing or unreadable.
     */
    public function digest(string $file): ?string
    {
        $entries = $this->entries();

        return $entries[$file]['sha256'] ?? null;
    }

    /** The byte size of one asset file, or null when it is missing. */
    public function size(string $file): ?int
    {
        $entries = $this->entries();

        return $entries[$file]['size'] ?? null;
    }

    /**
     * The exact bytes of one asset file, or null when it is missing or
     * empty; an empty asset is never servable.
     */
    public function read(string $file): ?string
    {
        $path = rtrim($this->assetsDir, '/').'/'.$file;
        if (!is_file($path)) {
            return null;
        }
        $body = @file_get_contents($path);

        return $body === false || $body === '' ? null : $body;
    }

    /**
     * The index map, loaded from the generated file when it is present
     * and fresh, otherwise recomputed and persisted best-effort.
     *
     * @return array<string, array{sha256: string, size: int, mtime: int}>
     */
    public function entries(): array
    {
        if ($this->entries !== null) {
            return $this->entries;
        }
        $stored = $this->load();
        $entries = [];
        $dirty = false;
        foreach ($this->assetFiles() as $file) {
            $path = rtrim($this->assetsDir, '/').'/'.$file;
            $size = @filesize($path);
            $mtime = @filemtime($path);
            if ($size === false || $mtime === false) {
                $dirty = $stored !== null;
                continue;
            }
            $known = $stored[$file] ?? null;
            if ($known !== null && $known['size'] === $size && $known['mtime'] === $mtime) {
                $entries[$file] = $known;
                continue;
            }
            $sha = @hash_file('sha256', $path);
            if ($sha === false) {
                $dirty = true;
                continue;
            }
            $entries[$file] = ['sha256' => $sha, 'size' => $size, 'mtime' => $mtime];
            $dirty = true;
        }
        $this->entries = $entries;
        if ($dirty) {
            $this->persist($entries);
        }

        return $entries;
    }

    /**
     * The digest of a fully built body, the /api.js loader: the body is
     * built from the indexed assets, so its own digest is computed once
     * per process and never re-hashed per request.
     */
    public function bodyDigest(string $body): string
    {
        return hash('sha256', $body);
    }

    public function assetsDir(): string
    {
        return $this->assetsDir;
    }

    /**
     * The fixed asset-file set the index knows about: every file the
     * AssetController can serve plus the /api.js loader chunks.
     *
     * @return list<string>
     */
    private function assetFiles(): array
    {
        $files = [];
        foreach (scandir($this->assetsDir) ?: [] as $entry) {
            if (str_ends_with($entry, '.js') || str_ends_with($entry, '.css')) {
                $files[] = $entry;
            }
        }
        sort($files);

        return $files;
    }

    /** @return array<string, array{sha256: string, size: int, mtime: int}>|null */
    private function load(): ?array
    {
        if ($this->cacheFile === null || !is_file($this->cacheFile)) {
            return null;
        }
        $stored = @include $this->cacheFile;

        return \is_array($stored) ? $stored : null;
    }

    /** @param array<string, array{sha256: string, size: int, mtime: int}> $entries */
    private function persist(array $entries): void
    {
        if ($this->cacheFile === null) {
            return;
        }
        $dir = \dirname($this->cacheFile);
        if (!is_dir($dir) && !@mkdir($dir, 0o755, true) && !is_dir($dir)) {
            return;
        }
        $tmp = @tempnam($dir, 'kiwi-assets-');
        if ($tmp === false) {
            return;
        }
        $php = "<?php\n\n// Generated by AssetDigestIndex::persist(); regenerated whenever an\n// asset file's size/mtime changes. Safe to delete.\nreturn ".var_export($entries, true).";\n";
        if (@file_put_contents($tmp, $php) === false) {
            @unlink($tmp);

            return;
        }
        @rename($tmp, $this->cacheFile);
    }
}
