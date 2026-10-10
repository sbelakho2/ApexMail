<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Asset;

use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;

/**
 * Precomputes the asset-digest index at cache warmup: the deploy-time
 * moment that already touches the filesystem, so PHP-FPM requests never
 * pay the first-request hashing cost of the eight widget assets.
 * AssetDigestIndex::persist() writes the generated map; runtime lazily
 * refreshes it if an asset changes under a warm cache.
 */
final class AssetDigestCacheWarmer implements CacheWarmerInterface
{
    public function __construct(
        private readonly AssetDigestIndex $digests,
    ) {
    }

    public function isOptional(): bool
    {
        return true;
    }

    /** @return list<string> */
    public function warmUp(string $cacheDir, ?string $buildDir = null): array
    {
        $this->digests->entries();

        return [];
    }
}
