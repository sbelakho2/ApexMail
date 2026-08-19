<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * In-memory NONCE-LEVEL redemption guard for tests/dev (single-process
 * semantics, like ArrayStorage). NOT for production: the guard must
 * survive across requests.
 *
 * Clock-less by design: register is a plain set-if-absent (first write
 * wins — no clock seam needed for the determinism of the write itself),
 * with a time()-based expiry bound like the metadata sidecar.
 */
final class ArraySiteVerifyRedemptionGuard implements SiteVerifyRedemptionGuard
{
    /** @var array<string, array{0: string, 1: int}> key => [responseHash, expiresAt] */
    private array $records = [];

    public function register(string $backendId, string $nonce, string $responseHash, int $ttlSeconds): void
    {
        $key = $this->key($backendId, $nonce);
        if (isset($this->records[$key])) {
            return;
        }
        $this->records[$key] = [$responseHash, time() + max(1, $ttlSeconds)];
    }

    public function originalHash(string $backendId, string $nonce): ?string
    {
        $key = $this->key($backendId, $nonce);
        $entry = $this->records[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry[1] < time()) {
            unset($this->records[$key]);

            return null;
        }

        return $entry[0];
    }

    private function key(string $backendId, string $nonce): string
    {
        return $backendId.':'.$nonce;
    }
}
