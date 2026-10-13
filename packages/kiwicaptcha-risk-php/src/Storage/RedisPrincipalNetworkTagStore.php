<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\DeploymentNamespace;
use Predis\Client;

/**
 * Production principal-network tag store over Redis, backed by the
 * canonical `principal_networks.lua` script. This is the only
 * production implementation of {@see PrincipalNetworkTagStoreInterface};
 * the in-memory fixtures in tests are named fakes and never wired into
 * the container.
 *
 * The hash key is `pnet:{kiwi:<ns>:<principal_hex>}`: the hash tag
 * carries the whole principal identity, so one principal's records
 * live on their own Cluster slot instead of every principal colliding
 * on the shared `{kiwi:<ns>}` slot (a hot slot under the record
 * rate). Deployments that already recorded under the older
 * `pnet:{kiwi:<ns>}:<principal_hex>` spelling keep their history: a
 * read-through migration probes the legacy key on a seen or
 * has_trusted miss, copies its fields into the current key and
 * deletes the legacy one. Each tag
 * (`net:<hex>`, `asn:<decimal|u4/prefix|u6/prefix>`, `session:<hex>`,
 * `device:<hex>`) is a hash field whose value is the last-use ms (Redis
 * TIME, never a client clock). The asn class carries a listed decimal
 * and the unlisted-namespace buckets. Trust is a `t:` prefixed mirror
 * field, minted only on an Allow or a completed step-up.
 *
 * Error contract: any Redis failure throws {@see RiskStoreException},
 * so the engine follows its existing fail-closed path. The store never
 * returns "not seen" on error (which would read as "novel" and price
 * users out without a signal) and never "seen" (which would fail open).
 * The one-time migration is auxiliary to the read it rides: a failed
 * probe or copy skips the migration for that read (the miss already
 * answered) and the next miss retries it.
 */
final class RedisPrincipalNetworkTagStore implements PrincipalNetworkTagStoreInterface
{
    /** Per-principal cap on session tags. */
    public const DEFAULT_SESSION_CAP = 32;
    /** Per-principal cap on device tags. */
    public const DEFAULT_DEVICE_CAP = 16;
    /** Per-principal cap on network and ASN tags. */
    public const DEFAULT_NET_CAP = 64;

    /** Session-tag TTL in ms (2x a 15-30 minute continuity cookie). */
    public const DEFAULT_SESSION_TTL_MS = 3_600_000;
    /** Device-tag TTL in ms (90 days). */
    public const DEFAULT_DEVICE_TTL_MS = 7_776_000_000;
    /** Network/ASN tag TTL in ms (400 days). */
    public const DEFAULT_NET_TTL_MS = 34_560_000_000;

    private readonly string $namespace;
    private string $scriptSha = '';

    /** @var array<string, true> principals whose legacy key was already migrated or found absent */
    private array $legacyChecked = [];

    /**
     * Production store over Redis.
     *
     * @param bool $migrateLegacy read-through migration of the legacy
     *                            shared-tag key form; default true for
     *                            one minor release
     */
    public function __construct(
        private readonly Client $client,
        string $namespace = 'd',
        private readonly int $sessionTtlMs = self::DEFAULT_SESSION_TTL_MS,
        private readonly int $deviceTtlMs = self::DEFAULT_DEVICE_TTL_MS,
        private readonly int $sessionCap = self::DEFAULT_SESSION_CAP,
        private readonly int $deviceCap = self::DEFAULT_DEVICE_CAP,
        private readonly int $netCap = self::DEFAULT_NET_CAP,
        int $namespaceKeyVersion = DeploymentNamespace::VERSION_LEGACY,
        private readonly bool $migrateLegacy = true,
    ) {
        if ($namespace === '' || preg_match('/[{}]/', $namespace)) {
            throw new \InvalidArgumentException('Risk namespace must be non-empty and free of braces');
        }
        if ($sessionTtlMs < 1 || $deviceTtlMs < 1) {
            throw new \InvalidArgumentException('Tag TTLs must be positive');
        }
        if ($sessionCap < 1 || $deviceCap < 1 || $netCap < 1) {
            throw new \InvalidArgumentException('Tag caps must be positive');
        }
        $this->namespace = DeploymentNamespace::derive($namespace, $namespaceKeyVersion);
    }

    /** The hash key of one principal's tag set. */
    public function tagKey(string $principalId): string
    {
        self::assertPrincipal($principalId);

        return "pnet:{kiwi:{$this->namespace}:{$principalId}}";
    }

    /** The pre-cluster-slot legacy hash key of one principal's tag set. */
    public function legacyTagKey(string $principalId): string
    {
        self::assertPrincipal($principalId);

        return "pnet:{kiwi:{$this->namespace}}:{$principalId}";
    }

    public function principalNetworkSeen(string $principalId, string $network): ?bool
    {
        $this->assertTag($network);
        // The configured class TTL rides every read (F6/N11): the script
        // answers "not seen" past the caller's TTL, never past the class
        // maximum, so a stored value cannot vouch past the lifetime the
        // deployment actually configured.
        [, $ttlMs] = $this->classOf($network);
        try {
            $result = $this->runScript([$this->tagKey($principalId)], ['seen', $network, (string) $ttlMs]);
            $seen = (int) $result === 1;
            if (!$seen) {
                // A miss under the current key may still be history
                // under the pre-cluster-slot spelling: migrate once,
                // then re-read the migrated state.
                $this->migrateLegacyKey($principalId);
                $result = $this->runScript([$this->tagKey($principalId)], ['seen', $network, (string) $ttlMs]);
                $seen = (int) $result === 1;
            }

            return $seen;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal network seen probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function recordPrincipalNetworkTag(string $principalId, string $network, bool $trusted = false): bool
    {
        $this->assertTag($network);
        [$class, $ttlMs, $cap] = $this->classOf($network);
        try {
            $result = $this->runScript(
                [$this->tagKey($principalId)],
                ['record', $network, (string) $ttlMs, (string) $cap, $trusted ? '1' : '0'],
            );

            return (int) $result === 1;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal network record failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function principalHasTrustedNetwork(string $principalId): ?bool
    {
        // A trusted network counts only the network classes: the
        // script's has_any_trusted op walks the trust mirrors atomically
        // inside the script and answers for net, asn and the engine's
        // bare-hex bucket spelling. Session and device mirrors are the
        // continuity plane's evidence and never make an account
        // network-trusted (a live bare tag behind the mirror answers
        // true, so the "any" variant no longer side-channels a
        // whole-hash read around the script).
        try {
            $result = $this->runScript([$this->tagKey($principalId)], ['has_any_trusted', '']);

            return (int) $result === 1;
        } catch (\Throwable $e) {
            throw new RiskStoreException('principal trusted-network probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function tagIsTrusted(string $principalId, string $network): ?bool
    {
        $this->assertTag($network);
        // The configured class TTL rides the trust probe too (F6/N11):
        // a trust flag past the deployment's device/session TTL answers
        // "not trusted", never the script's class-ceiling lifetime.
        [, $ttlMs] = $this->classOf($network);
        try {
            $result = $this->runScript([$this->tagKey($principalId)], ['has_trusted', $network, (string) $ttlMs]);
            $trusted = (int) $result === 1;
            if (!$trusted) {
                // A miss under the current key may still be history
                // under the pre-cluster-slot spelling: migrate once,
                // then re-read the migrated state.
                $this->migrateLegacyKey($principalId);
                $result = $this->runScript([$this->tagKey($principalId)], ['has_trusted', $network, (string) $ttlMs]);
                $trusted = (int) $result === 1;
            }

            return $trusted;
        } catch (\Throwable $e) {
            throw new RiskStoreException('tag trust probe failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Deletes every session and device tag for a principal (revocation).
     * The deletion runs inside the canonical script's atomic
     * `forget_devices` operation: one hash deletion removes the tags
     * and their trust mirrors, so a record racing the revocation cannot
     * survive half-deleted.
     */
    public function forgetDevices(string $principalId): void
    {
        self::assertPrincipal($principalId);
        try {
            $this->runScript([$this->tagKey($principalId)], ['forget_devices']);
        } catch (\Throwable $e) {
            throw new RiskStoreException('forget devices failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Read-through migration of the legacy shared-tag history. The
     * legacy `pnet:{kiwi:<ns>}:<principal>` hash (the spelling the
     * store wrote before the hash tag carried the principal) is probed
     * once per principal per process. When it exists, its fields are
     * copied into the current key and the legacy key is deleted.
     *
     * The two keys live on different Cluster slots, so the copy cannot
     * be one atomic script; it runs client-side over `HSCAN` with NX
     * writes, so a fresher value already written under the current key
     * is never clobbered by stale history. The legacy key is deleted
     * only after the copy answered. A failure at any step skips the
     * migration for this read (the miss already answered) and the next
     * miss retries it.
     */
    private function migrateLegacyKey(string $principalId): void
    {
        if (!$this->migrateLegacy) {
            return;
        }
        if (isset($this->legacyChecked[$principalId])) {
            return;
        }
        $this->legacyChecked[$principalId] = true;
        try {
            $legacyKey = $this->legacyTagKey($principalId);
            if ((int) $this->client->exists($legacyKey) !== 1) {
                return;
            }
            $newKey = $this->tagKey($principalId);
            $cursor = '0';
            $copied = 0;
            do {
                $reply = $this->client->hscan($legacyKey, $cursor, ['COUNT' => 500]);
                $cursor = (string) ($reply[0] ?? '0');
                // Predis parses the `HSCAN` reply into field => value pairs.
                foreach ($reply[1] ?? [] as $field => $value) {
                    $field = (string) $field;
                    // NX: a field the current key already carries is the
                    // newer write (the record path upserts under the
                    // current key), so stale history never overwrites it.
                    if ((int) $this->client->hsetnx($newKey, $field, (string) $value) === 1) {
                        $copied++;
                    }
                }
            } while ($cursor !== '0');
            if ($copied > 0) {
                // The copied history must not outlive the store's own
                // longest class ceiling (the next record recomputes the
                // precise per-class expiry).
                $this->client->pexpire($newKey, self::DEFAULT_NET_TTL_MS);
            }
            $this->client->del($legacyKey);
        } catch (\Throwable) {
            // Best effort: the migration rides a read that already
            // answered; a failed probe or copy is retried by the next
            // miss and never surfaces as a read error.
        }
    }

    /**
     * @return array{0: string, 1: int, 2: int} class name, TTL ms, cap
     */
    private function classOf(string $tag): array
    {
        if (str_starts_with($tag, 'session:')) {
            return ['session', $this->sessionTtlMs, $this->sessionCap];
        }
        if (str_starts_with($tag, 'device:')) {
            return ['device', $this->deviceTtlMs, $this->deviceCap];
        }

        return ['net', self::DEFAULT_NET_TTL_MS, $this->netCap];
    }

    private function runScript(array $keys, array $args)
    {
        $script = self::loadScript();
        $sha = $this->scriptSha !== '' ? $this->scriptSha : $this->loadSha($script);
        $callArgs = [];
        foreach ($args as $a) {
            $callArgs[] = (string) $a;
        }
        try {
            return $this->client->evalsha($sha, \count($keys), ...$keys, ...$callArgs);
        } catch (\Predis\Response\ServerException $e) {
            // Only the NOSCRIPT miss reloads and retries once. Every
            // other failure propagates: a retry on a non-NOSCRIPT
            // error re-executes a command the server may already have
            // applied (the script's writes are not idempotent in
            // aggregate — the LRU evictions and the last-use touches).
            if (!str_contains($e->getMessage(), 'NOSCRIPT')) {
                throw $e;
            }
            $this->scriptSha = $this->loadSha($script);

            return $this->client->evalsha($this->scriptSha, \count($keys), ...$keys, ...$callArgs);
        }
    }

    private function loadSha(string $script): string
    {
        $sha = $this->client->script('LOAD', $script);
        if (!\is_string($sha) || $sha === '') {
            throw new RiskStoreException('SCRIPT LOAD returned no sha');
        }
        $this->scriptSha = $sha;

        return $sha;
    }

    private static function loadScript(): string
    {
        $path = dirname(__DIR__, 2) . '/resources/principal_networks.lua';
        if (!is_file($path)) {
            throw new \RuntimeException(
                sprintf('Cannot locate the bundled script at resources/principal_networks.lua (resolved from %s)', __DIR__),
            );
        }
        $script = @file_get_contents($path);
        if ($script === false) {
            throw new \RuntimeException(sprintf('Cannot read the bundled script at %s', $path));
        }

        return $script;
    }

    private static function assertPrincipal(string $principalId): void
    {
        if (!preg_match('/^[0-9a-f]{1,64}$/', $principalId)) {
            throw new \InvalidArgumentException('principalId must be a lowercase hex pseudonym of at most 64 chars');
        }
    }

    private static function assertTag(string $tag): void
    {
        if (preg_match('/^(net|session|device):[0-9a-f]{1,64}$/', $tag)) {
            return;
        }
        // The ASN shapes: a canonical listed decimal, or the unlisted
        // namespace buckets (u4/<decimal /16 prefix>, u6/<8 hex of the
        // /32 prefix>). Without them an unlisted-ASN record is refused
        // and the novelty gate fails open for exactly those networks.
        if (preg_match('/^asn:(?:0|[1-9][0-9]{0,9}|u4\/(?:0|[1-9][0-9]{0,4})|u6\/[0-9a-f]{8})$/D', $tag)) {
            return;
        }
        // Bare hex: the engine's networkBucket() spelling (no prefix).
        if (preg_match('/^[0-9a-f]{2,68}$/', $tag)) {
            return;
        }
        throw new \InvalidArgumentException('tag must match net|session|device:<hex>, asn:<decimal|u4/prefix|u6/prefix>, or bare hex');
    }
}
