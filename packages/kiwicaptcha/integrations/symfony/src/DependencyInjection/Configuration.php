<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use KiwiCaptcha\Config;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('kiwi_captcha');
        $root = $treeBuilder->getRootNode();

        $root
            ->children()
                ->scalarNode('secret_key')
                    ->info('HMAC secret key for signing/verifying challenges (min 16 bytes).')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->enumNode('algorithm')
                    ->values(['sha256', 'argon2id'])
                    ->defaultValue('sha256')
                ->end()
                ->integerNode('argon_m_kib')
                    ->info('Argon2id memory cost in KiB (only for argon2id; must be >= 8 * argon_p).')
                    ->defaultValue(0)
                    ->min(0)
                    // Same browser-solvable ceiling as the core
                    // (KiwiCaptcha\Config validates m_kib <= 65536).
                    ->max(65536)
                ->end()
                ->integerNode('argon_t')
                    // Unconditional floor only; the conditional Argon2id
                    // profile rules (t >= 3, p == 1, m_kib >= 8 * p) are
                    // enforced by KiwiCaptcha\Config when the extension builds
                    // it, so this tree must not duplicate those protocol
                    // constraints (see the difficulty_bits comment).
                    ->defaultValue(3)
                    ->min(1)
                ->end()
                ->integerNode('argon_p')
                    ->defaultValue(1)
                    ->min(1)
                ->end()
                ->integerNode('difficulty_bits')
                    ->info('Leading zero bits for SHA-256 challenges (default 20).')
                    ->defaultValue(20)
                    ->min(1)
                    // Do NOT re-derive the protocol ceiling here: the single
                    // source of truth is KiwiCaptcha\Config::MAX_SHA_TARGET_BITS
                    // (20 — the wasm solver cannot go higher), so the tree can
                    // never drift from the core's constraint.
                    ->max(Config::MAX_SHA_TARGET_BITS)
                ->end()
                ->integerNode('argon2_difficulty_bits')
                    ->info('Leading zero bits for Argon2id challenges (default 8, max 10).')
                    ->defaultValue(8)
                    ->min(1)
                    // Same ceiling as the core's MAX_ARGON2_TARGET_BITS (10).
                    ->max(10)
                ->end()
                ->integerNode('challenge_ttl_secs')
                    ->defaultValue(120)
                    ->min(10)
                ->end()
                ->scalarNode('storage')
                    ->info('Service id implementing KiwiCaptcha\StorageInterface. Defaults to the in-memory ArrayStorage, which is only allowed in test/dev environments — in prod a shared storage (e.g. KiwiCaptcha\Storage\RedisStorage or Psr6Storage backed by a Redis PSR-6 pool) is required or the container fails to compile.')
                    ->defaultValue('kiwi_captcha.storage.array')
                ->end()
                ->scalarNode('redis_service')
                    ->info('Optional service id of a Redis client (\Redis or Predis\Client) used for the Redis-backed Argon2id admission semaphore. When set (and algorithm=argon2id with a positive argon2_max_concurrent_verifications), the concurrency cap is enforced ACROSS PHP-FPM workers, not just per process. When null, the extension falls back to the storage service itself if it is KiwiCaptcha\Storage\RedisStorage (its client is reused), and otherwise to the in-process semaphore (per-process only — see README).')
                    ->defaultNull()
                ->end()
                ->scalarNode('route_prefix')
                    ->info('Prefix for the challenge endpoint route.')
                    ->defaultValue('/kiwi-captcha')
                ->end()
                ->integerNode('rate_limit')
                    ->info('Max challenge issuances per client IP per rate_limit_window_secs (0 = disabled). Production deployments should enable this (e.g. 10 per 60 s) so mass challenge minting is not free — it bounds the aggregate verification work an attacker can trigger.')
                    ->defaultValue(0)
                    ->min(0)
                ->end()
                ->integerNode('rate_limit_window_secs')
                    ->info('Sliding-window size (seconds) for the issuance rate limit.')
                    ->defaultValue(60)
                    ->min(1)
                ->end()
                ->scalarNode('rate_limit_cache')
                    ->info('Optional service id of a PSR-6 pool (Psr\\Cache\\CacheItemPoolInterface) used as SHARED, multi-process rate-limit state, e.g. a Redis-backed Symfony Cache pool. When omitted, a per-process in-memory sliding window is used (single-worker only — PHP-FPM workers share no memory).')
                    ->defaultNull()
                ->end()
                ->scalarNode('rate_limit_pepper')
                    ->info('Secret used to HMAC client IPs before they are used as rate-limit keys, so raw IPs are never stored. Defaults to secret_key when not set.')
                    ->defaultNull()
                ->end()
                ->integerNode('argon2_max_concurrent_verifications')
                    ->info('Max concurrent Argon2id verifications (0 = unlimited). Each verification allocates argon_m_kib of memory, so size this to the available memory. Only applies when algorithm is argon2id. With a Redis client available (redis_service, or RedisStorage as the storage backend) the cap is enforced across all PHP-FPM workers; otherwise it is best-effort per process (see README for the multi-worker caveat).')
                    ->defaultValue(2)
                    ->min(0)
                ->end()
            ->end();

        return $treeBuilder;
    }
}
