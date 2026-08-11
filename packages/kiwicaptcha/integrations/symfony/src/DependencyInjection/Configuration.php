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
                ->enumNode('privacy_mode')
                    ->info("Privacy posture. 'strict' (default) FORCES: telemetry 'off', same_origin_only true, and min_duration_ms 0 (the server-side solve-timing floor is a timing heuristic and is disabled). 'standard' leaves those options under operator control. In strict mode the operator may still opt back INTO IP binding via binding_mode (binding is a relay-mitigation, not a privacy leak — the stored tag is nonce-bound, never a stable IP-derived identifier).")
                    ->values(['strict', 'standard'])
                    ->defaultValue('strict')
                ->end()
                ->enumNode('telemetry')
                    ->info("Widget behavioral telemetry collection: 'off' (default) sends no signal fields, 'minimal' and 'full' opt the widget into reporting bot-heuristic fields (client-controlled and forgeable — a supplement, never the security boundary). Forced to 'off' when privacy_mode is 'strict'.")
                    ->values(['off', 'minimal', 'full'])
                    ->defaultValue('off')
                ->end()
                ->enumNode('binding_mode')
                    ->info("Challenge binding: 'nonce_ip_hmac' (default) binds each challenge to the client IP via a nonce-bound HMAC tag (relay mitigation; the stored tag is unique per challenge, never a stable IP identifier). 'none' disables binding entirely — the core Issuer emits an EMPTY binding tag and verification skips the check (maximum privacy; relay protection off).")
                    ->values(['none', 'nonce_ip_hmac'])
                    ->defaultValue('nonce_ip_hmac')
                ->end()
                ->booleanNode('same_origin_only')
                    ->info('Reject challenge requests whose Origin header is not the application origin with HTTP 403 CROSS_ORIGIN_DENIED (cross-site abuse/CSRF hardening). Requests without an Origin header (curl, same-origin navigation) are allowed. Forced true when privacy_mode is strict.')
                    ->defaultValue(true)
                ->end()
                ->integerNode('rate_limit')
                    ->info('Max challenge issuances per client IP per rate_limit_window_secs (0 = disabled; default 10). Production deployments should keep this on — it bounds the aggregate verification work an attacker can trigger.')
                    ->defaultValue(10)
                    ->min(0)
                ->end()
                ->integerNode('rate_limit_global')
                    ->info('DEPLOYMENT-WIDE cap on challenge issuances per rate_limit_window_secs (0 = disabled; default 500). Enforced ATOMICALLY against Redis (Redis-backed rate limiter) so all PHP-FPM workers share one sliding window; without a Redis client the global cap is not enforced (in-memory/PSR-6 fallbacks are per-process/best-effort — see README). Exhaustion returns HTTP 429 with a distinct GLOBAL_RATE_LIMITED code.')
                    ->defaultValue(500)
                    ->min(0)
                ->end()
                ->integerNode('rate_limit_rotation_secs')
                    ->info('HMAC rate-limit identity rotation period in seconds (default 3600; 0 disables rotation). The rate-limit key is HMAC(pepper, "kiwi-rate-v2|epoch|ip"): the same IP yields a DIFFERENT keyed pseudonym in every epoch, so Redis snapshots cannot correlate one source across time periods. The previous-epoch key is still checked so the sliding window stays exact across a rotation boundary. Linkability within one epoch is unavoidable for rate limiting.')
                    ->defaultValue(3600)
                    ->min(0)
                    ->max(86400)
                ->end()
                ->integerNode('rate_limit_window_secs')
                    ->info('Sliding-window size (seconds) for the issuance rate limits (per-client and global).')
                    ->defaultValue(60)
                    ->min(1)
                ->end()
                ->integerNode('argon2_lease_ms')
                    ->info('Tokenized Redis lease lifetime in ms (default 45000). Must exceed the maximum verification request runtime (e.g. PHP request_terminate_timeout) by a safety margin — otherwise a lease can expire while its Argon2 hash is still running and another worker may enter.')
                    ->defaultValue(45000)
                    ->min(1000)
                    ->max(300000)
                ->end()
                ->scalarNode('argon2_semaphore_namespace')
                    ->info("Per-deployment discriminator for the Redis-backed Argon2 admission leases and the Redis global rate-limit key (defaults to kernel.project_dir). Two deployments sharing one Redis instance must use different namespaces so their lease sets and global windows do not compete. Sanitized to [A-Za-z0-9_.-] before being embedded in a key.")
                    ->defaultValue('%kernel.project_dir%')
                ->end()
                ->booleanNode('enforce_telemetry')
                    ->info('When true, the validator rejects tokens whose client-reported telemetry scores as bot-like (defense-in-depth; only meaningful when the widget collects telemetry). Telemetry is client-controlled, so this is never the security boundary.')
                    ->defaultValue(false)
                ->end()
                ->integerNode('min_duration_ms')
                    ->info('Minimum solve duration in ms, enforced by SERVER-side timing (null/0 = disabled; the default derives the floor from the difficulty). In strict privacy mode this is forced to 0 — the timing heuristic is off.')
                    ->defaultNull()
                    ->min(0)
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
                    // constraints (see the difficulty_bits comment). The
                    // protocol CEILING (MAX_ARGON_T = 6) is shared from the
                    // core: t above it is declared malformed by the verifier,
                    // so the tree refuses it at configuration time.
                    ->defaultValue(3)
                    ->min(1)
                    ->max(Config::MAX_ARGON_T)
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
                    ->max(Config::MAX_TTL_SECS)
                ->end()
                ->scalarNode('storage')
                    ->info('Service id implementing KiwiCaptcha\StorageInterface. Defaults to the in-memory ArrayStorage, which is only allowed in test/dev environments — in prod a shared storage (e.g. KiwiCaptcha\Storage\RedisStorage or Psr6Storage backed by a Redis PSR-6 pool) is required or the container fails to compile.')
                    ->defaultValue('kiwi_captcha.storage.array')
                ->end()
                ->scalarNode('redis_service')
                    ->info('Optional service id of a Redis client (\Redis or Predis\Client) used for the Redis-backed Argon2id admission semaphore AND the atomic global rate limiter. When set (and algorithm=argon2id with a positive argon2_max_concurrent_verifications), the concurrency cap is enforced ACROSS PHP-FPM workers, not just per process. When null, the extension falls back to the storage service itself if it is KiwiCaptcha\Storage\RedisStorage (its client is reused), and otherwise to the in-process semaphore (per-process only — see README).')
                    ->defaultNull()
                ->end()
                ->scalarNode('route_prefix')
                    ->info('Prefix for the challenge endpoint route.')
                    ->defaultValue('/kiwi-captcha')
                ->end()
                ->scalarNode('rate_limit_cache')
                    ->info('Optional service id of a PSR-6 pool (Psr\\Cache\\CacheItemPoolInterface) used as SHARED, multi-process rate-limit state, e.g. a Redis-backed Symfony Cache pool. Only used when no Redis client is available for the atomic limiter. When omitted, a per-process in-memory sliding window is used (single-worker only — PHP-FPM workers share no memory).')
                    ->defaultNull()
                ->end()
                ->scalarNode('rate_limit_pepper')
                    ->info('Secret used to HMAC client IPs before they are used as rate-limit keys, so raw IPs are never stored. Defaults to secret_key when not set.')
                    ->defaultNull()
                ->end()
                ->integerNode('argon2_max_concurrent_verifications')
                    ->info('Max concurrent Argon2id verifications (0 = unlimited). Each verification allocates argon_m_kib of memory, so size this to the available memory. Only applies when algorithm is argon2id. With a Redis client available (redis_service, or RedisStorage as the storage backend) the cap is enforced across all PHP-FPM workers via tokenized leases; otherwise it is best-effort per process (see README for the multi-worker caveat).')
                    ->defaultValue(2)
                    ->min(0)
                ->end()
            ->end();

        return $treeBuilder;
    }
}
