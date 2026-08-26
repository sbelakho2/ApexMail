<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The single place that knows the Redis-client-specific `eval()` calling
 * convention — phpredis and Predis pack the arguments differently:
 *
 * - phpredis (\Redis): `eval(script, [key, ...args], numKeys)` — keys and
 *   script arguments share one array; numKeys is the third parameter.
 * - Predis: `eval(script, numKeys, key, ...args)`.
 *
 * Mirrors the convention in the core RedisStorage
 * (`vendor/kiwicaptcha/kiwicaptcha-php/src/Storage/RedisStorage.php`).
 */
final class RedisEval
{
    /**
     * @param string|list<string> $key  a single declared key, or the
     *                                  declared KEYS list (all keys must
     *                                  share one hash tag)
     * @param list<mixed> $args the script ARGV values (after the keys)
     */
    public static function eval(\Predis\Client|\Redis $client, string $script, string|array $key, array $args): mixed
    {
        $keys = \is_array($key) ? \array_values($key) : [$key];

        if ($client instanceof \Redis) {
            return $client->eval($script, [...$keys, ...$args], \count($keys));
        }

        return $client->eval($script, \count($keys), ...$keys, ...$args);
    }
}
