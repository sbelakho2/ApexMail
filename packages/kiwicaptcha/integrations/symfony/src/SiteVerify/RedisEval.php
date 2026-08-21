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
     * @param list<mixed> $args the script ARGV values (after the key)
     */
    public static function eval(\Predis\Client|\Redis $client, string $script, string $key, array $args): mixed
    {
        if ($client instanceof \Redis) {
            return $client->eval($script, [$key, ...$args], 1);
        }

        return $client->eval($script, 1, $key, ...$args);
    }
}
