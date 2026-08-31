<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The single authority-safety classifier of the kiwicaptcha core
 * (docs/ha-authority.md): judges the actual constructed Redis client
 * instance and returns the canonical {@see AuthoritySafety} verdict.
 *
 * The classifier is the one seam every authority decision shares:
 *
 *  - {@see VerifiedWaitGuard::refuseUnsupported()} refuses the
 *    verified-WAIT barrier on an Unsafe client (the connection
 *    affinity of WAIT is exactly what retries and aggregates break).
 *  - the Symfony bundle's runtime authority classifier and the
 *    pinned-primary authority guard refuse an Unsafe or Unknown client
 *    under the fail_closed and pinned_primary postures.
 *
 * A Predis replication or cluster aggregate is Unsafe: commands route
 * through promotion machinery, so the serving node can change under
 * the client. A single-node direct connection is Safe only when
 * client-side reconnect retries are disabled — with retries enabled
 * the vendored retry wrapper can re-execute a durability-critical
 * mutation on a fresh connection whose write offset is empty. A
 * phpredis (\Redis) client is Safe only when OPT_MAX_RETRIES is 0
 * (phpredis reconnects automatically otherwise). Every uninspectable
 * shape is Unknown.
 */
final class AuthoritySafetyClassifier
{
    public static function classify(mixed $client): AuthoritySafety
    {
        if ($client instanceof \Predis\Client) {
            return self::classifyPredis($client);
        }
        if ($client instanceof \Redis) {
            $retries = self::phpRedisRetriesEnabled($client);
            if ($retries === null) {
                return AuthoritySafety::Unknown;
            }

            return $retries ? AuthoritySafety::Unsafe : AuthoritySafety::Safe;
        }

        return AuthoritySafety::Unknown;
    }

    private static function classifyPredis(\Predis\Client $client): AuthoritySafety
    {
        try {
            $connection = $client->getConnection();
        } catch (\Throwable) {
            return AuthoritySafety::Unknown;
        }
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface
            || $connection instanceof \Predis\Connection\Cluster\ClusterInterface
        ) {
            return AuthoritySafety::Unsafe;
        }
        if ($connection === null) {
            // An in-memory stand-in without a real connection object.
            return AuthoritySafety::Unknown;
        }
        if (!$connection instanceof \Predis\Connection\NodeConnectionInterface) {
            return AuthoritySafety::Unknown;
        }
        try {
            $retriesDisabled = $connection->getParameters()->isDisabledRetry();
        } catch (\Throwable) {
            return AuthoritySafety::Unknown;
        }

        return $retriesDisabled ? AuthoritySafety::Safe : AuthoritySafety::Unsafe;
    }

    /**
     * Whether a phpredis client has automatic reconnect retries armed
     * (OPT_MAX_RETRIES != 0), or null when the option cannot be read
     * (an uninspectable \Redis instance is Unknown).
     */
    private static function phpRedisRetriesEnabled(\Redis $client): ?bool
    {
        try {
            return (int) $client->getOption(\Redis::OPT_MAX_RETRIES) !== 0;
        } catch (\Throwable) {
            return null;
        }
    }
}
