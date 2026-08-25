<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The centralized verified-WAIT topology guard, shared by EVERY
 * durability-critical Redis component (the core RedisStorage, the
 * SiteVerify idempotency store, the siteverify metadata store, the
 * outstanding accounting, the chained-challenge state store and the
 * post-solve disposition store).
 *
 * Verified WAIT is CONNECTION-AFFINE: Redis defines WAIT relative to the
 * writes sent by the current client connection, so the durability proof
 * is only valid when the mutation and the WAIT execute on the SAME
 * connection. The guard refuses configurations that can break the
 * affinity:
 *
 *  - Predis replication aggregates (Sentinel / master-slave) and Redis
 *    Cluster clients: WAIT is connection-relative and cannot be routed;
 *  - retry-enabled standalone Predis clients: the vendored retry wrapper
 *    can re-execute the WAIT on a replacement connection whose write
 *    offset is empty;
 *  - retry-enabled phpredis (\\Redis) clients: phpredis automatically
 *    reconnects on connection failures (OPT_MAX_RETRIES defaults to 10),
 *    so a mutation acknowledged on connection A followed by a socket
 *    failure before the WAIT would issue the WAIT on a RECONNECTED
 *    connection B, whose acknowledgment says nothing about A's write
 *    offset — exactly the stale-replica-promotion failure WAIT is meant
 *    to prevent.
 *
 * Supported verified-WAIT topology is standalone Redis only, with
 * client-side reconnect retries disabled.
 */
final class VerifiedWaitGuard
{
    public static function refuseUnsupported(mixed $client, int $waitReplicas, string $component): void
    {
        if ($waitReplicas <= 0) {
            return;
        }
        if ($client instanceof \Predis\Client) {
            self::refuseUnsupportedPredis($client, $component);

            return;
        }
        if ($client instanceof \Redis) {
            self::refuseRetryEnabledPhpRedis($client, $component);
        }
    }

    private static function refuseUnsupportedPredis(\Predis\Client $client, string $component): void
    {
        $connection = $client->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
            throw new \InvalidArgumentException(
                $component.': verified-WAIT durability (waitReplicas > 0) is not supported on a Predis replication aggregate (Sentinel or master-slave) — WAIT is connection-affine, counting replicas of the connection it is sent on, and the aggregate\'s failure retry executes the WAIT on a replacement connection whose write offset is empty. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on an aggregate.'
            );
        }
        if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
            throw new \InvalidArgumentException(
                $component.': verified-WAIT durability (waitReplicas > 0) is not supported on a Predis Redis Cluster client — WAIT is connection-relative and cannot be routed by slot. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on a cluster.'
            );
        }
        if ($connection === null) {
            // An in-memory stand-in with no real connection object (the
            // tests' fake clients skip the parent constructor): there is
            // no Parameters instance to carry a retry policy and the
            // stand-in overrides the command dispatch itself, so the
            // vendored retry wrapper never engages.
            return;
        }
        if ($connection instanceof \Predis\Connection\RelayConnection) {
            return;
        }
        if (!$connection->getParameters()->isDisabledRetry()) {
            throw new \InvalidArgumentException(
                $component.': verified-WAIT durability (waitReplicas > 0) is not supported on a retry-enabled standalone Predis client — verified-WAIT durability requires that a durability-critical mutation is attempted exactly once on the connection whose subsequent WAIT establishes the replication offset. Retries must be disabled on the connection (remove the \'retry\' connection parameter), or keep waitReplicas = 0.'
            );
        }
    }

    private static function refuseRetryEnabledPhpRedis(\Redis $client, string $component): void
    {
        // phpredis's OPT_MAX_RETRIES controls automatic reconnects on
        // connection failures (default 10): a mutation acknowledged on
        // connection A followed by a socket failure before the WAIT would
        // silently reconnect and issue the WAIT on connection B, whose
        // acknowledgment proves nothing about A's write offset.
        if ((int) $client->getOption(\Redis::OPT_MAX_RETRIES) !== 0) {
            throw new \InvalidArgumentException(
                $component.': verified-WAIT durability (waitReplicas > 0) is not supported on a retry-enabled phpredis (\\Redis) client — phpredis reconnects automatically on connection failures, so the WAIT could execute on a different connection than the one that performed the mutation. Reconnect retries must be disabled (\\Redis::OPT_MAX_RETRIES = 0) before the client is used with waitReplicas > 0, or keep waitReplicas = 0.'
            );
        }
    }
}
