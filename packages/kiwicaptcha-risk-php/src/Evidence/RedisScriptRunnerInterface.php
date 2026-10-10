<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

/**
 * The single seam a deployment adapts to its Redis client (phpredis,
 * Predis, a sidecar): run one Lua script with keys and arguments. The
 * decoy-escalation store never touches the risk state store internals;
 * this contract keeps the scripting surface injectable.
 */
interface RedisScriptRunnerInterface
{
    /**
     * Runs one script and returns its integer reply.
     *
     * @param list<string> $keys
     * @param list<string> $args
     *
     * @return int|string|null the raw reply (error replies throw)
     */
    public function evalScript(string $script, array $keys, array $args): int|string|null;
}
