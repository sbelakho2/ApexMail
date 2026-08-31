<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

/**
 * Command-level failover hook client for the promotion-state-loss
 * suites. It delegates every command to an inner Predis client, the
 * in-memory FakePredisClient stand-in or a real connection. Two
 * deterministic hooks fire exactly where a promotion window sits:
 * between the runtime-state snapshot read and the consume, and after
 * a Lua transition executed on the server but before its reply
 * reached the caller.
 *
 * deleteKeyAfterRuntimeRead: the key vanishes right after the first GET
 * returns, the same observable state a promoted stale replica presents
 * when the primary lost the write. The verify flow consumes a missing
 * record and must answer RecordNotFound, with no residue.
 *
 * throwAfterEvalFrom: the Nth Lua invocation (EVAL or `EVALSHA`)
 * executes on the server and then throws, simulating a reply lost on
 * the wire after the mutation landed. The verifier treats the
 * transition as indeterminate, never as absent.
 */
final class FailoverHookingClient extends \Predis\Client
{
    public \Predis\Client $delegate;

    public bool $deleteKeyAfterRuntimeRead = false;

    /**
     * The 1-based Lua invocation threshold: the invocation whose number
     * reaches this value runs and then throws. PHP_INT_MAX disarms the
     * hook.
     */
    public int $throwAfterEvalFrom = \PHP_INT_MAX;

    /** Lua invocations (EVAL or `EVALSHA`) executed so far. */
    private int $luaInvocations = 0;

    public function __construct(\Predis\Client $delegate)
    {
        $this->delegate = $delegate;
    }

    public function __call($commandID, $arguments)
    {
        $id = strtoupper((string) $commandID);

        if ($id === 'GET' && $this->deleteKeyAfterRuntimeRead) {
            $this->deleteKeyAfterRuntimeRead = false;
            $result = $this->delegate->__call('GET', $arguments);
            $this->delegate->__call('DEL', [$arguments[0]]);

            return $result;
        }

        if ($id === 'EVAL' || $id === 'EVALSHA') {
            $this->luaInvocations++;
            $result = $this->delegate->__call($commandID, $arguments);
            if ($this->luaInvocations >= $this->throwAfterEvalFrom) {
                throw new \RuntimeException('simulated lost reply after the Lua transition');
            }

            return $result;
        }

        return $this->delegate->__call($commandID, $arguments);
    }

    public function executeRaw(array $arguments, &$error = null): mixed
    {
        return $this->delegate->executeRaw($arguments, $error);
    }

    public function getConnection()
    {
        return $this->delegate->getConnection();
    }

    /** Lua invocations (EVAL or `EVALSHA`) that reached the server. */
    public function luaInvocationCount(): int
    {
        return $this->luaInvocations;
    }
}
