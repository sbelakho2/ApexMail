<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The Redis-backed auth-outcome window: per-identity hash counters
 * (the hash-increment command on fields f and s) under the risk
 * store's hash-tagged key family with a window-bounded TTL, so every
 * worker of a deployment shares one view. The read path returns null
 * when the backend is unreachable — the gate then refuses credit, fail
 * closed.
 */
final class RedisAuthOutcomeWindow implements AuthOutcomeWindowInterface
{
    /** Increment one field and arm the window TTL; mint the key on first touch. */
    private const RECORD_SCRIPT = <<<'LUA'
local n = redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return n
LUA;

    /** Read both counters; nil when the window key does not exist. */
    private const READ_SCRIPT = <<<'LUA'
local f = redis.call('HGET', KEYS[1], 'f')
local s = redis.call('HGET', KEYS[1], 's')
if not f and not s then return false end
return { tonumber(f) or 0, tonumber(s) or 0 }
LUA;

    private ?\BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor $luaSeam = null;

    public function __construct(
        private readonly \Redis|\Predis\Client $redis,
        private readonly string $prefix,
        private readonly int $windowSecs = 3600,
    ) {
    }

    private function executor(): \BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor
    {
        return $this->luaSeam ??= new \BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor($this->redis);
    }

    public function recordFailure(string $sessionPseudonym): void
    {
        $this->executor()->executeMutation(self::RECORD_SCRIPT, $this->key($sessionPseudonym), ['f', (string) ($this->windowSecs * 1000)]);
    }

    public function recordSuccess(string $sessionPseudonym): void
    {
        $this->executor()->executeMutation(self::RECORD_SCRIPT, $this->key($sessionPseudonym), ['s', (string) ($this->windowSecs * 1000)]);
    }

    public function failureRatio(string $sessionPseudonym): ?float
    {
        try {
            $answer = $this->executor()->executeRead(self::READ_SCRIPT, $this->key($sessionPseudonym), []);
        } catch (\Throwable) {
            return null;
        }
        if (!\is_array($answer) || \count($answer) !== 2 || $answer === [false]) {
            // Absent window: no readable history is not a clean
            // history. The gate refuses credit so a brand-new session
            // never earns trust from a single success.
            return null;
        }
        $failures = (int) $answer[0];
        $successes = (int) $answer[1];
        $total = $failures + $successes;

        return $total === 0 ? null : $failures / $total;
    }

    private function key(string $sessionPseudonym): string
    {
        // The pseudonym is already a keyed digest; a bounded prefix
        // keeps the key family inside the deployment namespace.
        return $this->prefix.'authwin:'.substr($sessionPseudonym, 0, 64);
    }
}
