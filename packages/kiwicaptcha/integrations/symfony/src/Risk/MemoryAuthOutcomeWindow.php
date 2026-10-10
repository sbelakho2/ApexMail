<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The bounded in-memory fallback of the auth-outcome window: the same
 * contract as the Redis window, scoped to one process, with explicit
 * caps so an attacker cannot grow the map without bound. Deployments
 * sharing auth traffic across workers wire the Redis window instead
 * (the extension chooses it whenever a security Redis client exists).
 */
final class MemoryAuthOutcomeWindow implements AuthOutcomeWindowInterface
{
    /** The per-identity entry cap: the oldest identity is evicted. */
    private const MAX_IDENTITIES = 4096;

    /** @var array<string, array{f: int, s: int, at: int}> */
    private array $counts = [];

    public function __construct(
        private readonly int $windowSecs = 3600,
        private readonly ?\Closure $now = null,
    ) {
    }

    public function recordFailure(string $sessionPseudonym): void
    {
        $this->record($sessionPseudonym, 'f');
    }

    public function recordSuccess(string $sessionPseudonym): void
    {
        $this->record($sessionPseudonym, 's');
    }

    public function failureRatio(string $sessionPseudonym): ?float
    {
        $entry = $this->counts[$sessionPseudonym] ?? null;
        if ($entry === null || $this->now() - $entry['at'] > $this->windowSecs) {
            // No readable history is not a clean history: the gate
            // refuses credit (a brand-new session earns nothing from a
            // single success).
            return null;
        }
        $total = $entry['f'] + $entry['s'];

        return $total === 0 ? null : $entry['f'] / $total;
    }

    private function record(string $sessionPseudonym, string $field): void
    {
        $now = $this->now();
        $entry = $this->counts[$sessionPseudonym] ?? null;
        if ($entry === null || $now - $entry['at'] > $this->windowSecs) {
            if (\count($this->counts) >= self::MAX_IDENTITIES) {
                $oldest = null;
                $oldestAt = \PHP_INT_MAX;
                foreach ($this->counts as $key => $candidate) {
                    if ($candidate['at'] < $oldestAt) {
                        $oldestAt = $candidate['at'];
                        $oldest = $key;
                    }
                }
                if ($oldest !== null) {
                    unset($this->counts[$oldest]);
                }
            }
            $entry = ['f' => 0, 's' => 0, 'at' => $now];
        }
        ++$entry[$field];
        $this->counts[$sessionPseudonym] = $entry;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
