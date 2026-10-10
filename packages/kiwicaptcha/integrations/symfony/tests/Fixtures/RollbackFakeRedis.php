<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * The shared outstanding-challenge fake Redis of the rollback and
 * recovery suites: an in-memory predis stand-in whose counters, sorted
 * sets and strings answer the outstanding-challenge scripts, with the
 * connection the durability barrier pins behaving as permanently
 * healthy.
 */
final class RollbackFakeRedis extends \Predis\Client
{
    /** @var array<string, int> plain incr counters */
    public array $counters = [];

    /** @var array<string, array<string, float>> live-outstanding membership: key => nonce => score */
    public array $zsets = [];

    /** @var array<string, string> plain strings (the nonce sidecars) */
    public array $strings = [];

    public function __construct()
    {
        // Deliberately skip the parent constructor: no connection setup.
    }

    private function timeMs(): float
    {
        return (float) (time() * 1000);
    }

    public function __call($commandID, $arguments)
    {
        if (strtoupper((string) $commandID) === 'GET') {
            return $this->strings[(string) $arguments[0]] ?? null;
        }
        if (strtoupper((string) $commandID) !== 'EVAL') {
            throw new \LogicException('unexpected command '.$commandID);
        }
        $script = (string) $arguments[0];
        $numKeys = (int) $arguments[1];
        $keys = \array_slice($arguments, 2, $numKeys);
        $rest = \array_slice($arguments, 2 + $numKeys);

        if (str_contains($script, 'Outstanding challenge issuance')) {
            // OutstandingChallenges::issue: keys[1] the per-source
            // membership ZSET (member = <source>:<nonce>, score = absolute
            // expiry), keys[2] the global LIVE-outstanding ZSET, keys[3]
            // the nonce sidecar; argv[1] source cap, argv[2] global cap,
            // argv[3] TTL seconds, argv[4] absolute expiry (the score),
            // argv[5] the minted nonce, argv[6] the source pseudonym.
            $sourceZset = (string) $keys[0];
            $global = (string) $keys[1];
            $sidecar = (string) $keys[2];
            $pseudonym = (string) $rest[5];
            $liveUntil = (int) floor($this->timeMs() / 1000) + (int) $rest[3];
            if ($this->sourceCount($sourceZset) >= (int) $rest[0]) {
                return 0;
            }
            if (\count($this->zsets[$global] ?? []) >= (int) $rest[1]) {
                return -1;
            }
            $this->zsets[$sourceZset][(string) $rest[4]] = (float) $liveUntil;
            $this->zsets[$global][(string) $rest[4]] = (float) $liveUntil;
            $this->strings[$sidecar] = $pseudonym;
            $this->mirrorSourceCount($sourceZset);

            return 1;
        }

        if (str_contains($script, 'Outstanding challenge release')) {
            // OutstandingChallenges::solved / ::abortedBeforeHandoff:
            // keys[1] the global live ZSET, keys[2] the nonce sidecar,
            // keys[3] the original source's membership ZSET; argv[1] the
            // released nonce, argv[2] the caller-resolved source. One-shot,
            // nonce-authoritative.
            $global = (string) $keys[0];
            $sidecar = (string) $keys[1];
            $sourceZset = (string) $keys[2];
            $nonce = (string) $rest[0];
            $expectedSource = (string) $rest[1];
            $removed = 0;
            if (isset($this->zsets[$global][$nonce])) {
                unset($this->zsets[$global][$nonce]);
                $removed = 1;
                if (isset($this->strings[$sidecar]) && (string) $this->strings[$sidecar] === $expectedSource) {
                    unset($this->zsets[$sourceZset][$nonce]);
                    unset($this->strings[$sidecar]);
                    $this->mirrorSourceCount($sourceZset);
                }
            }

            return $removed;
        }

        throw new \LogicException('unexpected script');
    }

    private function sourceCount(string $sourceZset): int
    {
        return \count($this->zsets[$sourceZset] ?? []);
    }

    private function mirrorSourceCount(string $sourceZset): void
    {
        $this->counters[$sourceZset] = $this->sourceCount($sourceZset);
    }
}
