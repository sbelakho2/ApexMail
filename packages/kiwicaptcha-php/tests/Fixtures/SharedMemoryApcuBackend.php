<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\Storage\ApcuBackendInterface;
use KiwiCaptcha\Storage\ApcuFetchOutcome;

/**
 * A fork-shareable, faithful in-process emulation of the APCu backend
 * seam, so the whole ApcuStorage invariant suite runs where the
 * extension is absent.
 *
 * State lives in one System V shared memory segment. Every seam
 * operation runs under one System V kernel semaphore, which is what
 * makes the emulation honest in the places the suite leans on it:
 *
 *  - `add` is a real cross-process create-if-absent. The semaphore
 *    serializes the check and the insert as one critical section, the
 *    role the APCu segment lock plays for `apcu_add()`. Forked workers
 *    racing on one lock key therefore observe exactly one winner, the
 *    same interleaving guarantee the real segment gives.
 *  - A TTL-expired entry answers exactly like a missing key on fetch,
 *    and `add` over an expired entry succeeds, mirroring APCu's
 *    read-time expiry.
 *  - `store` is an unconditional overwrite that installs the new TTL.
 *
 * Fidelity limits, stated rather than hidden. The emulation has no
 * segment-size cap or eviction (APCu refuses writes when full), its
 * lock is a kernel semaphore rather than a userspace spinlock, and it
 * serializes whole operations where APCu can serve readers in
 * parallel. None of those differences touch the contract the storage
 * depends on: atomic create-if-absent, atomic overwrite, and
 * expiry-reads-as-absent.
 *
 * The owner instance created by {@see self::create()} removes the
 * segment and semaphore on {@see self::dispose()}; instances attached
 * through {@see self::attach()} (the forked workers) never do.
 */
final class SharedMemoryApcuBackend implements ApcuBackendInterface
{
    /** The shared map's variable slot inside the segment. */
    private const VAR_KEY = 0;

    /** The fixed segment size; creation and attachment must agree. */
    private const SEGMENT_BYTES = 262_144;

    /** @var resource|null the shared memory segment handle */
    private $shm;

    /** @var resource|null the guarding semaphore handle */
    private $sem;

    private bool $owner;

    private int $ownerPid;

    private int $shmKey;

    private int $semKey;

    /**
     * @param resource $shm
     * @param resource $sem
     */
    private function __construct($shm, $sem, int $shmKey, int $semKey, bool $owner)
    {
        $this->shm = $shm;
        $this->sem = $sem;
        $this->shmKey = $shmKey;
        $this->semKey = $semKey;
        $this->owner = $owner;
        // A forked child inherits the owner object too; only the
        // creating process may ever tear the set down, or the first
        // child to exit would destroy the segment under every sibling.
        $this->ownerPid = getmypid();
    }

    /**
     * Create a fresh segment and semaphore owned by this process.
     *
     * @throws \RuntimeException when the System V shared memory or
     *                           semaphore extensions are unavailable
     */
    public static function create(): self
    {
        if (!\function_exists('shm_attach') || !\function_exists('sem_get')) {
            throw new \RuntimeException(
                'the sysvshm and sysvsem extensions are required by the emulated APCu backend fixture'
            );
        }
        $shmKey = self::randomKey();
        $semKey = self::randomKey();
        $shm = shm_attach($shmKey, self::SEGMENT_BYTES);
        $sem = sem_get($semKey, 1);
        if ($shm === false || $sem === false) {
            throw new \RuntimeException('the emulated APCu backend could not attach its segment and semaphore');
        }
        $backend = new self($shm, $sem, $shmKey, $semKey, true);
        $backend->withLock(static function () use ($backend): void {
            shm_put_var($backend->shm, self::VAR_KEY, []);
        });

        return $backend;
    }

    /**
     * Attach to an existing segment and semaphore by their keys: the
     * forked workers' construction path, sharing the parent's state
     * without owning its teardown.
     */
    public static function attach(int $shmKey, int $semKey): self
    {
        $shm = shm_attach($shmKey, self::SEGMENT_BYTES);
        $sem = sem_get($semKey, 1);
        if ($shm === false || $sem === false) {
            throw new \RuntimeException('the emulated APCu backend could not attach the shared segment');
        }

        return new self($shm, $sem, $shmKey, $semKey, false);
    }

    /** The segment and semaphore keys, for forked children to attach. */
    public function descriptor(): array
    {
        return ['shm' => $this->shmKey, 'sem' => $this->semKey];
    }

    /**
     * Remove the segment and semaphore. Only the owning instance in
     * the process that created them removes them; attached instances
     * and forked children inheriting the owner object are no-ops.
     */
    public function dispose(): void
    {
        if (!$this->owner || $this->shm === null || getmypid() !== $this->ownerPid) {
            return;
        }
        shm_remove($this->shm);
        sem_remove($this->sem);
        $this->shm = null;
        $this->sem = null;
    }

    public function __destruct()
    {
        $this->dispose();
    }

    public function fetch(string $key): ApcuFetchOutcome
    {
        return $this->withLock(function () use ($key): ApcuFetchOutcome {
            $entries = $this->entries();
            if (!\array_key_exists($key, $entries)) {
                return ApcuFetchOutcome::notFound();
            }
            if ($this->expired($entries[$key])) {
                unset($entries[$key]);
                $this->saveEntries($entries);

                return ApcuFetchOutcome::notFound();
            }

            return ApcuFetchOutcome::found($entries[$key]['value']);
        });
    }

    public function store(string $key, mixed $value, int $ttlSecs): bool
    {
        return $this->withLock(function () use ($key, $value, $ttlSecs): bool {
            $entries = $this->entries();
            $entries[$key] = ['value' => $value, 'expires' => time() + $ttlSecs];
            $this->saveEntries($entries);

            return true;
        });
    }

    public function add(string $key, mixed $value, int $ttlSecs): bool
    {
        return $this->withLock(function () use ($key, $value, $ttlSecs): bool {
            $entries = $this->entries();
            if (\array_key_exists($key, $entries) && !$this->expired($entries[$key])) {
                return false;
            }
            $entries[$key] = ['value' => $value, 'expires' => time() + $ttlSecs];
            $this->saveEntries($entries);

            return true;
        });
    }

    public function delete(string $key): bool
    {
        return $this->withLock(function () use ($key): bool {
            $entries = $this->entries();
            if (!\array_key_exists($key, $entries) || $this->expired($entries[$key])) {
                return false;
            }
            unset($entries[$key]);
            $this->saveEntries($entries);

            return true;
        });
    }

    /**
     * Test introspection: how many live entries the segment holds under
     * the emulation, the sweep-visibility stand-in the narrow seam
     * deliberately does not expose.
     */
    public function countLiveEntries(): int
    {
        return $this->withLock(function (): int {
            $live = 0;
            foreach ($this->entries() as $entry) {
                if (!$this->expired($entry)) {
                    $live++;
                }
            }

            return $live;
        });
    }

    /**
     * Test introspection: the recorded expiry deadline of one entry, or
     * null when it holds no live entry.
     */
    public function expiryOf(string $key): ?int
    {
        return $this->withLock(function () use ($key): ?int {
            $entries = $this->entries();
            if (!\array_key_exists($key, $entries) || $this->expired($entries[$key])) {
                return null;
            }

            return $entries[$key]['expires'];
        });
    }

    /**
     * Run one operation under the kernel semaphore, the emulation's
     * stand-in for the APCu segment lock.
     *
     * @template T
     *
     * @param callable():T $body
     *
     * @return T
     */
    private function withLock(callable $body): mixed
    {
        if (!sem_acquire($this->sem)) {
            throw new \RuntimeException('the emulated APCu backend could not acquire its semaphore');
        }
        try {
            return $body();
        } finally {
            sem_release($this->sem);
        }
    }

    /** The live entry map inside the segment. */
    private function entries(): array
    {
        if (!shm_has_var($this->shm, self::VAR_KEY)) {
            return [];
        }
        $entries = shm_get_var($this->shm, self::VAR_KEY);

        return \is_array($entries) ? $entries : [];
    }

    /** Persist the entry map inside the segment. */
    private function saveEntries(array $entries): void
    {
        shm_put_var($this->shm, self::VAR_KEY, $entries);
    }

    /** Whether an entry's TTL deadline passed on the wall clock. */
    private function expired(array $entry): bool
    {
        return time() >= $entry['expires'];
    }

    /** One random key out of the private System V key space. */
    private static function randomKey(): int
    {
        return random_int(0x4b430000, 0x4b43ffff);
    }
}
