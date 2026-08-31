<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

use KiwiCaptcha\AuthoritySafety;
use KiwiCaptcha\AuthoritySafetyClassifier;

/**
 * The pinned-primary authority guard (docs/ha-authority.md): pins the
 * serving authority identity through an explicit operator bootstrap and
 * refuses every use when the authority changed.
 *
 * Bootstrap: the production runtime never auto-pins. A guard with no
 * pin and no {@see $expectedIdentity} refuses the first use with the
 * typed {@see PinnedAuthorityRefusalException} naming the
 * `kiwicaptcha:ha-initialize` command. The operator records the
 * initial authority pin deliberately (`SET ... NX`), after quiescing a
 * deliberate authority change. The pin key is per distinct Redis
 * authority: `{kiwi:<ns>}:authority:pin:<suffix>` (the extension wires
 * the suffix "storage" for the storage/limiter authority and "risk"
 * for a distinct risk authority), so one deployment can pin two
 * authorities independently.
 *
 * Expected identity: the optional `ha_authority_expected` configuration
 * carries an operator-provisioned identity ("role|run_id"). When set,
 * the guard compares the serving identity against it instead of the
 * pin key. The configuration is the pin, and a deployment whose
 * identity is immutable can skip the Redis pin entirely. The pin key
 * may still exist (initialize writes it to match), but the comparison
 * target is the operator-provisioned value. The extension accepts the
 * scalar shorthand (one identity for every authority) and the
 * per-authority map (`{"storage": ..., "risk": ...}`). This guard is
 * constructed with the resolved identity of its own authority only,
 * so a distinct storage and risk authority never share one expected
 * run_id.
 *
 * Pin store: one Redis key in the same security-Redis namespace,
 * holding "role|run_id". The pin is write-once (`SET ... NX`). The
 * first verified use of a pinless guard is a refusal (never a pin); an
 * operator runs `kiwicaptcha:ha-initialize` to record the authority.
 * Every later check compares the serving identity against the pin (or
 * the expected identity). Any change (a promotion to a stale replica, a
 * restarted primary with a new run_id, a pointed-at replica) raises the
 * typed {@see PinnedAuthorityRefusalException} naming the pinned vs
 * observed identity and the remediation. The remediation is explicit:
 * quiesce the deployment, delete the pin key, and re-run
 * `kiwicaptcha:ha-initialize` after a deliberate authority change.
 *
 * Missing-pin semantics (documented choice): refuse, never re-pin. A
 * pin that disappears (a failover to a node that never received the
 * pin key) is a refusal, and the guard refuses instead of re-pinning.
 * The deployment can only re-pin explicitly through the initialize
 * command, exactly the operation a stale-promotion recovery must not
 * perform automatically. An authority that cannot be verified (the
 * `INFO` read fails, the pin cannot be read) is a refusal too: the
 * guard can only fail closed, never fail open.
 *
 * Check window and connection generation: the verification result is
 * cached in-process per connection object for `reverifySecs` (default
 * 5). The cache key is `spl_object_id($connection)`, so a reconnect
 * that replaces the connection object invalidates the cache and the
 * next check re-verifies. Within the window, checks return without any
 * round trip, so the `INFO` probe costs one round trip per window per
 * process per connection, not one per operation. A mutating
 * security-final transition (a consume, a committed result, a chain or
 * idempotency finalize) calls {@see assertServeEligible()} with
 * $securityFinal true and bypasses the cache. It re-verifies before
 * every such write, so a security-final transition can never execute
 * on a changed authority inside a stale window (zero stale).
 *
 * Topology contract: the guard refuses automatic-failover aggregates
 * (Predis Sentinel, replication and cluster connections) AND
 * retry-enabled direct connections, and refuses an uninspectable
 * client. A pinned authority is a single node, and an aggregate or a
 * retry wrapper can change the serving node or re-execute the write
 * under the client. That change is exactly what this guard detects at
 * the deployment boundary; it is not routed around. The bundle refuses
 * these shapes under `ha_authority: pinned_primary` at container build
 * time; the constructor check is the same classification at runtime.
 */
final class PinnedPrimaryAuthorityGuard implements AuthorityTransitionGuard
{
    private readonly string $pinKey;

    /**
     * The identity ("role|run_id") this process established or last
     * observed as pinned, or null before the first verification. Once
     * non-null, a missing pin key is a refusal (never a silent re-pin).
     */
    private ?string $establishedIdentity = null;

    /** hrtime(true) of the last successful verification, or null. */
    private ?int $lastVerifiedAt = null;

    private ?string $lastVerifiedIdentity = null;

    /**
     * The connection-generation verification cache:
     * spl_object_id(connection) => hrtime(true). A reconnect that
     * replaces the connection object changes the key and forces a
     * re-verification; each re-verification keeps only the current
     * connection's entry.
     *
     * @var array<int, int>
     */
    private array $verifiedConnections = [];

    /**
     * @param \Predis\Client|\Redis $client          the bound authority
     *        client. Its `INFO` identity reads and its pin-key
     *        reads/writes go through this client, never through the
     *        passed client of {@see assertServeEligible()}. A guarded
     *        wrapper would otherwise recurse into its own check.
     * @param string                $namespace       the deployment
     *        namespace, sanitized to [A-Za-z0-9_.-] before it is
     *        embedded in the pin key. Matches every other bundle key.
     * @param int                   $reverifySecs    the verification cache
     *        window in seconds. 0 disables the cache, so every check
     *        re-verifies (the test-mode and doctor-mode behavior).
     * @param string                $pinKeySuffix    the per-authority
     *        suffix of the pin key ("storage", "risk"). An empty
     *        suffix keeps the legacy single-authority key shape
     *        `{kiwi:<ns>}:authority:pin`.
     * @param string|null           $expectedIdentity the operator-
     *        provisioned expected identity ("role|run_id", the same
     *        shape as the pin value). When set, the guard compares the
     *        serving identity against it instead of the pin key.
     *
     * @throws PinnedAuthorityRefusalException when the client is an
     *         automatic-failover aggregate, a retry-enabled connection,
     *         or an uninspectable client
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $client,
        string $namespace = 'kiwicaptcha',
        private readonly int $reverifySecs = 5,
        string $pinKeySuffix = '',
        private readonly ?string $expectedIdentity = null,
    ) {
        if ($reverifySecs < 0) {
            throw new \InvalidArgumentException(sprintf('reverifySecs must be >= 0, got %d', $reverifySecs));
        }
        $sanitized = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: 'kiwi';
        $this->pinKey = sprintf('{kiwi:%s}:authority:pin%s', $sanitized, $pinKeySuffix !== '' ? ':'.$pinKeySuffix : '');
        if ($expectedIdentity !== null && preg_match('/^[^|]+\|[^|]+$/D', $expectedIdentity) !== 1) {
            throw new \InvalidArgumentException(sprintf('ha_authority_expected must be the identity shape "role|run_id" (got "%s")', $expectedIdentity));
        }
        $this->assertClientSafe($client);
    }

    /**
     * The pin key in the security-Redis namespace, named in every
     * refusal message so the operator can re-pin deliberately.
     */
    public function pinKey(): string
    {
        return $this->pinKey;
    }

    /**
     * The operator-provisioned expected identity ("role|run_id"), or
     * null when the pin key carries the contract.
     */
    public function expectedIdentity(): ?string
    {
        return $this->expectedIdentity;
    }

    /**
     * Record the initial authority pin (the explicit bootstrap,
     * `kiwicaptcha:ha-initialize`). The pin is write-once: an existing
     * pin is refused unless $force is set, because re-pinning an
     * authority is a deliberate operation the operator must perform
     * after a quiesce. With {@see $expectedIdentity} configured, the
     * pin is written to match the operator-provisioned identity (and a
     * mismatch between the expected identity and the serving server is
     * refused).
     *
     * @return string the effective pin ("role|run_id")
     *
     * @throws PinnedAuthorityRefusalException when the authority cannot
     *         be verified, the expected identity disagrees with the
     *         serving server, or the pin already exists without $force
     */
    public function initializePin(bool $force = false): string
    {
        $observed = $this->readIdentity();
        $observedIdentity = $this->formatIdentity($observed);
        if ($this->expectedIdentity !== null && $this->expectedIdentity !== $observedIdentity) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'kiwicaptcha:ha-initialize refused: ha_authority_expected is "%s" but the serving authority is %s (key %s) — the operator-provisioned expected identity and the connected server disagree. Fix the configuration, then re-run initialization (see docs/ha-authority.md).',
                    $this->expectedIdentity,
                    $observedIdentity,
                    $this->pinKey,
                ),
                $this->expectedIdentity,
                $observedIdentity,
            );
        }
        $target = $this->expectedIdentity ?? $observedIdentity;
        $existing = $this->readPin();
        if ($existing !== null && !$force) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'kiwicaptcha:ha-initialize refused: a pin already exists (key %s, %s). Re-initializing an authority is a deliberate operation: quiesce the deployment, then re-run with --force to record the new authority (see docs/ha-authority.md).',
                    $this->pinKey,
                    $existing,
                ),
                $existing,
                $observedIdentity,
            );
        }
        if ($existing === null) {
            $written = $this->setNx($this->pinKey, $target);
            if ($written) {
                $this->establishedIdentity = $target;
                $this->cacheVerified($target, $this->connectionIdOf($this->client));

                return $target;
            }
            // A concurrent initialize won the write: adopt the winner's
            // pin.
            $winner = $this->readPin();
            if ($winner === null) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'kiwicaptcha:ha-initialize refused: the pin could not be established (key %s) — the concurrent initialization and the re-read raced. Quiesce and retry (see docs/ha-authority.md).',
                        $this->pinKey,
                    ),
                    null,
                    $observedIdentity,
                );
            }
            $this->establishedIdentity = $winner;
            $this->cacheVerified($winner, $this->connectionIdOf($this->client));

            return $winner;
        }
        // --force: overwrite the pin after a deliberate quiesce.
        $this->client->set($this->pinKey, $target);
        $this->establishedIdentity = $target;
        $this->cacheVerified($target, $this->connectionIdOf($this->client));

        return $target;
    }

    /**
     * The guard's observable state for the doctor: armed (an identity
     * is established and was verified), the pinned identity (the
     * expected identity when configured, else the pin key value), the
     * last verified identity and the age of the last verification.
     *
     * @return array{armed: bool, pinned: ?string, lastVerified: ?string, lastCheckedAgoSecs: ?int}
     */
    public function state(): array
    {
        $pinned = $this->expectedIdentity;
        if ($pinned === null) {
            $pinned = $this->establishedIdentity;
            if ($pinned === null) {
                try {
                    $raw = $this->readPin();
                    if (\is_string($raw) && $raw !== '') {
                        $pinned = $raw;
                    }
                } catch (\Throwable) {
                    $pinned = null;
                }
            }
        }

        return [
            'armed' => $pinned !== null && $this->lastVerifiedAt !== null,
            'pinned' => $pinned,
            'lastVerified' => $this->lastVerifiedIdentity,
            'lastCheckedAgoSecs' => $this->lastVerifiedAt === null
                ? null
                : (int) floor((hrtime(true) - $this->lastVerifiedAt) / 1_000_000_000),
        ];
    }

    public function assertServeEligible(mixed $client, bool $securityFinal = false): void
    {
        if (!$client instanceof \Predis\Client && !$client instanceof \Redis) {
            throw new PinnedAuthorityRefusalException(
                'pinned_primary authority check refused: the client about to serve is not a Redis client ('.get_debug_type($client).') — the pinned-primary guard cannot verify an authority it cannot read.',
                $this->establishedIdentity,
            );
        }
        $this->assertClientSafe($client);
        // Cached verification: a non-security-final check within the
        // window on the same connection object serves without a round
        // trip. A security-final transition bypasses the cache entirely
        // (zero stale), and a connection object that was replaced by a
        // reconnect is a cache miss.
        $connectionId = $this->connectionIdOf($client);
        if (!$securityFinal
            && $connectionId !== null
            && isset($this->verifiedConnections[$connectionId])
            && (hrtime(true) - $this->verifiedConnections[$connectionId]) < $this->reverifySecs * 1_000_000_000
        ) {
            return;
        }
        $observed = $this->readIdentity();
        $observedIdentity = $this->formatIdentity($observed);
        $expected = $this->expectedIdentity ?? $this->readPin();
        if ($expected === null) {
            if ($this->establishedIdentity !== null) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority check refused: the pinned identity is missing — the deployment was pinned to %s (key %s), but the key is gone now. A promotion to a node that never received the pin would present exactly this state, so the guard refuses instead of re-pinning. Re-pin explicitly after a deliberate authority change: quiesce the deployment, run kiwicaptcha:ha-initialize, and verify the new authority (see docs/ha-authority.md).',
                        $this->establishedIdentity,
                        $this->pinKey,
                    ),
                    $this->establishedIdentity,
                    $observedIdentity,
                );
            }
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority check refused: the deployment is not bootstrapped — no pin exists (key %s) and no ha_authority_expected identity is configured, and the production runtime never auto-pins. Run kiwicaptcha:ha-initialize after a deliberate authority quiesce to record the initial authority pin, or configure ha_authority_expected with the operator-provisioned identity (see docs/ha-authority.md).',
                    $this->pinKey,
                ),
                null,
                $observedIdentity,
            );
        }
        if ($expected !== $observedIdentity) {
            throw new PinnedAuthorityRefusalException(
                $this->mismatchMessage($expected, $observedIdentity),
                $expected,
                $observedIdentity,
            );
        }
        $this->establishedIdentity = $expected;
        $this->cacheVerified($expected, $connectionId);
    }

    private function cacheVerified(string $identity, ?int $connectionId): void
    {
        $this->lastVerifiedIdentity = $identity;
        $this->lastVerifiedAt = hrtime(true);
        if ($connectionId !== null) {
            // Keep only the current connection's entry: a replaced
            // connection is a cache miss on the next check.
            $this->verifiedConnections = [$connectionId => hrtime(true)];
        }
    }

    /**
     * The stale-promotion refusal: names the pinned vs observed
     * identity and the remediation.
     */
    private function mismatchMessage(string $pinned, string $observed): string
    {
        return sprintf(
            'pinned_primary authority REFUSED: the serving authority changed — pinned %s, observed %s (key %s). A promotion to a stale replica or a restarted primary with a new run_id presents exactly this identity change, so the guard refuses every durability-critical transition. Re-pin explicitly after a deliberate authority change: quiesce the deployment, run kiwicaptcha:ha-initialize, and verify the new authority (see docs/ha-authority.md).',
            $pinned,
            $observed,
            $this->pinKey,
        );
    }

    /**
     * Write the pin once (SET NX): the first initialize that wins
     * establishes it; a concurrent initialize reads the winner's pin.
     * Returns whether this caller wrote the pin.
     */
    private function setNx(string $key, string $value): bool
    {
        if ($this->client instanceof \Predis\Client) {
            return $this->client->set($key, $value, 'NX') === 'OK';
        }

        return (bool) $this->client->set($key, $value, ['nx' => true]);
    }

    /**
     * The pinned identity from the pin key, or null when absent or
     * unreadable (an unreadable store is a refusal, never a pass).
     */
    private function readPin(): ?string
    {
        try {
            $raw = $this->client->get($this->pinKey);

            return \is_string($raw) && $raw !== '' ? $raw : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The serving authority identity: the role and run_id of the
     * connected server, from `INFO replication` (falling back to
     * `INFO server` for the run_id on Redis builds that omit it from
     * the replication section). An identity that cannot be read is a
     * refusal: unverifiable means stale.
     *
     * @return array{role: string, run_id: string}
     *
     * @throws PinnedAuthorityRefusalException when the identity cannot
     *                                         be established
     */
    private function readIdentity(): array
    {
        try {
            if ($this->client instanceof \Predis\Client) {
                $replication = $this->client->info('replication');
                $role = $this->fieldOf($replication, 'role');
                $runId = $this->fieldOf($replication, 'run_id');
                if ($runId === null) {
                    $server = $this->client->info('server');
                    $runId = $this->fieldOf($server, 'run_id');
                }
            } else {
                $replication = $this->client->info('replication');
                $role = $this->fieldOf($replication, 'role');
                $runId = $this->fieldOf($replication, 'run_id');
                if ($runId === null) {
                    $runId = $this->fieldOf($this->client->info('server'), 'run_id');
                }
            }
        } catch (\Throwable $e) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the serving authority cannot be verified — reading the server identity failed: %s. An unverifiable authority is treated as stale, never passed. Check the security Redis and re-pin explicitly after a deliberate authority change (see docs/ha-authority.md).',
                    $e->getMessage(),
                ),
                $this->establishedIdentity,
            );
        }
        if (!\is_string($role) || $role === '' || !\is_string($runId) || $runId === '') {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the serving authority identity is incomplete — the server reported role %s, run_id %s. An unverifiable authority is treated as stale, never passed (see docs/ha-authority.md).',
                    \is_string($role) && $role !== '' ? $role : '(none)',
                    \is_string($runId) && $runId !== '' ? $runId : '(none)',
                ),
                $this->establishedIdentity,
            );
        }

        return ['role' => $role, 'run_id' => $runId];
    }

    /**
     * One field of an `INFO` section. Predis returns the parsed
     * section array, either flat ("role", "run_id") or nested under
     * the section name ("Replication" => ["role", "run_id"]); phpredis
     * may return a raw "key:value" section string, which is parsed
     * line by line.
     *
     * @param mixed $section
     */
    private function fieldOf(mixed $section, string $field): ?string
    {
        if (\is_array($section)) {
            $value = $section[$field] ?? null;
            if (!\is_string($value) || $value === '') {
                foreach ($section as $nested) {
                    if (\is_array($nested)) {
                        $value = $nested[$field] ?? null;
                        if (\is_string($value) && $value !== '') {
                            return $value;
                        }
                    }
                }
            }

            return \is_string($value) && $value !== '' ? $value : null;
        }
        if (\is_string($section)) {
            foreach (explode("\r\n", $section) as $line) {
                if (preg_match('/^'.preg_quote($field, '/').':(.*)$/', $line, $m) === 1) {
                    $value = trim($m[1]);

                    return $value !== '' ? $value : null;
                }
            }
        }

        return null;
    }

    /**
     * @param array{role: string, run_id: string} $identity
     */
    private function formatIdentity(array $identity): string
    {
        return $identity['role'].'|'.$identity['run_id'];
    }

    /**
     * The connection object identity of a client, or null when no
     * connection object is inspectable (phpredis, or a client whose
     * connection cannot be read). The cache is keyed on this identity,
     * so a reconnect that replaces the connection object invalidates
     * the cached verification.
     */
    private function connectionIdOf(mixed $client): ?int
    {
        if (!$client instanceof \Predis\Client) {
            return null;
        }
        try {
            $connection = $client->getConnection();

            return $connection === null ? null : spl_object_id($connection);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * A pinned authority is a single node with retries disabled: an
     * aggregate can change the serving node under the client, a
     * retry-enabled connection can re-execute the write on a
     * replacement connection, and an uninspectable client cannot be
     * proven safe. All three are refused outright.
     */
    private function assertClientSafe(\Predis\Client|\Redis $client): void
    {
        $classification = AuthoritySafetyClassifier::classify($client);
        if ($classification === AuthoritySafety::Safe) {
            return;
        }
        if ($classification === AuthoritySafety::Unknown) {
            throw new PinnedAuthorityRefusalException(
                sprintf(
                    'pinned_primary authority REFUSED: the client (%s) cannot be classified as a single-node direct connection — unknown authority-transition semantics are unsafe under pinned_primary until proven safe. Wire a direct single-node Predis client with retries disabled (see docs/ha-authority.md).',
                    get_debug_type($client),
                ),
            );
        }
        if ($client instanceof \Predis\Client) {
            $connection = $client->getConnection();
            if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority REFUSED: the client is a %s aggregate (%s) — automatic failover can change the serving node under the client, which is exactly the authority change the pin exists to detect at the deployment boundary. Wire a direct single-node client (standalone connection with retries disabled) for pinned_primary (see docs/ha-authority.md).',
                        'cluster',
                        \get_class($connection),
                    ),
                );
            }
            if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority REFUSED: the client is a %s aggregate (%s) — automatic failover can change the serving node under the client, which is exactly the authority change the pin exists to detect at the deployment boundary. Wire a direct single-node client (standalone connection with retries disabled) for pinned_primary (see docs/ha-authority.md).',
                        'replication',
                        \get_class($connection),
                    ),
                );
            }
            if ($connection instanceof \Predis\Connection\NodeConnectionInterface && !$connection->getParameters()->isDisabledRetry()) {
                throw new PinnedAuthorityRefusalException(
                    sprintf(
                        'pinned_primary authority REFUSED: the client is a retry-enabled standalone Predis connection (%s) — the vendored retry wrapper can re-execute a durability-critical transition on a replacement connection whose write offset is empty, exactly the authority-change window the pin exists to detect at the deployment boundary. Wire a direct single-node client with retries disabled for pinned_primary (see docs/ha-authority.md).',
                        \get_class($connection),
                    ),
                );
            }
        }
        throw new PinnedAuthorityRefusalException(
            sprintf(
                'pinned_primary authority REFUSED: the client (%s) is unsafe under the canonical authority-safety classification — automatic failover or client-side retries can change the serving authority. Wire a direct single-node Predis client with retries disabled (see docs/ha-authority.md).',
                get_debug_type($client),
            ),
        );
    }
}
