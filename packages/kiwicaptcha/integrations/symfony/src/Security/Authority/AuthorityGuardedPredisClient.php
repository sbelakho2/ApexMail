<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

use Predis\Command\CommandInterface;

/**
 * The pinned-primary wiring seam: a Predis\Client that delegates every
 * command to an inner client after consulting the authority guard.
 *
 * The bundle decorates the storage/limiter/risk client service with
 * this wrapper under `ha_authority: pinned_primary`. Every command
 * the bundle components issue (including the verified-WAIT
 * `executeRaw` calls) is preceded by
 * {@see AuthorityTransitionGuard::assertServeEligible()}, so a
 * durability transition can never execute on a changed authority.
 * The guard is consulted with the inner raw client (never this
 * wrapper), so its own `INFO` reads and pin-key operations cannot
 * recurse into the check.
 *
 * Zero-stale security-final lane: the wrapper forces the security-final
 * guard lane for every `EVALSHA` whose recorded script body carries a
 * mutating security-final marker, and for every unrecorded sha (fail
 * closed, an unseen script can never be proven non-final). A plain
 * `EVAL` executed without the typed seam is an unknown mutating
 * script: it is security-final by default, so it is re-validated
 * immediately, never served inside the window (fail closed).
 *
 * The bundle's own stores never rely on this default. They execute
 * their Lua through the typed `RedisSecurityCommandExecutor` seam,
 * which declares the lane for every script. The seam's explicit lanes
 * override the default for both `EVAL` and `EVALSHA`: the
 * security-final lane forces revalidation regardless of command
 * shape, and the ordinary lane serves within the window. The forced
 * lane bypasses the verification window and re-verifies the authority
 * before every such write, so a security-final transition can never
 * execute on a changed authority inside a stale window: the window
 * applies to ordinary reads and non-final writes only.
 *
 * The guard caches its verification for a short window per connection
 * object (spl_object_id), so the wrapper costs one `INFO` probe per
 * window per connection per process, not one round trip per command.
 * Within the window ordinary checks return without any I/O; a
 * reconnect that replaces the connection object invalidates the cache.
 *
 * The wrapper is a Predis\Client subclass (never a proxy) so every
 * existing `\Predis\Client` type hint keeps accepting the decorated
 * service. A phpredis `\Redis` client cannot be intercepted this way,
 * which is why the extension refuses phpredis under
 * `pinned_primary` (fail closed, never silently unguarded).
 */
final class AuthorityGuardedPredisClient extends \Predis\Client
{
    /** The seam's ordinary lane: serve within the verification window. */
    public const LANE_ORDINARY = 'ordinary';

    /** The seam's zero-stale lane: re-verify before the write. */
    public const LANE_SECURITY_FINAL = 'security-final';

    /**
     * The distinctive body markers of the mutating security-final Lua
     * scripts the core RedisStorage loads (`EVALSHA` only — the bundle's
     * own stores execute through the typed
     * {@see RedisSecurityCommandExecutor} seam and never need these
     * markers). A script whose body carries one of these markers is
     * preceded by the zero-stale security-final guard lane. The markers
     * mirror the components' script header comments
     * (docs/ha-authority.md).
     */
    private const SECURITY_FINAL_MARKERS = [
        '-- kiwicaptcha consume transition',
        '-- kiwicaptcha delete-if-pending (atomic cleanup)',
        '-- kiwicaptcha cancel transition',
        '-- kiwicaptcha commit result',
        '-- kiwicaptcha resume-derivation claim',
        '-- Chain obligation create-or-get',
        '-- Chain reservation:',
        '-- Chain issuance:',
        '-- Chain verification:',
        '-- Chain step-up:',
        '-- Chain denial:',
        '-- Transaction denial:',
        '-- Transaction step-up:',
        '-- Chain rearm:',
        '-- Chain release:',
        '-- Chain completion',
        '-- Chain obligation compare-delete:',
        '-- Post-solve disposition claim:',
        '-- Post-solve disposition guarded finalize:',
        '-- Post-solve disposition finalize:',
        '-- The finalize must authorize the state',
        'Outstanding challenge issuance',
        'Outstanding challenge release',
        'Outstanding challenge cancellation admission',
    ];

    /**
     * sha => script body, captured at `SCRIPT LOAD` time so an
     * `EVALSHA` can be classified by its body without knowing the
     * components' private Lua constants.
     *
     * @var array<string, string>
     */
    private array $scriptBodiesBySha = [];

    /**
     * The lane stack of the executing {@see RedisSecurityCommandExecutor}
     * calls: `withLane()` pushes the seam's declared lane for the
     * duration of the closure, so the wrapper can force (or relax) the
     * guard lane for a specific command regardless of its shape.
     *
     * @var list<string>
     */
    private array $laneStack = [];

    public function __construct(
        private readonly AuthorityTransitionGuard $guard,
        private readonly \Predis\Client $inner,
    ) {
        parent::__construct();
    }

    /**
     * Run an operation inside the seam's declared lane. The operation's
     * commands bypass the wrapper's shape-based classification and use
     * exactly the lane the seam declared: the security-final lane
     * forces the zero-stale revalidation for every command shape, and
     * the ordinary lane serves within the window.
     */
    public function withLane(string $lane, callable $operation): mixed
    {
        $this->laneStack[] = $lane;
        try {
            return $operation();
        } finally {
            array_pop($this->laneStack);
        }
    }

    public function executeCommand(CommandInterface $command): mixed
    {
        $this->guard->assertServeEligible($this->inner, $this->isForcedSecurityFinalCommand($command));

        return $this->inner->executeCommand($command);
    }

    public function __call($commandID, $arguments): mixed
    {
        if (strtoupper((string) $commandID) === 'SCRIPT') {
            $this->recordScriptLoad($arguments);
        }
        $this->guard->assertServeEligible($this->inner, $this->isForcedSecurityFinalCall($commandID, $arguments));

        return $this->inner->__call($commandID, $arguments);
    }

    public function executeRaw(array $arguments, &$error = null): mixed
    {
        // The verified-WAIT executeRaw carries WAIT, never a
        // security-final mutation, so the ordinary window lane applies.
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->executeRaw($arguments, $error);
    }

    public function pipeline(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->pipeline(...$arguments);
    }

    public function transaction(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->transaction(...$arguments);
    }

    public function pubSubLoop(...$arguments): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->pubSubLoop(...$arguments);
    }

    public function monitor(): mixed
    {
        $this->guard->assertServeEligible($this->inner);

        return $this->inner->monitor();
    }

    public function connect(): void
    {
        $this->inner->connect();
    }

    public function disconnect(): void
    {
        $this->inner->disconnect();
    }

    public function quit(): mixed
    {
        return $this->inner->quit();
    }

    public function isConnected(): bool
    {
        return $this->inner->isConnected();
    }

    public function getConnection(): mixed
    {
        return $this->inner->getConnection();
    }

    public function getClientBy($selector, $value): mixed
    {
        return $this->inner->getClientBy($selector, $value);
    }

    public function getCommandFactory(): mixed
    {
        return $this->inner->getCommandFactory();
    }

    public function getOptions(): mixed
    {
        return $this->inner->getOptions();
    }

    public function createCommand($commandID, $arguments = []): mixed
    {
        return $this->inner->createCommand($commandID, $arguments);
    }

    public function pack($value): mixed
    {
        return $this->inner->pack($value);
    }

    public function unpack($value): mixed
    {
        return $this->inner->unpack($value);
    }

    public function getIterator(): \Traversable
    {
        return $this->inner->getIterator();
    }

    public function __get(string $name): mixed
    {
        return $this->inner->{$name};
    }

    public function __set(string $name, $value): void
    {
        $this->inner->{$name} = $value;
    }

    public function __isset(string $name): bool
    {
        return isset($this->inner->{$name});
    }

    /**
     * Record a `SCRIPT LOAD` body under its sha so the later `EVALSHA`
     * can be classified. Both the `__call` shape (the `script` command
     * with the subcommand `LOAD`) and a direct command are covered.
     *
     * @param list<mixed> $arguments
     */
    private function recordScriptLoad(array $arguments): void
    {
        $sub = $arguments[0] ?? null;
        if (\is_string($sub) && strtoupper($sub) === 'LOAD' && \is_string($arguments[1] ?? null)) {
            $this->scriptBodiesBySha[sha1($arguments[1])] = $arguments[1];
        }
    }

    /**
     * Whether the command about to execute must ride the zero-stale
     * security-final lane. The seam's declared lane always wins; a
     * bare command falls back to the shape classification (an unknown
     * mutating `EVAL` and an unrecorded `EVALSHA` are security-final
     * by default, fail closed).
     */
    private function isForcedSecurityFinalCommand(CommandInterface $command): bool
    {
        return $this->isForcedSecurityFinalCall($command->getId(), $command->getArguments());
    }

    /**
     * @param mixed $commandID
     * @param list<mixed> $arguments
     */
    private function isForcedSecurityFinalCall(mixed $commandID, array $arguments): bool
    {
        if ($this->laneStack !== []) {
            // The RedisSecurityCommandExecutor seam declared the lane
            // for this execution: the declaration wins over the shape
            // heuristic for both `EVAL` and `EVALSHA`.
            return $this->laneStack[\count($this->laneStack) - 1] === self::LANE_SECURITY_FINAL;
        }

        return $this->isSecurityFinalCall($commandID, $arguments);
    }

    /**
     * The shape-based fallback classification for commands executed
     * without the seam's lane declaration. An unknown mutating `EVAL`
     * and an unrecorded `EVALSHA` are security-final by default (fail
     * closed).
     *
     * @param mixed $commandID
     * @param list<mixed> $arguments
     */
    private function isSecurityFinalCall(mixed $commandID, array $arguments): bool
    {
        $id = strtoupper((string) $commandID);
        if ($id === 'EVAL') {
            // A plain EVAL carries its script body inline; the wrapper
            // cannot prove a body non-final without a marker heuristic
            // (which the stores deliberately abandoned for the typed
            // seam). Unknown mutating EVAL = security-final: default to
            // immediate revalidation, never a window pass.
            return true;
        }
        if ($id !== 'EVALSHA') {
            return false;
        }
        $sha = $arguments[0] ?? null;
        if (!\is_string($sha) || $sha === '') {
            return false;
        }
        $body = $this->scriptBodiesBySha[$sha] ?? null;
        if ($body === null) {
            // An unrecorded script cannot be proven non-final: fail
            // closed with the zero-stale lane.
            return true;
        }

        return self::isSecurityFinalScript($body);
    }

    /**
     * Whether a loaded Lua body is a mutating security-final
     * transition: any of the components' security-final markers.
     */
    private static function isSecurityFinalScript(string $body): bool
    {
        foreach (self::SECURITY_FINAL_MARKERS as $marker) {
            if (str_contains($body, $marker)) {
                return true;
            }
        }

        return false;
    }
}
