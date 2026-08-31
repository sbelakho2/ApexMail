<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use PHPUnit\Framework\Assert;

/**
 * The model-checking walk driver of the consume/commit/recovery state
 * machine: replays a transition sequence against the clean-room
 * {@see ConsumeRecoveryModel} and a concrete {@see ConsumeRecoveryDriver}
 * (the in-memory ArrayStorage mirror or the real RedisStorage Lua
 * store) in lockstep. It asserts outcome parity and the invariant suite
 * after every step:
 *
 *  - outcome parity: the concrete store and the verifier resolution
 *    return exactly the abstract model's outcome for the same
 *    transition and arguments.
 *  - the invariant suite of ConsumeRecoveryModel::assertInvariants()
 *    (exactly one consume winner, a committed result never re-derived,
 *    the claim lease discipline, the vanished-record vocabulary, no
 *    double success, no replay outside the identity gate).
 *  - concrete-state equality: the stored envelope's observable shape
 *    equals the model configuration.
 *
 * The step generator is a fixed-seed LCG, so every run of a given seed
 * replays the identical walk (deterministic model checking). The BFS
 * generator enumerates the reachable state space of the model, and the
 * test replays every recorded sequence against the real stores. A
 * record that vanished is repaired with a fresh issuance, exactly like
 * the ticket service mints a fresh generation after an expiry.
 */
final class ConsumeRecoveryWalk
{
    /** The shared HMAC secret of the issued challenges. */
    public const SECRET = '0123456789abcdef0123456789abcdef';

    /** The two logical-operation identities of the walk. */
    public const IDENTITY_A = 'op-a';

    public const IDENTITY_B = 'op-other';

    /** A foreign lease owner token (32 lowercase hex, the shared contract). */
    public const FOREIGN_OWNER = 'cccccccccccccccccccccccccccccccc';

    /** The claim lease length in seconds (the storage default mirror). */
    public const CLAIM_TTL = 60;

    /**
     * The deterministic bounded random-walk step list for a seed. The
     * transition weights favor the replay resolution, so the identity
     * gate and the committed-result semantics dominate the walk.
     *
     * @return list<array{0: string, 1: array<string, mixed>}>
     */
    public static function steps(int $seed, int $count): array
    {
        $rng = $seed;
        $steps = [];
        for ($i = 0; $i < $count; ++$i) {
            $steps[] = self::step($rng);
        }

        return $steps;
    }

    /**
     * The breadth-first enumeration of the reachable state space: every
     * state-changing transition application from every discovered
     * configuration, recorded as a path. Each recorded path is replayed
     * against the concrete drivers by the test, so the exhaustive
     * reachable transition set executes against the real stores.
     *
     * @return list<list<array{0: string, 1: array<string, mixed>}>>
     */
    public static function bfsPaths(int $maxDepth = 14, int $maxPaths = 600): array
    {
        $root = ConsumeRecoveryModel::fresh();
        $paths = [[]];
        $visited = [$root->configKey() => true];
        $frontier = [[$root, []]];
        while ($frontier !== [] && \count($paths) < $maxPaths) {
            [$model, $path] = array_shift($frontier);
            if (\count($path) >= $maxDepth) {
                continue;
            }
            foreach (self::bfsTransitions($model) as [$name, $args]) {
                $next = clone $model;
                $resolved = self::resolveArgsForModel($model, $args);
                $next->apply($name, $resolved);
                if ($next->configKey() === $model->configKey()) {
                    continue;
                }
                $nextPath = [...$path, [$name, $args]];
                $paths[] = $nextPath;
                if (!isset($visited[$next->configKey()])) {
                    $visited[$next->configKey()] = true;
                    $frontier[] = [$next, $nextPath];
                }
            }
        }

        return $paths;
    }

    /**
     * Run the walk: every step is applied to the abstract model and to
     * the concrete driver, with the invariant + parity + state-equality
     * assertions after each step. A missing record is repaired with a
     * fresh issuance (a fresh generation).
     *
     * @param list<array{0: string, 1: array<string, mixed>}> $steps
     *
     * @return array{steps: int, generations: int}
     */
    public static function run(string $context, ConsumeRecoveryDriver $driver, array $steps): array
    {
        $model = ConsumeRecoveryModel::fresh();
        $nonce = $driver->issue();
        $generations = 0;
        $applied = 0;
        foreach ($steps as [$name, $args]) {
            if ($model->state === ConsumeRecoveryModel::MISSING) {
                $nonce = $driver->issue();
                $model = ConsumeRecoveryModel::fresh();
                ++$generations;
            }
            if (self::applyStep($context, $driver, $model, $nonce, $name, $args)) {
                ++$applied;
            }
            ConsumeRecoveryModel::assertConcreteMatchesModel($model, $driver->readState($nonce), $context);
        }

        return ['steps' => $applied, 'generations' => $generations];
    }

    /**
     * Apply one step to the model and the driver, asserting outcome
     * parity and the invariant suite. Returns false when the step was
     * guarded out (the replay transition on a still-pending record: the
     * verifier would burn the record by deriving, a different machine
     * than the consumed-record resolution the model describes; the BFS
     * never generates it).
     *
     * @param array<string, mixed> $args
     */
    private static function applyStep(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, string $name, array $args): bool
    {
        if ($name === 'replay' && $model->state === ConsumeRecoveryModel::PENDING) {
            return false;
        }
        // The owner arguments resolve against the model before both the
        // model application and the driver call, so the invariant suite
        // and the parity assertion observe the same resolved token.
        if ($name === 'commit' || $name === 'release') {
            $args['owner'] = self::resolveOwner($model, $args['owner'] ?? null);
        }
        $before = clone $model;
        $expected = match ($name) {
            'consume' => self::applyConsume($context, $driver, $model, $nonce, $args),
            'derive' => self::applyDerive($context, $driver, $model, $nonce, $args),
            'commit' => self::applyCommit($context, $driver, $model, $nonce, $args),
            'claim' => self::applyClaim($context, $driver, $model, $nonce, $args),
            'claim-expire' => self::applyClaimExpire($context, $driver, $model, $nonce),
            'release' => self::applyRelease($context, $driver, $model, $nonce, $args),
            'replay' => self::applyReplay($context, $driver, $model, $nonce, $args),
            'vanish' => self::applyVanish($context, $driver, $model, $nonce),
            'cancel' => self::applyCancel($context, $driver, $model, $nonce),
            default => throw new \LogicException(sprintf('unknown walk transition %s', $name)),
        };
        ConsumeRecoveryModel::assertInvariants($before, $model, $expected, $name, $args, $context);

        return true;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyConsume(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): mixed
    {
        $identity = isset($args['identity']) ? (string) $args['identity'] : null;
        $actual = $driver->consume($nonce, $identity);
        $expected = $model->apply('consume', ['identity' => $identity]);
        if ($expected === null) {
            Assert::assertNull($actual, $context.': a missing or cancelled record consumes to nothing');
        } elseif ($expected === 'win') {
            Assert::assertNotNull($actual, $context.': the model win must win the concrete transition');
            Assert::assertTrue($actual['win'], $context.': the concrete transition reports the win');
        } else {
            Assert::assertNotNull($actual, $context.': the model lose must observe the concrete lose');
            Assert::assertTrue($actual['lose'], $context.': the concrete transition reports the lose');
        }

        return $expected;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyDerive(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): string
    {
        $valid = (bool) ($args['valid'] ?? false);
        $actual = $driver->commit($nonce, $valid, null);
        $expected = $model->apply('derive', ['valid' => $valid]);
        Assert::assertSame($expected === 'committed', $actual, $context.': the derivation parity (committed lands exactly when the model commits)');

        return $expected;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyCommit(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): string
    {
        $valid = (bool) ($args['valid'] ?? false);
        $owner = $args['owner'] ?? null;
        $actual = $driver->commit($nonce, $valid, $owner);
        $expected = $model->apply('commit', ['valid' => $valid, 'owner' => $owner]);
        Assert::assertSame($expected === 'committed', $actual, $context.': the commit parity (the claim fence included)');

        return $expected;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyClaim(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): mixed
    {
        $owner = $driver->claim($nonce, self::CLAIM_TTL);
        $expected = $model->apply('claim', ['owner' => $owner ?? 'no-owner', 'ttl' => self::CLAIM_TTL]);
        Assert::assertSame($owner !== null, $expected !== null, $context.': the claim parity (won exactly when the model claims)');
        if ($owner !== null) {
            Assert::assertSame($owner, $model->claimOwner, $context.': the model holds the minted owner token');
        }

        return $expected;
    }

    private static function applyClaimExpire(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce): bool
    {
        $actual = $driver->expireClaim($nonce);
        $expected = $model->apply('claim-expire', []);
        Assert::assertSame($expected, $actual, $context.': the lease expiry parity');

        return $expected;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyRelease(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): bool
    {
        $owner = $args['owner'] ?? self::FOREIGN_OWNER;
        $actual = $driver->release($nonce, $owner);
        $expected = $model->apply('release', ['owner' => $owner]);
        Assert::assertSame($expected, $actual, $context.': the compare-and-delete release parity');

        return $expected;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function applyReplay(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce, array $args): string
    {
        $symbol = isset($args['identity']) ? (string) $args['identity'] : null;
        $presented = $symbol === 'exact' ? $model->identity : ($symbol === 'other' ? self::IDENTITY_B : null);
        $actual = $driver->replay($nonce, $presented);
        $expected = $model->apply('replay', ['identity' => $symbol]);
        Assert::assertSame($expected, $actual, $context.': the replay resolution parity (the identity gate included)');

        return $expected;
    }

    private static function applyVanish(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce): bool
    {
        $driver->vanish($nonce);
        $expected = $model->apply('vanish', []);
        Assert::assertTrue($expected, $context.': the vanish transition always applies');

        return $expected;
    }

    private static function applyCancel(string $context, ConsumeRecoveryDriver $driver, ConsumeRecoveryModel &$model, string $nonce): mixed
    {
        $actual = $driver->cancel($nonce);
        $expected = $model->apply('cancel', []);
        Assert::assertSame($expected, $actual, $context.': the cancel parity');

        return $expected;
    }

    /**
     * Resolve a symbolic owner argument: 'held' is the model's current
     * lease owner (or a foreign token when no lease is held, so both
     * sides agree on the refusal), 'foreign' is the walk's foreign
     * owner token, any other value passes through.
     */
    private static function resolveOwner(ConsumeRecoveryModel $model, ?string $owner): ?string
    {
        if ($owner === null) {
            return null;
        }
        if ($owner === 'held') {
            return $model->claimOwner ?? self::FOREIGN_OWNER;
        }
        if ($owner === 'foreign') {
            return self::FOREIGN_OWNER;
        }

        return $owner;
    }

    /**
     * The state-changing transition set of a configuration, for the BFS
     * exploration. Owner arguments stay symbolic ('held' resolves
     * against the configuration at application time, exactly like the
     * walk's execution-time resolution).
     *
     * @return list<array{0: string, 1: array<string, mixed>}>
     */
    private static function bfsTransitions(ConsumeRecoveryModel $model): array
    {
        $state = $model->state;
        $transitions = [];
        if ($state === ConsumeRecoveryModel::PENDING) {
            $transitions[] = ['consume', ['identity' => null]];
            $transitions[] = ['consume', ['identity' => self::IDENTITY_A]];
            $transitions[] = ['cancel', []];
            $transitions[] = ['vanish', []];

            return $transitions;
        }
        if ($state === ConsumeRecoveryModel::MISSING) {
            return $transitions;
        }
        if ($state === ConsumeRecoveryModel::CANCELLED) {
            $transitions[] = ['vanish', []];

            return $transitions;
        }
        if ($state === ConsumeRecoveryModel::CONSUMED_RESULTLESS) {
            $transitions[] = ['derive', ['valid' => true]];
            $transitions[] = ['derive', ['valid' => false]];
            $transitions[] = ['commit', ['valid' => true, 'owner' => null]];
            $transitions[] = ['commit', ['valid' => false, 'owner' => null]];
            $transitions[] = ['claim', ['owner' => 'owner-token', 'ttl' => self::CLAIM_TTL]];
            if ($model->claimOwner !== null) {
                if ($model->claimUntil > 0) {
                    $transitions[] = ['claim-expire', []];
                }
                $transitions[] = ['release', ['owner' => 'held']];
                $transitions[] = ['commit', ['valid' => true, 'owner' => 'held']];
                $transitions[] = ['commit', ['valid' => false, 'owner' => 'held']];
                $transitions[] = ['commit', ['valid' => true, 'owner' => 'foreign']];
                $transitions[] = ['commit', ['valid' => false, 'owner' => 'foreign']];
            }
            $transitions[] = ['vanish', []];

            return $transitions;
        }
        // The committed states: only the lease transitions and the
        // vanish sweep change the configuration (the replay resolution
        // is state-preserving; the random walk exercises it).
        if ($model->claimOwner !== null) {
            if ($model->claimUntil > 0) {
                $transitions[] = ['claim-expire', []];
            }
            $transitions[] = ['release', ['owner' => 'held']];
        }
        $transitions[] = ['vanish', []];

        return $transitions;
    }

    /**
     * Resolve the symbolic owner argument of a transition against a
     * configuration, for the BFS exploration: 'held' becomes the
     * configuration's own lease owner (or a foreign token when no lease
     * is held, so the exploration observes the refusal).
     *
     * @param array<string, mixed> $args
     *
     * @return array<string, mixed>
     */
    private static function resolveArgsForModel(ConsumeRecoveryModel $model, array $args): array
    {
        if (($args['owner'] ?? null) === 'held') {
            $args['owner'] = $model->claimOwner ?? self::FOREIGN_OWNER;
        }

        return $args;
    }

    /**
     * @return array{0: string, 1: array<string, mixed>} one weighted-random step
     */
    private static function step(int &$rng): array
    {
        $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
        $pick = $rng % 100;
        $name = match (true) {
            $pick < 15 => 'consume',
            $pick < 27 => 'derive',
            $pick < 35 => 'commit',
            $pick < 45 => 'claim',
            $pick < 51 => 'claim-expire',
            $pick < 59 => 'release',
            $pick < 81 => 'replay',
            $pick < 89 => 'vanish',
            default => 'cancel',
        };
        $args = [];
        if ($name === 'consume') {
            $args['identity'] = self::pick($rng, [null, self::IDENTITY_A]);
        }
        if ($name === 'derive') {
            $args['valid'] = self::pick($rng, [true, false]);
        }
        if ($name === 'commit') {
            $args['valid'] = self::pick($rng, [true, false]);
            $args['owner'] = self::pick($rng, [null, 'held', 'foreign']);
        }
        if ($name === 'replay') {
            $args['identity'] = self::pick($rng, [null, 'exact', 'other']);
        }
        if ($name === 'release') {
            $args['owner'] = self::pick($rng, ['held', 'foreign']);
        }

        return [$name, $args];
    }

    /** @param list<mixed> $choices */
    private static function pick(int &$rng, array $choices): mixed
    {
        $rng = (1103515245 * $rng + 12345) & 0x7fffffff;

        return $choices[$rng % \count($choices)];
    }
}
