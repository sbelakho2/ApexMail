<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use PHPUnit\Framework\Assert;

/**
 * The model-checking walk driver: replays a transition sequence against
 * the clean-room {@see ChainModel} and a concrete
 * {@see ChainStoreDriver} (the in-memory or the real-Redis Lua store)
 * in lockstep. It asserts outcome parity and the invariant suite after
 * every step:
 *
 *  - outcome parity: the concrete store returns exactly the abstract
 *    model's outcome for the same transition and arguments.
 *  - the invariant suite of ChainModel::assertInvariants() (single-use
 *    per challenge, no double success, no mint on a consumed chain,
 *    expiry, terminal absorption, obligation lifecycle, schema,
 *    identity, monotone rank floor).
 *  - concrete-state equality: the stored record (state, owner, nonce,
 *    rank, lease, obligation mapping) equals the model configuration.
 *
 * The sequence generator is a fixed-seed LCG, so every run of a given
 * seed replays the identical walk (deterministic model checking). The
 * walk mints a fresh chain generation whenever a create-or-get finds
 * the obligation absent (the expired/stale-repair path), exactly like
 * the ticket service with its fresh random chain ids.
 */
final class ChainStateWalk
{
    /** The canonical stage-1 nonce (a valid Kiwi base64 challenge nonce). */
    public const S1_NONCE = '1/rjkTf+s+7yxIG1bxydPkq6IDlWiXESiMJQ0CYDhx8=';

    /** The chainable action of the walk's two rank rungs. */
    public const RANKS = [1 => 'sha16', 6 => 'argon64'];

    /** The walk's obligation id (64 lowercase hex, the chain's own). */
    public const OBLIGATION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** A foreign obligation id (never the chain's own). */
    public const OTHER_OBLIGATION = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** The two reservation owners. */
    public const OWNERS = ['owner-token-a', 'owner-token-b'];

    /** The two stage-2 nonces (valid Kiwi base64 challenge nonces). */
    public const NONCES = [
        '7yyCtGa+Du+1gDpcTduhUIavLPMoj+Eu63fm5IfimbE=',
        'sOPHfcnfrgohVECdEYhDGndY8nEBLX75qa8B7OJhEaU=',
    ];

    /**
     * The deterministic bounded random-walk step list for a seed.
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
     * Run the walk: every step is applied to the abstract model and to
     * the concrete driver, with the invariant + parity + state-equality
     * assertions after each step.
     *
     * @param list<array{0: string, 1: array<string, mixed>}> $steps
     *
     * @return array{steps: int, generations: int}
     */
    public static function run(string $context, ChainStoreDriver $driver, array $steps): array
    {
        $model = ChainModel::fresh(self::OBLIGATION);
        $chainId = 'chain-initial';
        $obligationId = self::OBLIGATION;
        $generation = 0;
        $applied = 0;
        foreach ($steps as [$name, $args]) {
            ++$applied;
            $chainId = self::applyStep($context, $driver, $model, $chainId, $obligationId, $name, $args, $generation);
            self::assertConcreteMatchesModel($context, $driver, $model, $chainId, $obligationId);
        }

        return ['steps' => $applied, 'generations' => $generation];
    }

    /**
     * Apply one step to the model and the store, asserting outcome parity
     * and the invariant suite. Returns the (possibly fresh-generation)
     * chain id; on a fresh generation the model is replaced by a new
     * generation instance. The concrete old record survives untouched at
     * its own chain id, exactly like the ticket service mints a fresh
     * random chain id per generation.
     *
     * @param array<string, mixed> $args
     */
    private static function applyStep(string $context, ChainStoreDriver $driver, ChainModel &$model, string $chainId, string $obligationId, string $name, array $args, int &$generation): string
    {
        if ($name === 'advanceLease') {
            if ($driver->advanceLease($chainId)) {
                $before = clone $model;
                $model->apply('advanceLease', []);
                ChainModel::assertInvariants($before, $model, null, 'advanceLease', [], $context);
            }

            return $chainId;
        }
        if ($name === 'expire') {
            if ($driver->expireChain($chainId, $obligationId)) {
                $before = clone $model;
                $model->apply('expire', []);
                ChainModel::assertInvariants($before, $model, null, 'expire', [], $context);
            }

            return $chainId;
        }
        if ($name === 'createOrGet') {
            $mapped = $driver->obligationChainId($obligationId);
            if ($mapped !== $chainId) {
                // Fresh generation: the chain is absent (expired) or the
                // mapping is gone (compare-deleted). The walk repairs it
                // with a fresh chain id, exactly like the ticket service;
                // the prior generation is sealed by its per-step invariant
                // checks and its concrete record (terminal or otherwise)
                // survives untouched — the model must never mutate it.
                Assert::assertNull($mapped, $context.': the walk never repoints a live obligation');
                $pre = ChainModel::fresh($obligationId);
                $fresh = clone $pre;
                $expected = $fresh->apply('createOrGet', $args);
                Assert::assertSame('created', $expected, $context.': a missing obligation creates a fresh chain');
                ChainModel::assertInvariants($pre, $fresh, $expected, 'createOrGet', $args, $context);
                $model = $fresh;
                $chainId = 'chain-gen-'.(string) (++$generation);
                $actual = $driver->createOrGet($chainId, $obligationId, $args['rank'], $driver->now() + 300);
                Assert::assertSame($chainId, $actual, $context.': the fresh create returns the new chain id');

                return $chainId;
            }
            $before = clone $model;
            $expected = $model->apply('createOrGet', $args);
            Assert::assertSame('existing', $expected, $context.': a live obligation returns the existing chain');
            $actual = $driver->createOrGet($chainId, $obligationId, $args['rank'], $driver->now() + 300);
            Assert::assertSame($chainId, $actual, $context.': the create-or-get recovery returns the same chain id');
            ChainModel::assertInvariants($before, $model, $expected, 'createOrGet', $args, $context);

            return $chainId;
        }
        $before = clone $model;
        $expected = $model->apply($name, $args);
        if ($name === 'complete') {
            $actual = $driver->complete($chainId, $args['owner'], $args['nonce']);
            Assert::assertSame($expected === 'completed', $actual !== null, $context.': the legacy completion parity');
        } else {
            $actual = self::storeOutcome($driver, $name, $chainId, $obligationId, $args);
            Assert::assertSame($expected, $actual, $context.sprintf(': outcome parity for %s(%s)', $name, json_encode($args, JSON_THROW_ON_ERROR)));
        }
        ChainModel::assertInvariants($before, $model, $expected, $name, $args, $context);

        return $chainId;
    }

    /**
     * @param array<string, mixed> $args
     */
    private static function storeOutcome(ChainStoreDriver $driver, string $name, string $chainId, string $obligationId, array $args): mixed
    {
        return match ($name) {
            'reserve' => $driver->reserve($chainId, $args['owner']),
            'release' => $driver->release($chainId, $args['owner']),
            'markIssued' => $driver->markIssued($chainId, $args['owner'], $args['nonce']),
            'markVerified' => $driver->markVerified($chainId, $args['nonce']),
            'markStepUpRequired' => $driver->markStepUpRequired($chainId, $args['nonce']),
            'markDenied' => $driver->markDenied($chainId, $args['nonce']),
            'markTransactionDenied' => $driver->markTransactionDenied($chainId, $args['obligationId']),
            'markTransactionStepUpRequired' => $driver->markTransactionStepUpRequired($chainId, $args['obligationId']),
            'rearmIssued' => $driver->rearmIssued($chainId, $args['nonce']),
            'deleteObligation' => $driver->deleteObligation($chainId, $obligationId),
            default => throw new \LogicException(sprintf('unknown walk transition %s', $name)),
        };
    }

    /**
     * The concrete record (or absence) must equal the abstract
     * configuration field by field after every step.
     */
    public static function assertConcreteMatchesModel(string $context, ChainStoreDriver $driver, ChainModel $model, string $chainId, string $obligationId): void
    {
        $record = $driver->read($chainId);
        if ($model->state === ChainModel::ABSENT) {
            Assert::assertNull($record, $context.': an absent model chain has no record');
            if (!$model->obligationPresent) {
                Assert::assertNull($driver->obligationChainId($obligationId), $context.': an absent model chain has no obligation mapping');
            }

            return;
        }
        Assert::assertIsArray($record, $context.': a live model chain has a record');
        // The legacy 'completed' state is the historical name of 'issued'
        // (the semantic alias the model folds).
        $recordState = $record['state'] === 'completed' ? 'issued' : $record['state'];
        Assert::assertSame($model->state, $recordState, $context.': the concrete state equals the model state');
        Assert::assertSame($model->owner, $record['owner'], $context.': the concrete owner equals the model owner');
        Assert::assertSame($model->nonce, $record['stage2Nonce'], $context.': the concrete stage-2 nonce equals the model nonce');
        Assert::assertSame($model->rank, $record['requiredRank'], $context.': the concrete required rank equals the model rank');
        Assert::assertSame(self::RANKS[$model->rank], $record['requiredAction'], $context.': the concrete required action matches the rank');
        Assert::assertSame(2, $record['chainDepth'], $context.': the chain depth is exactly 2');
        Assert::assertSame('login', $record['scope'], $context.': the scope is immutable');
        Assert::assertSame('txn-alpha', $record['requestBinding'], $context.': the authoritative binding is immutable');
        Assert::assertSame(1, $record['policyVersion'], $context.': the policy epoch is immutable');
        Assert::assertSame($model->obligationId, $record['obligationId'], $context.': the obligation id is immutable');
        if ($record['state'] === 'reserved') {
            Assert::assertNotNull($record['leaseUntil'], $context.': a reserved record carries a lease');
            Assert::assertSame($model->leaseLive, $record['leaseUntil'] > $driver->now(), $context.': the concrete lease liveness equals the model lease liveness');
        } else {
            Assert::assertNull($record['leaseUntil'], $context.': the lease is cleared outside the reserved state');
        }
        Assert::assertSame($model->obligationPresent, $driver->obligationChainId($obligationId) === $chainId, $context.': the concrete obligation mapping equals the model mapping');
    }

    /**
     * @return array{0: string, 1: array<string, mixed>} one weighted-random step
     */
    private static function step(int &$rng): array
    {
        $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
        $pick = $rng % 100;
        $name = match (true) {
            $pick < 10 => 'createOrGet',
            $pick < 25 => 'reserve',
            $pick < 33 => 'release',
            $pick < 48 => 'markIssued',
            $pick < 58 => 'markVerified',
            $pick < 66 => 'markStepUpRequired',
            $pick < 74 => 'markDenied',
            $pick < 80 => 'markTransactionDenied',
            $pick < 86 => 'markTransactionStepUpRequired',
            $pick < 93 => 'rearmIssued',
            $pick < 96 => 'deleteObligation',
            $pick < 98 => 'advanceLease',
            default => 'expire',
        };
        $args = [];
        if (\in_array($name, ['reserve', 'release', 'markIssued'], true)) {
            $args['owner'] = self::pick($rng, self::OWNERS);
        }
        if (\in_array($name, ['markIssued', 'markVerified', 'markStepUpRequired', 'markDenied', 'rearmIssued'], true)) {
            $args['nonce'] = self::pick($rng, self::NONCES);
        }
        if (\in_array($name, ['markTransactionDenied', 'markTransactionStepUpRequired'], true)) {
            $args['obligationId'] = self::pick($rng, [self::OBLIGATION, self::OTHER_OBLIGATION]);
        }
        if ($name === 'createOrGet') {
            $args['rank'] = self::pick($rng, [1, 6]);
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
