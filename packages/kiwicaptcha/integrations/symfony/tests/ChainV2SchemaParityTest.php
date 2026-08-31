<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainV2LuaPredicate;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use PHPUnit\Framework\TestCase;

/**
 * Differential schema parity: every record in the malformed and valid
 * corpus must produce identical accept and reject outcomes from the
 * strict PHP decoder and from the Lua predicate every Redis
 * authorization and transition boundary runs. The R76 adversarial tests proved a
 * hand-picked subset; this corpus proves actual schema equivalence
 * across types, patterns, alphabet/length rules, the action -> rank
 * table and the state-dependent invariants.
 *
 * The corpus is generated, not hand-listed: the valid v2 record plus
 * every single-field mutation (wrong type, wrong value, wrong shape,
 * wrong state-dependent invariant, missing field, null field). The one
 * representational edge Lua 5.1 cannot express (an integral float like
 * 2.0, which cjson decodes as the number 2 while PHP's json_decode
 * yields a float) is documented in {@see ChainV2LuaPredicate} and
 * excluded; the canonical writers never emit float literals.
 */
final class ChainV2SchemaParityTest extends TestCase
{
    private const NAMESPACE = 'ci-schema-parity';

    private const VALID_NONCE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ=';

    private const VALID_BINDING = 'auth';

    private const VALID_OBLIGATION = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    private \Predis\Client $client;

    private RedisChainedChallengeStateStore $store;

    protected function setUp(): void
    {
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client(self::redisUrl());
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.self::redisUrl().': '.$e->getMessage());
        }
        $this->client->flushdb();
        $this->store = new RedisChainedChallengeStateStore($this->client, self::NAMESPACE);
    }

    private static function redisUrl(): string
    {
        $env = getenv('KC_REDIS_URL');
        if (\is_string($env) && $env !== '') {
            return $env;
        }
        $env = getenv('TEST_REDIS_URL');
        if (\is_string($env) && $env !== '') {
            return $env;
        }

        return 'redis://127.0.0.1:6399';
    }

    private function validRecord(array $overrides = []): array
    {
        return array_replace([
            'v' => 2,
            'stage1Nonce' => self::VALID_NONCE,
            'scope' => 'login',
            'obligationId' => self::VALID_OBLIGATION,
            'requiredAction' => 'sha20',
            'requiredRank' => 3,
            'policyVersion' => 1,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => self::VALID_BINDING,
            'expiresAt' => time() + 300,
        ], $overrides);
    }

    /**
     * @return list<array{0: string, 1: array<string, mixed>}> the corpus:
     *         name + record
     */
    private function corpus(): array
    {
        $records = [['valid-available', $this->validRecord()]];
        $records[] = ['valid-reserved', $this->validRecord(['state' => 'reserved', 'owner' => 'owner-a', 'leaseUntil' => time() + 30])];
        $records[] = ['valid-issued', $this->validRecord(['state' => 'issued', 'stage2Nonce' => self::VALID_NONCE])];
        $records[] = ['valid-verified', $this->validRecord(['state' => 'verified', 'stage2Nonce' => self::VALID_NONCE])];
        $records[] = ['valid-completed', $this->validRecord(['state' => 'completed', 'stage2Nonce' => self::VALID_NONCE])];
        $records[] = ['valid-stepup-with-nonce', $this->validRecord(['state' => 'step_up_required', 'stage2Nonce' => self::VALID_NONCE])];
        $records[] = ['valid-stepup-null-nonce', $this->validRecord(['state' => 'step_up_required'])];
        $records[] = ['valid-denied-with-nonce', $this->validRecord(['state' => 'denied', 'stage2Nonce' => self::VALID_NONCE])];
        $records[] = ['valid-denied-null-nonce', $this->validRecord(['state' => 'denied'])];
        $records[] = ['valid-null-binding', $this->validRecord(['requestBinding' => null])];
        $records[] = ['valid-all-actions', $this->validRecord(['requiredAction' => 'sha16', 'requiredRank' => 1])];
        $records[] = ['valid-all-actions', $this->validRecord(['requiredAction' => 'sha18', 'requiredRank' => 2])];
        $records[] = ['valid-all-actions', $this->validRecord(['requiredAction' => 'argon16', 'requiredRank' => 4])];
        $records[] = ['valid-all-actions', $this->validRecord(['requiredAction' => 'argon32', 'requiredRank' => 5])];
        $records[] = ['valid-all-actions', $this->validRecord(['requiredAction' => 'argon64', 'requiredRank' => 6])];

        // Single-field corruptions: wrong type, wrong shape, wrong value.
        $corrupt = [
            ['v-string', ['v' => '2']],
            ['v-wrong', ['v' => 3]],
            ['v-null', ['v' => null]],
            ['v-float', ['v' => 2.5]],
            ['v-missing', ['v' => 'REMOVE']],
            ['chainDepth-string', ['chainDepth' => '2']],
            ['chainDepth-wrong', ['chainDepth' => 3]],
            ['chainDepth-null', ['chainDepth' => null]],
            ['chainDepth-missing', ['chainDepth' => 'REMOVE']],
            ['nonce-short', ['stage1Nonce' => 'abc']],
            ['nonce-long', ['stage1Nonce' => str_repeat('a', 45)]],
            ['nonce-no-pad', ['stage1Nonce' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX01']],
            ['nonce-bad-char', ['stage1Nonce' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0!']],
            ['nonce-empty', ['stage1Nonce' => '']],
            ['nonce-int', ['stage1Nonce' => 42]],
            ['nonce-null', ['stage1Nonce' => null]],
            ['nonce-missing', ['stage1Nonce' => 'REMOVE']],
            ['scope-empty', ['scope' => '']],
            ['scope-long', ['scope' => str_repeat('a', 129)]],
            ['scope-bad-char', ['scope' => 'log in']],
            ['scope-int', ['scope' => 7]],
            ['scope-null', ['scope' => null]],
            ['scope-missing', ['scope' => 'REMOVE']],
            ['obligation-short', ['obligationId' => 'abc']],
            ['obligation-uppercase', ['obligationId' => strtoupper(self::VALID_OBLIGATION)]],
            ['obligation-bad-char', ['obligationId' => str_repeat('g', 64)]],
            ['obligation-empty', ['obligationId' => '']],
            ['obligation-int', ['obligationId' => 64]],
            ['obligation-null', ['obligationId' => null]],
            ['obligation-missing', ['obligationId' => 'REMOVE']],
            ['action-unknown', ['requiredAction' => 'not-a-real-action', 'requiredRank' => 3]],
            ['action-allow', ['requiredAction' => 'allow', 'requiredRank' => 0]],
            ['action-stepup', ['requiredAction' => 'step_up', 'requiredRank' => 7]],
            ['action-denied', ['requiredAction' => 'deny', 'requiredRank' => 8]],
            ['action-empty', ['requiredAction' => '']],
            ['action-int', ['requiredAction' => 3]],
            ['action-null', ['requiredAction' => null]],
            ['action-missing', ['requiredAction' => 'REMOVE']],
            ['rank-float', ['requiredAction' => 'sha20', 'requiredRank' => 3.5]],
            ['rank-string', ['requiredAction' => 'sha20', 'requiredRank' => '3']],
            ['rank-mismatch-high', ['requiredAction' => 'sha20', 'requiredRank' => 4]],
            ['rank-mismatch-low', ['requiredAction' => 'sha20', 'requiredRank' => 2]],
            ['rank-zero', ['requiredAction' => 'sha20', 'requiredRank' => 0]],
            ['rank-null', ['requiredRank' => null]],
            ['rank-missing', ['requiredRank' => 'REMOVE']],
            ['policy-zero', ['policyVersion' => 0]],
            ['policy-negative', ['policyVersion' => -1]],
            ['policy-float', ['policyVersion' => 1.5]],
            ['policy-string', ['policyVersion' => '1']],
            ['policy-null', ['policyVersion' => null]],
            ['policy-missing', ['policyVersion' => 'REMOVE']],
            ['state-unknown', ['state' => 'unexpected-state']],
            ['state-uppercase', ['state' => 'Available']],
            ['state-empty', ['state' => '']],
            ['state-int', ['state' => 2]],
            ['state-null', ['state' => null]],
            ['state-missing', ['state' => 'REMOVE']],
            ['reserved-no-owner', ['state' => 'reserved', 'leaseUntil' => time() + 30]],
            ['reserved-empty-owner', ['state' => 'reserved', 'owner' => '', 'leaseUntil' => time() + 30]],
            ['reserved-float-lease', ['state' => 'reserved', 'owner' => 'owner-a', 'leaseUntil' => time() + 30.5]],
            ['reserved-string-lease', ['state' => 'reserved', 'owner' => 'owner-a', 'leaseUntil' => '123']],
            ['reserved-null-lease', ['state' => 'reserved', 'owner' => 'owner-a', 'leaseUntil' => null]],
            ['reserved-lease-missing', ['state' => 'reserved', 'owner' => 'owner-a', 'leaseUntil' => 'REMOVE']],
            ['available-with-owner', ['owner' => 'owner-a']],
            ['available-with-lease', ['leaseUntil' => time() + 30]],
            ['available-with-nonce', ['stage2Nonce' => self::VALID_NONCE]],
            ['issued-null-nonce', ['state' => 'issued', 'stage2Nonce' => null]],
            ['issued-string-flag', ['state' => 'issued', 'stage2Nonce' => 'flag']],
            ['issued-short-nonce', ['state' => 'issued', 'stage2Nonce' => 'abc']],
            ['issued-nonce-missing', ['state' => 'issued', 'stage2Nonce' => 'REMOVE']],
            ['verified-float-nonce', ['state' => 'verified', 'stage2Nonce' => 42]],
            ['completed-bad-nonce', ['state' => 'completed', 'stage2Nonce' => 'x']],
            ['stepup-float-nonce', ['state' => 'step_up_required', 'stage2Nonce' => 42]],
            ['denied-float-nonce', ['state' => 'denied', 'stage2Nonce' => 42]],
            ['binding-empty', ['requestBinding' => '']],
            ['binding-long', ['requestBinding' => str_repeat('a', 129)]],
            ['binding-bad-char', ['requestBinding' => 'au th']],
            ['binding-int', ['requestBinding' => 42]],
            ['binding-float-nonce', ['requestBinding' => 42.5]],
            ['unknown-key', ['extraField' => 'x']],
            ['renamed-binding-key', ['requestBInding' => self::VALID_BINDING]],
            ['unknown-key-with-valid-shape', ['requestBinding' => self::VALID_BINDING, 'newField' => 1]],
            ['expires-float', ['expiresAt' => time() + 300.5]],
            ['expires-string', ['expiresAt' => '1700000000']],
            ['expires-null', ['expiresAt' => null]],
            ['expires-missing', ['expiresAt' => 'REMOVE']],
        ];

        foreach ($corrupt as [$name, $overrides]) {
            $record = $this->validRecord($overrides);
            if (($overrides['v'] ?? null) === 'REMOVE') {
                unset($record['v']);
            }
            if (($overrides['chainDepth'] ?? null) === 'REMOVE') {
                unset($record['chainDepth']);
            }
            if (($overrides['stage1Nonce'] ?? null) === 'REMOVE') {
                unset($record['stage1Nonce']);
            }
            if (($overrides['scope'] ?? null) === 'REMOVE') {
                unset($record['scope']);
            }
            if (($overrides['obligationId'] ?? null) === 'REMOVE') {
                unset($record['obligationId']);
            }
            if (($overrides['requiredAction'] ?? null) === 'REMOVE') {
                unset($record['requiredAction']);
            }
            if (($overrides['requiredRank'] ?? null) === 'REMOVE') {
                unset($record['requiredRank']);
            }
            if (($overrides['policyVersion'] ?? null) === 'REMOVE') {
                unset($record['policyVersion']);
            }
            if (($overrides['state'] ?? null) === 'REMOVE') {
                unset($record['state']);
            }
            if (($overrides['leaseUntil'] ?? null) === 'REMOVE') {
                unset($record['leaseUntil']);
            }
            if (($overrides['stage2Nonce'] ?? null) === 'REMOVE') {
                unset($record['stage2Nonce']);
            }
            if (($overrides['expiresAt'] ?? null) === 'REMOVE') {
                unset($record['expiresAt']);
            }
            $records[] = [$name, $record];
        }

        return $records;
    }

    /**
     * The Lua side of the differential test: the predicate itself runs
     * against the real Redis Lua runtime, exactly as every transition
     * boundary runs it.
     */
    private function luaAccepts(array $record): bool
    {
        $script = ChainV2LuaPredicate::LUA."\nreturn isValidChainRecord(cjson.decode(ARGV[1])) and 'accept' or 'reject'";
        $raw = (string) json_encode($record, JSON_THROW_ON_ERROR);
        $result = $this->client->eval($script, 1, 'parity-key', $raw);

        return $result === 'accept';
    }

    /**
     * The PHP side: the strict decoder, exactly as read()/assertLiveRecord()
     * run it (MalformedChainedChallengeStateException on any corruption).
     */
    private function phpAccepts(array $record): bool
    {
        $chainId = 'parity-chain-'.$this->corpusIndex;
        try {
            $this->store->create($chainId, self::VALID_NONCE, 'login', 300, self::VALID_BINDING, 'sha20', 1);
        } catch (\Throwable) {
            // ignore: the seed write only needs the key namespace warm.
        }
        $key = '{kiwi:'.self::NAMESPACE.'}:chain:'.$chainId;
        $this->client->set($key, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);
        try {
            $this->store->read($chainId);
        } catch (MalformedChainedChallengeStateException) {
            return false;
        }

        return true;
    }

    private int $corpusIndex = 0;

    public function testEveryCorpusRecordGetsIdenticalPhpAndLuaOutcomes(): void
    {
        $mismatches = [];
        $count = 0;
        $phpAccepted = 0;
        foreach ($this->corpus() as [$name, $record]) {
            ++$count;
            ++$this->corpusIndex;
            $lua = $this->luaAccepts($record);
            $php = $this->phpAccepts($record);
            if ($php) {
                ++$phpAccepted;
            }
            if ($lua !== $php) {
                $mismatches[] = sprintf('%s: php=%s lua=%s', $name, $php ? 'accept' : 'reject', $lua ? 'accept' : 'reject');
            }
        }
        self::assertSame([], $mismatches, sprintf('PHP and Lua schema validation diverge on %d of %d corpus records', \count($mismatches), $count));
        self::assertGreaterThan(60, $count, 'the corpus must cover a wide mutation surface');
        self::assertGreaterThan(10, $phpAccepted, 'the corpus must include a meaningful set of valid records accepted by both sides');
        self::assertGreaterThan(50, $count - $phpAccepted, 'the corpus must also reject a wide corruption surface on both sides');
    }
}
