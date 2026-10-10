<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\MalformedPostSolveDispositionException;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionLuaPredicate;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use PHPUnit\Framework\TestCase;

/**
 * Differential schema parity for the post-solve disposition record.
 * Every corpus record must produce identical accept and reject
 * outcomes. The two sides are the strict PHP decoder
 * ({@see RedisPostSolveDispositionStore}, the read path) and the Lua
 * predicate every Redis transition and replay boundary runs
 * ({@see PostSolveDispositionLuaPredicate}).
 *
 * The corpus is generated, not hand-listed: valid pending/complete
 * records plus every single-field mutation (wrong type, wrong shape,
 * missing field, null field) and the full kind <-> chain_id <->
 * chain_expires_at matrix, v1 legacy / v2 included. The one
 * representational edge Lua 5.1 cannot express (an integral float like
 * 2.0, which cjson decodes as the number 2 while PHP's json_decode
 * yields a float) is excluded; the canonical writers never emit float
 * literals.
 */
final class PostSolveDispositionSchemaParityTest extends TestCase
{
    private const NAMESPACE = 'ci-postsolve-parity';

    private const CHAIN_ID = 'AbC-123_base64url';

    private \Predis\Client $client;

    private RedisPostSolveDispositionStore $store;

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $url = RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable at '.$url.': '.$e->getMessage());
        }
        $this->client->flushdb();
        $this->store = new RedisPostSolveDispositionStore($this->client, self::NAMESPACE);
    }

    /** @param array<string, mixed> $overrides */
    private function pending(array $overrides = []): array
    {
        return array_replace([
            'v' => 1,
            'state' => 'pending',
            'owner' => 'owner-a',
            'lease_until' => time() + 15,
            'disposition' => null,
            'decision_id' => null,
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $dispOverrides
     * @param array<string, mixed> $recordOverrides
     */
    private function complete(array $dispOverrides = [], array $recordOverrides = []): array
    {
        return array_replace([
            'v' => 1,
            'state' => 'complete',
            'owner' => null,
            'lease_until' => null,
            'disposition' => array_replace([
                'kind' => 'pass',
                'decision_id' => null,
                'chain_id' => null,
                'chain_expires_at' => null,
            ], $dispOverrides),
            'decision_id' => null,
        ], $recordOverrides);
    }

    /** @return list<array{0: string, 1: array<string, mixed>}> */
    private function corpus(): array
    {
        $records = [
            ['valid-pending', $this->pending()],
            ['valid-pending-decision', $this->pending(['decision_id' => 'decision-1'])],
            ['valid-complete-pass', $this->complete()],
            ['valid-complete-deny', $this->complete(['kind' => 'deny'])],
            ['valid-complete-step-up', $this->complete(['kind' => 'step_up'])],
            ['valid-complete-pass-decision', $this->complete(['decision_id' => 'decision-1'], ['decision_id' => 'record-decision'])],
            ['valid-chain-required-v1-expiry', $this->complete(['kind' => 'chain_required', 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => time() + 300])],
            ['valid-chain-required-v1-legacy-null-expiry', $this->complete(['kind' => 'chain_required', 'chain_id' => self::CHAIN_ID])],
            ['valid-chain-required-v2-expiry', $this->complete(['kind' => 'chain_required', 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => time() + 300], ['v' => 2])],
            // The additive quarantine flag: written only when true, valid
            // only on the pass kind (change.md 1.3 and 3.3.4).
            ['valid-complete-pass-quarantined', $this->complete(['quarantined' => true])],
            ['valid-complete-pass-quarantined-v2', $this->complete(['quarantined' => true], ['v' => 2])],
        ];

        $corrupt = [
            ['v-string', ['v' => '1']],
            ['v-wrong', ['v' => 3]],
            ['v-null', ['v' => null]],
            ['state-unknown', ['state' => 'quantum']],
            ['state-uppercase', ['state' => 'Pending']],
            ['state-int', ['state' => 1]],
            ['state-null', ['state' => null]],
            ['pending-no-owner', ['owner' => null]],
            ['pending-empty-owner', ['owner' => '']],
            ['pending-int-owner', ['owner' => 7]],
            ['pending-null-lease', ['lease_until' => null]],
            ['pending-string-lease', ['lease_until' => '123']],
            ['pending-disposition', ['disposition' => ['kind' => 'pass']]],
            ['pending-decision-int', ['decision_id' => 7]],
            ['pending-decision-empty', ['decision_id' => '']],
            ['unknown-record-key', ['extra' => 'x']],
            ['complete-owner', ['owner' => 'stale-owner']],
            ['complete-lease', ['lease_until' => 123]],
            ['complete-missing-disposition', ['disposition' => null]],
            ['complete-disposition-string', ['disposition' => 'pass']],
            ['complete-disposition-empty', ['disposition' => []]],
            ['kind-unknown', ['disposition' => ['kind' => 'allow', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null]]],
            ['kind-missing', ['disposition' => ['decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null]]],
            ['kind-int', ['disposition' => ['kind' => 1, 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null]]],
            ['nested-unknown-key', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'extra' => 1]]],
            // The quarantine flag's corruption surface: a non-boolean
            // value, a false that the writers never emit, and the flag
            // on every kind the severity rule forbids.
            ['quarantined-string', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => 'yes']]],
            ['quarantined-int', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => 1]]],
            ['quarantined-false', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => false]]],
            ['quarantined-null-explicit', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => null]]],
            ['quarantined-on-deny', ['disposition' => ['kind' => 'deny', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => true]]],
            ['quarantined-on-step-up', ['disposition' => ['kind' => 'step_up', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => null, 'quarantined' => true]]],
            ['quarantined-on-chain-required', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => time() + 300, 'quarantined' => true]]],
            ['nested-decision-int', ['disposition' => ['kind' => 'pass', 'decision_id' => 7, 'chain_id' => null, 'chain_expires_at' => null]]],
            ['nested-decision-empty', ['disposition' => ['kind' => 'pass', 'decision_id' => '', 'chain_id' => null, 'chain_expires_at' => null]]],
            // The kind <-> chain_id <-> chain_expires_at matrix.
            ['pass-with-chain-id', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => null]]],
            ['deny-with-chain-id', ['disposition' => ['kind' => 'deny', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => null]]],
            ['step-up-with-chain-id', ['disposition' => ['kind' => 'step_up', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => null]]],
            ['pass-with-chain-expiry', ['disposition' => ['kind' => 'pass', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => time() + 300]]],
            ['chain-required-without-chain-id', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => null, 'chain_expires_at' => time() + 300]]],
            ['chain-required-empty-chain-id', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => '', 'chain_expires_at' => time() + 300]]],
            ['chain-required-bad-chain-id-char', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => 'bad chain!', 'chain_expires_at' => time() + 300]]],
            ['chain-required-long-chain-id', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => str_repeat('a', 65), 'chain_expires_at' => time() + 300]]],
            ['chain-required-int-chain-id', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => 7, 'chain_expires_at' => time() + 300]]],
            ['chain-required-zero-expiry', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => 0]]],
            ['chain-required-negative-expiry', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => -5]]],
            ['chain-required-string-expiry', ['disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => '1700000000']]],
            ['chain-required-v2-null-expiry', ['v' => 2, 'disposition' => ['kind' => 'chain_required', 'decision_id' => null, 'chain_id' => self::CHAIN_ID, 'chain_expires_at' => null]]],
            ['complete-decision-int', ['decision_id' => 7]],
            ['complete-decision-empty', ['decision_id' => '']],
        ];

        foreach ($corrupt as [$name, $overrides]) {
            if (\array_key_exists('disposition', $overrides)) {
                $record = array_replace($this->complete(), ['disposition' => $overrides['disposition']], array_diff_key($overrides, ['disposition' => true]));
            } else {
                $record = $this->pending($overrides);
            }
            $records[] = [$name, $record];
        }

        // The same single-field mutations against the complete-pass base.
        foreach ($corrupt as [$name, $overrides]) {
            if (\array_key_exists('disposition', $overrides) || \array_key_exists('state', $overrides)) {
                continue;
            }
            $record = $this->complete([], $overrides);
            $records[] = ['complete-'.$name, $record];
        }

        // Missing-field shapes: PHP's `?? null` and the Lua nil checks
        // must agree on absence exactly like on explicit null.
        $records[] = ['pending-without-v', array_diff_key($this->pending(), ['v' => true])];
        $records[] = ['pending-without-lease', array_diff_key($this->pending(), ['lease_until' => true])];
        $records[] = ['pending-without-disposition', array_diff_key($this->pending(), ['disposition' => true])];
        $records[] = ['complete-without-owner', array_diff_key($this->complete(), ['owner' => true])];
        $records[] = ['complete-without-lease', array_diff_key($this->complete(), ['lease_until' => true])];
        $records[] = ['complete-without-disposition', array_diff_key($this->complete(), ['disposition' => true])];
        $records[] = ['complete-without-decision', array_diff_key($this->complete(), ['decision_id' => true])];
        $withoutExpiryKey = $this->complete(['kind' => 'chain_required', 'chain_id' => self::CHAIN_ID]);
        unset($withoutExpiryKey['disposition']['chain_expires_at']);
        $records[] = ['chain-required-without-expiry-key', $withoutExpiryKey];
        $v2WithoutExpiryKey = $this->complete(['kind' => 'chain_required', 'chain_id' => self::CHAIN_ID], ['v' => 2]);
        unset($v2WithoutExpiryKey['disposition']['chain_expires_at']);
        $records[] = ['v2-chain-required-without-expiry-key', $v2WithoutExpiryKey];
        $records[] = ['valid-v2-pending', $this->pending(['v' => 2])];
        $records[] = ['valid-v2-complete', $this->complete([], ['v' => 2])];
        // Absence of the quarantine key is the earlier record shape and
        // must decode as a non-quarantined pass on both sides.
        $withoutQuarantineKey = $this->complete(['quarantined' => true]);
        unset($withoutQuarantineKey['disposition']['quarantined']);
        $records[] = ['complete-pass-without-quarantine-key', $withoutQuarantineKey];

        return $records;
    }

    private function luaAccepts(array $record): bool
    {
        $script = PostSolveDispositionLuaPredicate::LUA."\nreturn validPostSolveRecord(cjson.decode(ARGV[1])) and 'accept' or 'reject'";
        $raw = (string) json_encode($record, JSON_THROW_ON_ERROR);
        $result = $this->client->eval($script, 1, 'parity-key', $raw);

        return $result === 'accept';
    }

    private function phpAccepts(array $record, int $index): bool
    {
        $nonce = 'parity-'.$index;
        $key = '{kiwi:'.self::NAMESPACE.'}:postsolve:'.$nonce;
        $this->client->set($key, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', 300);
        try {
            $this->store->read($nonce);

            return true;
        } catch (MalformedPostSolveDispositionException) {
            return false;
        }
    }

    public function testEveryCorpusRecordGetsIdenticalPhpAndLuaOutcomes(): void
    {
        $mismatches = [];
        $count = 0;
        $accepted = 0;
        $index = 0;
        foreach ($this->corpus() as [$name, $record]) {
            ++$count;
            ++$index;
            $lua = $this->luaAccepts($record);
            $php = $this->phpAccepts($record, $index);
            if ($php) {
                ++$accepted;
            }
            if ($lua !== $php) {
                $mismatches[] = sprintf('%s: php=%s lua=%s', $name, $php ? 'accept' : 'reject', $lua ? 'accept' : 'reject');
            }
        }
        self::assertSame([], $mismatches, sprintf('PHP and Lua schema validation diverge on %d of %d corpus records', \count($mismatches), $count));
        self::assertGreaterThan(50, $count, 'the corpus must cover a wide mutation surface');
        self::assertGreaterThan(5, $accepted, 'the corpus must include a meaningful set of valid records accepted by both sides');
        self::assertGreaterThan(40, $count - $accepted, 'the corpus must also reject a wide corruption surface on both sides');
    }
}
