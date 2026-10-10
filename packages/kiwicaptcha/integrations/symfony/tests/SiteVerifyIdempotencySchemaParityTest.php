<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyLuaPredicate;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyIdempotencyRecordSchema;
use PHPUnit\Framework\TestCase;

/**
 * Differential schema parity for the SiteVerify idempotency record:
 * every corpus record must produce identical accept and reject outcomes
 * from the PHP schema
 * ({@see SiteVerifyIdempotencyRecordSchema}) and from the Lua predicate
 * every Redis transition and read boundary runs
 * ({@see SiteVerifyIdempotencyLuaPredicate}). The v2 shape and the
 * read-only legacy shape are both covered, with the canonical formats
 * (64-lowercase-hex response hash / fingerprint / binding, 32-hex
 * owner, positive integer lease) and the exact provider-result shapes.
 *
 * The one representational edge Lua 5.1 cannot express (an integral
 * float like 2.0, which cjson decodes as the number 2 while PHP's
 * json_decode yields a float) is excluded; the canonical writers never
 * emit float literals.
 */
final class SiteVerifyIdempotencySchemaParityTest extends TestCase
{
    private const HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const FINGERPRINT = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private const BINDING = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

    private const OWNER = 'dddddddddddddddddddddddddddddddd';

    /** @param array<string, mixed> $overrides */
    private function pending(array $overrides = []): array
    {
        return array_replace([
            'v' => 2,
            'state' => 'pending',
            'response_hash' => self::HASH,
            'remoteip_fingerprint' => self::FINGERPRINT,
            'binding' => self::BINDING,
            'owner' => self::OWNER,
            'lease_expires_at' => time() + 60,
            'result' => null,
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $resultOverrides
     * @param array<string, mixed> $recordOverrides
     */
    private function complete(array $resultOverrides = [], array $recordOverrides = []): array
    {
        return array_replace([
            'v' => 2,
            'state' => 'complete',
            'response_hash' => self::HASH,
            'remoteip_fingerprint' => self::FINGERPRINT,
            'binding' => self::BINDING,
            'owner' => null,
            'lease_expires_at' => null,
            'result' => array_replace([
                'success' => true,
                'challenge_ts' => null,
                'hostname' => null,
            ], $resultOverrides),
        ], $recordOverrides);
    }

    /** @param array<string, mixed> $overrides */
    private function legacy(array $overrides = []): array
    {
        $record = $this->pending([
            'remoteip_fingerprint' => null,
            'binding' => null,
        ]);
        unset($record['v']);

        return array_replace($record, $overrides);
    }

    /** @return list<array{0: string, 1: array<string, mixed>}> */
    private function corpus(): array
    {
        $records = [
            ['valid-v2-pending', $this->pending()],
            ['valid-v2-pending-no-ip', $this->pending(['remoteip_fingerprint' => 'no-ip'])],
            ['valid-v2-pending-unbound', $this->pending(['binding' => ''])],
            ['valid-v2-complete-minimal-success', $this->complete()],
            ['valid-v2-complete-full-success', $this->complete(['action' => 'login', 'cdata' => 'payload', 'error-codes' => []])],
            ['valid-v2-complete-null-fields-success', $this->complete(['challenge_ts' => null, 'hostname' => null, 'action' => null, 'cdata' => null, 'error-codes' => []])],
            ['valid-v2-complete-failure', $this->complete(['success' => false, 'error-codes' => ['timeout-or-duplicate']])],
            ['valid-legacy-pending', $this->legacy(),],
            ['valid-legacy-complete', $this->legacy(['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null]])],
        ];

        $corrupt = [
            ['v-missing', 'REMOVE_V'],
            ['v-wrong', ['v' => 1]],
            ['v-string', ['v' => '2']],
            ['response-hash-short', ['response_hash' => 'abc']],
            ['response-hash-uppercase', ['response_hash' => strtoupper(self::HASH)]],
            ['response-hash-int', ['response_hash' => 42]],
            ['response-hash-null', ['response_hash' => null]],
            ['response-hash-missing', 'REMOVE_RESPONSE_HASH'],
            ['fingerprint-short', ['remoteip_fingerprint' => 'fp']],
            ['fingerprint-int', ['remoteip_fingerprint' => 7]],
            ['fingerprint-null', ['remoteip_fingerprint' => null]],
            ['fingerprint-missing', 'REMOVE_FINGERPRINT'],
            ['binding-short', ['binding' => 'b']],
            ['binding-null', ['binding' => null]],
            ['binding-missing', 'REMOVE_BINDING'],
            ['owner-short', ['owner' => 'owner-a']],
            ['owner-int', ['owner' => 7]],
            ['owner-empty', ['owner' => '']],
            ['lease-zero', ['lease_expires_at' => 0]],
            ['lease-negative', ['lease_expires_at' => -5]],
            ['lease-string', ['lease_expires_at' => '123']],
            ['lease-null', ['lease_expires_at' => null]],
            ['state-unknown', ['state' => 'quantum']],
            ['state-null', ['state' => null]],
            ['pending-result', ['result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null]]],
            ['unknown-key', ['extra' => 'x']],
            ['result-missing', 'REMOVE_RESULT'],
            ['complete-owner', ['state' => 'complete', 'owner' => self::OWNER]],
            ['result-not-object', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => 'yes']],
            ['result-success-string', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => 'true', 'challenge_ts' => null, 'hostname' => null]]],
            ['result-success-four-keys', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null, 'action' => null]]],
            ['result-success-nonempty-codes', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['bad-request']]]],
            ['result-success-hostname-int', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => true, 'challenge_ts' => null, 'hostname' => 7]]],
            ['result-failure-two-codes', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['bad-request', 'internal-error']]]],
            ['result-failure-unknown-code', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => ['not-a-code']]]],
            ['result-failure-hostname-set', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => false, 'challenge_ts' => null, 'hostname' => 'example.com', 'error-codes' => ['bad-request']]]],
            ['result-failure-empty-codes', ['state' => 'complete', 'owner' => null, 'lease_expires_at' => null, 'result' => ['success' => false, 'challenge_ts' => null, 'hostname' => null, 'error-codes' => []]]],
            ['pending-result-key-set-six', ['result' => ['success' => true, 'challenge_ts' => null]]],
        ];

        foreach ($corrupt as [$name, $mutation]) {
            $record = $this->pending();
            if ($mutation === 'REMOVE_V') {
                unset($record['v']);
            } elseif ($mutation === 'REMOVE_RESPONSE_HASH') {
                unset($record['response_hash']);
            } elseif ($mutation === 'REMOVE_FINGERPRINT') {
                unset($record['remoteip_fingerprint']);
            } elseif ($mutation === 'REMOVE_BINDING') {
                unset($record['binding']);
            } elseif ($mutation === 'REMOVE_RESULT') {
                unset($record['result']);
            } else {
                $record = array_replace($record, $mutation);
            }
            $records[] = [$name, $record];
        }

        // The same corruptions against the legacy base: only the shape
        // rules the legacy reader enforces may reject.
        foreach ($corrupt as [$name, $mutation]) {
            if (\is_array($mutation) && \array_key_exists('v', $mutation)) {
                continue;
            }
            $record = $this->legacy();
            if ($mutation === 'REMOVE_V') {
                // already absent in the legacy shape
            } elseif ($mutation === 'REMOVE_RESPONSE_HASH') {
                unset($record['response_hash']);
            } elseif ($mutation === 'REMOVE_FINGERPRINT') {
                unset($record['remoteip_fingerprint']);
            } elseif ($mutation === 'REMOVE_BINDING') {
                unset($record['binding']);
            } elseif ($mutation === 'REMOVE_RESULT') {
                unset($record['result']);
            } else {
                $record = array_replace($record, $mutation);
            }
            $records[] = ['legacy-'.$name, $record];
        }

        return $records;
    }

    private function luaAccepts(\Predis\Client $client, array $record): bool
    {
        $script = SiteVerifyIdempotencyLuaPredicate::LUA."\nreturn classifyIdempotencyRecord(cjson.decode(ARGV[1])) ~= nil and 'accept' or 'reject'";
        $raw = (string) json_encode($record, JSON_THROW_ON_ERROR);

        return $client->eval($script, 1, 'parity-key', $raw) === 'accept';
    }

    private static function redisUrl(): string
    {
        $url = \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl::resolve();
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }

        return $url;
    }

    /**
     * Raw-JSON vectors (never PHP-array-generated): the JSON collection
     * representation of error-codes is part of the schema, and a decoded
     * PHP array can silently normalize shapes Lua sees distinctly. Each
     * vector is a complete record document fed verbatim to both sides.
     *
     * @return list<array{0: string, 1: string, 2: bool}> [name, record json, parity expected]
     */
    private function rawJsonCorpus(): array
    {
        $hash = str_repeat('a', 64);
        $prefix = '{"v":2,"state":"complete","response_hash":"'.$hash.'","remoteip_fingerprint":"no-ip","binding":"","owner":null,"lease_expires_at":null,"result":{"success":false,"challenge_ts":null,"hostname":null,"error-codes":';
        $suffix = '}}';

        return [
            ['raw-list-one', $prefix.'["bad-request"]'.$suffix, true],
            ['raw-object-key', $prefix.'{"x":"bad-request"}'.$suffix, true],
            ['raw-object-key-one', $prefix.'{"1":"bad-request"}'.$suffix, true],
            ['raw-object-key-two', $prefix.'{"2":"bad-request"}'.$suffix, true],
            ['raw-list-two', $prefix.'["bad-request","internal-error"]'.$suffix, true],
            ['raw-list-unknown', $prefix.'["not-a-code"]'.$suffix, true],
            // PHP's json_decode coerces the numeric string key "0" to a
            // list position, so {"0":...} is indistinguishable from
            // ["..."] in the decoded domain and PHP accepts it; Lua sees
            // the object spelling and refuses it. The parity assertion is
            // skipped for this ONE representation edge and each side's
            // documented behavior is asserted instead.
            ['raw-object-key-zero', $prefix.'{"0":"bad-request"}'.$suffix, false],
        ];
    }

    public function testTheRawJsonRepresentationVectorsMatchOnBothSides(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $client = new \Predis\Client(self::redisUrl());
        try {
            $client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }

        $script = SiteVerifyIdempotencyLuaPredicate::LUA."\nreturn classifyIdempotencyRecord(cjson.decode(ARGV[1])) ~= nil and 'accept' or 'reject'";
        foreach ($this->rawJsonCorpus() as [$name, $raw, $expectParity]) {
            $luaRaw = $client->eval($script, 1, 'parity-key', $raw);
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
            $php = SiteVerifyIdempotencyRecordSchema::tryClassify($decoded) !== null;
            $lua = $luaRaw === 'accept';
            if ($expectParity) {
                self::assertSame($php, $lua, $name.': PHP and Lua must agree on the raw representation');
            } else {
                // The one documented representation edge: PHP accepts the
                // numerically-keyed object (its decoder normalizes it to
                // a list) while Lua's canonical-list rule refuses it. The
                // strict Lua rule is what protects the transition
                // boundary; PHP's acceptance is the decoded-domain limit.
                self::assertFalse($lua, $name.': Lua refuses the object spelling');
                self::assertTrue($php, $name.': PHP normalizes the numeric key to a list position');
            }
        }
    }

    public function testEveryCorpusRecordGetsIdenticalPhpAndLuaOutcomes(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $client = new \Predis\Client(self::redisUrl());
        try {
            $client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }

        $mismatches = [];
        $count = 0;
        $accepted = 0;
        foreach ($this->corpus() as [$name, $record]) {
            ++$count;
            $lua = $this->luaAccepts($client, $record);
            $php = SiteVerifyIdempotencyRecordSchema::tryClassify($record) !== null;
            if ($php) {
                ++$accepted;
            }
            if ($lua !== $php) {
                $mismatches[] = sprintf('%s: php=%s lua=%s', $name, $php ? 'accept' : 'reject', $lua ? 'accept' : 'reject');
            }
        }
        self::assertSame([], $mismatches, sprintf('PHP and Lua schema validation diverge on %d of %d corpus records', \count($mismatches), $count));
        self::assertGreaterThan(50, $count, 'the corpus must cover a wide mutation surface');
        self::assertGreaterThan(8, $accepted, 'the corpus must include a meaningful set of valid records accepted by both sides');
        self::assertGreaterThan(40, $count - $accepted, 'the corpus must also reject a wide corruption surface on both sides');
    }
}
