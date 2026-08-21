<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\MalformedRecordException;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Strict serde-mirror record parser: ChallengeRecord::fromArray
 * must reject exactly what the Rust `ChallengeRecord` serde schema rejects —
 * unknown keys (deny_unknown_fields), out-of-range/negative integers, wrong
 * types, oversized strings, algorithm aliases, unexpected nulls, duplicate
 * binding aliases, and missing required fields.
 */
final class StrictParserTest extends TestCase
{
    /** @return array<string, mixed> a fully valid 23-key record array */
    private static function base(): array
    {
        return [
            'nonce' => '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=',
            'scope' => 'login',
            'binding_tag' => 'tag123',
            'issued_at' => 1_800_000_000,
            'expires_at' => 1_800_000_120,
            'algorithm' => 'sha256',
            'm_kib' => 0,
            't' => 1,
            'p' => 1,
            'target_bits' => 8,
            'salt' => 'c2FsdA==',
            'prefix' => 'prefix',
            'challenge' => 'challenge',
            'min_duration_ms' => 0,
            'issued_at_ns' => 1_800_000_000_000_000,
            'attempts_used' => 0,
            'protocol_version' => 2,
            'region' => null,
            'policy_version' => 1,
            'request_binding' => null,
            'issuer' => null,
            'kid' => 1,
            'hostname' => null,
        ];
    }

    /** @return array<string, mixed> */
    private static function mutate(string $key, mixed $value): array
    {
        $data = self::base();
        $data[$key] = $value;

        return $data;
    }

    /** @return array<string, mixed> */
    private static function omit(string $key): array
    {
        $data = self::base();
        unset($data[$key]);

        return $data;
    }

    public function testValidRecordRoundTrips(): void
    {
        $record = ChallengeRecord::fromArray(self::base());

        self::assertSame('login', $record->scope);
        self::assertSame(PoWAlgorithm::Sha256, $record->algorithm);
        self::assertSame(2, $record->protocolVersion);
        self::assertSame(1, $record->policyVersion);
        self::assertNull($record->requestBinding);
        self::assertNull($record->issuer);
        self::assertSame(1, $record->kid, 'kid defaults to 1 on the wire');
        self::assertSame(23, \count(ChallengeRecord::WIRE_KEYS));
        self::assertSame(ChallengeRecord::WIRE_KEYS, \array_keys($record->toArray()));
        self::assertSame(1, $record->toArray()['kid'], 'the kid key is ALWAYS present');
    }

    /**
     * @dataProvider rejectionProvider
     *
     * @param array<string, mixed> $data
     */
    public function testRejects(array $data, string $expectedMessageSubstring): void
    {
        try {
            ChallengeRecord::fromArray($data);
            self::fail('fromArray must reject the mutated record');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString($expectedMessageSubstring, $e->getMessage());
        }
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function rejectionProvider(): iterable
    {
        yield 'unknown key (trailing garbage)' => [self::base() + ['trailing' => 'garbage'], 'unknown record key'];

        yield 'json array in place of object' => [
            [0 => 'x', 1 => 'y'],
            'unknown record key',
        ];

        yield 'missing required field' => [self::omit('scope'), 'missing required record field'];

        yield 'missing nonce' => [self::omit('nonce'), 'missing required record field'];

        yield 'missing challenge' => [self::omit('challenge'), 'missing required record field'];

        yield 'non-string nonce' => [self::mutate('nonce', 123), 'must be a string'];

        yield 'non-string scope (bool)' => [self::mutate('scope', true), 'must be a string'];

        yield 'integer in place of string salt' => [self::mutate('salt', 7), 'must be a string'];

        yield 'oversized scope (> 4096)' => [
            self::mutate('scope', str_repeat('a', 4097)),
            'exceeds the 4096-byte ceiling',
        ];

        yield 'oversized binding_tag (> 4096)' => [
            self::mutate('binding_tag', str_repeat('b', 5000)),
            'exceeds the 4096-byte ceiling',
        ];

        yield 'oversized salt (> 4096)' => [
            self::mutate('salt', str_repeat('s', 4097)),
            'exceeds the 4096-byte ceiling',
        ];

        yield 'oversized nonce (> 4096)' => [
            self::mutate('nonce', str_repeat('n', 10_000)),
            'exceeds the 4096-byte ceiling',
        ];

        yield 'negative issued_at' => [self::mutate('issued_at', -1), 'must be within'];

        yield 'float issued_at' => [self::mutate('issued_at', 1_800_000_000.0), 'must be an integer'];

        yield 'bool p' => [self::mutate('p', true), 'must be an integer'];

        yield 'numeric string target_bits' => [self::mutate('target_bits', '8'), 'must be an integer'];

        yield 'u32 overflow m_kib' => [self::mutate('m_kib', 4_294_967_296), 'must be within'];

        yield 'u32 overflow policy_version' => [
            self::mutate('policy_version', 4_294_967_296),
            'must be within',
        ];

        yield 'u8 overflow protocol_version' => [self::mutate('protocol_version', 256), 'must be within'];

        yield 'negative min_duration_ms' => [self::mutate('min_duration_ms', -5), 'must be within'];

        yield 'negative issued_at_ns' => [self::mutate('issued_at_ns', -1), 'must be within'];

        yield 'null nonce' => [self::mutate('nonce', null), 'must be a string'];

        yield 'null issued_at' => [self::mutate('issued_at', null), 'must be an integer'];

        yield 'null optional issued_at_ns' => [self::mutate('issued_at_ns', null), 'must be an integer'];

        yield 'null optional attempts_used' => [self::mutate('attempts_used', null), 'must be an integer'];

        yield 'null optional policy_version' => [self::mutate('policy_version', null), 'must be an integer'];

        yield 'null algorithm' => [self::mutate('algorithm', null), 'must be exactly'];

        yield 'null salt' => [self::mutate('salt', null), 'must be a string'];

        yield 'algorithm alias uppercase' => [self::mutate('algorithm', 'SHA256'), 'must be exactly'];

        yield 'algorithm alias hyphenated' => [self::mutate('algorithm', 'sha-256'), 'must be exactly'];

        yield 'algorithm alias mixed case' => [self::mutate('algorithm', 'Sha256'), 'must be exactly'];

        yield 'algorithm alias trailing space' => [self::mutate('algorithm', 'sha256 '), 'must be exactly'];

        yield 'algorithm alias argon2' => [self::mutate('algorithm', 'argon2'), 'must be exactly'];

        // Unknown algorithm strings must be rejected identically to the
        // Rust parser (PoWAlgorithm enum: exact lowercase names only, no
        // aliases, no spelling variants).
        yield 'algorithm unknown argon2d' => [self::mutate('algorithm', 'argon2d'), 'must be exactly'];

        yield 'algorithm unknown sha1' => [self::mutate('algorithm', 'sha1'), 'must be exactly'];

        yield 'algorithm unknown sha256-v2' => [self::mutate('algorithm', 'sha256-v2'), 'must be exactly'];

        yield 'algorithm unknown spaced variant' => [self::mutate('algorithm', 'ARGO N2ID'), 'must be exactly'];

        yield 'binding_tag and ip_hash together rejected' => [
            self::base() + ['ip_hash' => 'legacyhash'],
            'both "binding_tag" and its legacy alias "ip_hash"',
        ];

        yield 'kid as string rejected' => [self::mutate('kid', '1'), 'must be an integer'];

        yield 'kid as float rejected' => [self::mutate('kid', 1.0), 'must be an integer'];

        yield 'null kid rejected' => [self::mutate('kid', null), 'must be an integer'];

        yield 'u32 overflow kid' => [self::mutate('kid', 4_294_967_296), 'must be within'];

        yield 'region with space rejected (alphabet)' => [self::mutate('region', 'eu west'), 'must be 1-64 characters of [A-Za-z0-9._:-]'];

        yield 'region with unicode rejected (alphabet)' => [self::mutate('region', 'eu\u00eb'), 'must be 1-64 characters of [A-Za-z0-9._:-]'];

        yield 'region empty string rejected (alphabet)' => [self::mutate('region', ''), 'must be 1-64 characters of [A-Za-z0-9._:-]'];

        yield 'region with invisible char rejected (alphabet)' => [self::mutate('region', "eu\x00"), 'must be 1-64 characters of [A-Za-z0-9._:-]'];

        yield 'request_binding with pipe rejected (alphabet)' => [self::mutate('request_binding', 'txn|1'), 'must be 1-128 characters of [A-Za-z0-9._:-]'];

        yield 'issuer with unicode rejected (alphabet)' => [self::mutate('issuer', 'pr\u00f6d'), 'must be 1-128 characters of [A-Za-z0-9._:-]'];

        yield 'issuer with space rejected (alphabet)' => [self::mutate('issuer', 'prod one'), 'must be 1-128 characters of [A-Za-z0-9._:-]'];

        yield 'issuer empty string rejected (alphabet)' => [self::mutate('issuer', ''), 'must be 1-128 characters of [A-Za-z0-9._:-]'];

        yield 'issuer with invisible char rejected (alphabet)' => [self::mutate('issuer', "prod\x1f"), 'must be 1-128 characters of [A-Za-z0-9._:-]'];
    }

    public function testLegacyIpHashAliasIsAcceptedInPlaceOfBindingTag(): void
    {
        $data = self::omit('binding_tag');
        $data['ip_hash'] = 'legacyhash';

        $record = ChallengeRecord::fromArray($data);

        self::assertSame('legacyhash', $record->bindingTag);
        self::assertSame('legacyhash', $record->ipHash());
    }

    public function testNullRegionRequestBindingAndIssuerAreAccepted(): void
    {
        $record = ChallengeRecord::fromArray(self::base());

        self::assertNull($record->region);
        self::assertNull($record->requestBinding);
        self::assertNull($record->issuer);
    }

    public function testStringRegionRequestBindingAndIssuerAreAccepted(): void
    {
        $data = self::mutate('region', 'eu');
        $data['request_binding'] = 'txn-42';
        $data['issuer'] = 'prod';

        $record = ChallengeRecord::fromArray($data);

        self::assertSame('eu', $record->region);
        self::assertSame('txn-42', $record->requestBinding);
        self::assertSame('prod', $record->issuer);
    }

    public function testNonStringIssuerIsRejected(): void
    {
        try {
            ChallengeRecord::fromArray(self::mutate('issuer', 123));
            self::fail('a non-string issuer must be rejected');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('issuer', $e->getMessage());
        }
    }

    public function testOversizedIssuerIsRejected(): void
    {
        try {
            ChallengeRecord::fromArray(self::mutate('issuer', str_repeat('i', 5000)));
            self::fail('an oversized issuer must be rejected');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('4096-byte ceiling', $e->getMessage());
        }
    }

    public function testAbsentOptionalFieldsDefault(): void
    {
        $data = self::base();
        unset($data['issued_at_ns'], $data['attempts_used'], $data['region'], $data['policy_version'], $data['request_binding'], $data['issuer'], $data['protocol_version'], $data['kid']);

        $record = ChallengeRecord::fromArray($data);

        self::assertSame(0, $record->issuedAtNs);
        self::assertSame(1, $record->protocolVersion, 'serde default protocol_version is 1');
        self::assertNull($record->region);
        self::assertSame(1, $record->policyVersion, 'serde default policy_version is 1');
        self::assertNull($record->requestBinding);
        self::assertNull($record->issuer, 'a missing issuer key defaults to null (the fuzz corpus has no issuer field)');
        self::assertSame(1, $record->kid, 'a missing kid key defaults to 1 (serde default — the fuzz corpus has no kid field)');
    }

    public function testKidRoundTripsThroughToArrayAndFromArray(): void
    {
        $data = self::mutate('kid', 7);

        $record = ChallengeRecord::fromArray($data);
        self::assertSame(7, $record->kid);
        self::assertSame(7, $record->toArray()['kid']);
        self::assertSame(7, ChallengeRecord::fromArray($record->toArray())->kid);
    }

    public function testProtocolVersionWithinU8RangeIsAccepted(): void
    {
        // serde accepts any u8 — 99 is within range and deserializes (the
        // verifier's validateRecord rejects it later, exactly like Rust).
        $record = ChallengeRecord::fromArray(self::mutate('protocol_version', 99));

        self::assertSame(99, $record->protocolVersion);
    }

    public function testBase64IsNotValidatedAtParseTime(): void
    {
        // serde treats nonce/salt as plain strings — the differential fuzz
        // corpus pins both parsers to the same acceptance split, so a
        // non-canonical base64 string must still parse here.
        $record = ChallengeRecord::fromArray(self::mutate('salt', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY'));

        self::assertSame('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY', $record->salt);
    }

    public function testWireKeySetIsPinnedTo23(): void
    {
        self::assertSame([
            'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
            'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
            'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
            'attempts_used', 'region', 'policy_version', 'request_binding',
            'issuer', 'kid', 'hostname',
        ], ChallengeRecord::WIRE_KEYS);
    }

    public function testRuntimeStorageFieldsAreNotWireKeys(): void
    {
        // `state`, `consumed_result` and `operation_identity` are
        // storage-layer runtime fields wrapped around the canonical JSON —
        // they are NOT part of the canonical record schema and must be
        // rejected by the strict serde-mirror parser exactly like any other
        // unknown key.
        foreach (['state', 'consumed_result', 'operation_identity'] as $key) {
            try {
                ChallengeRecord::fromArray(self::base() + [$key => 'x']);
                self::fail("'$key' is a storage runtime field and must NOT parse into the record");
            } catch (MalformedRecordException $e) {
                self::assertStringContainsString('unknown record key', $e->getMessage());
            }
        }
    }

    public function testVectorsSecretIsStillUsableAsRecordSeed(): void
    {
        // Keep the fixture reference alive so the strict parser tests never
        // drift from the shared vector constants.
        self::assertSame(32, \strlen(Vectors::SECRET));
    }
}
