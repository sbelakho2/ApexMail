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
            'salt' => 'c2FsdHNhbHRzYWx0c2FsdA==',
            'prefix' => 'challenge|c2FsdHNhbHRzYWx0c2FsdA==|',
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
        self::assertSame(29, \count(ChallengeRecord::WIRE_KEYS));
        // An unarmed record omits the optional decoy_field, execution
        // and server_mac keys entirely (the skip_serializing_if mirror),
        // so toArray() emits exactly the 23 always-present keys.
        self::assertSame(
            \array_values(\array_diff(ChallengeRecord::WIRE_KEYS, ['decoy_field', 'execution_program', 'execution_version', 'execution_commitment', 'rsw_modulus_sha256', 'server_mac'])),
            \array_keys($record->toArray()),
        );
        self::assertNull($record->decoyField);
        self::assertArrayNotHasKey('decoy_field', $record->toArray());
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

        // The rejection vocabulary names every accepted algorithm, rsw
        // included.
        yield 'unknown algorithm names all three accepted values' => [self::mutate('algorithm', 'scrypt'), '"sha256", "argon2id" or "rsw"'];

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

        yield 'decoy_field with pipe rejected (alphabet)' => [self::mutate('decoy_field', 'company|website'), 'must be 1-64 characters of [A-Za-z0-9_-]'];

        yield 'decoy_field with dot rejected (alphabet)' => [self::mutate('decoy_field', 'company.website'), 'must be 1-64 characters of [A-Za-z0-9_-]'];

        yield 'decoy_field empty string rejected (alphabet)' => [self::mutate('decoy_field', ''), 'must be 1-64 characters of [A-Za-z0-9_-]'];

        yield 'decoy_field over-long rejected (alphabet)' => [self::mutate('decoy_field', str_repeat('x', 65)), 'must be 1-64 characters of [A-Za-z0-9_-]'];

        yield 'non-string decoy_field rejected' => [self::mutate('decoy_field', 123), 'must be a string'];

        // ── The protocol-v4 execution triplet  ──
        // execution_version / execution_commitment: types and shapes.
        // $program is a well-formed generated program (see the helper
        // below), so these cases isolate the triplet grammar, never the
        // program-blob validity.
        $program = self::validProgram();

        yield 'string execution_version rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => '1', 'execution_commitment' => hash('sha256', $program)],
            'must be an integer',
        ];

        yield 'execution_version outside the canonical register 1..MAX rejected' => [
            self::mutate('protocol_version', 4) + ['execution_program' => $program, 'execution_version' => 9, 'execution_commitment' => hash('sha256', $program)],
            sprintf('must be one of the canonical execution-dimension versions 1..%d', \KiwiCaptcha\ExecutionChallengeGenerator::MAX_EXECUTION_VERSION),
        ];



        yield 'non-hex execution_commitment rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => str_repeat('g', 64)],
            'exactly 64 lowercase hex',
        ];

        yield 'short execution_commitment rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => str_repeat('0', 63)],
            'exactly 64 lowercase hex',
        ];

        yield 'uppercase hex execution_commitment rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => str_repeat('A', 64)],
            'exactly 64 lowercase hex',
        ];

        yield 'non-string execution_commitment rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => 123],
            'must be a string',
        ];

        // The exact armed/unarmed equivalence: the three execution keys
        // are one triplet — partial sets are corrupt/foreign records.
        yield 'execution_version without a program rejected' => [
            self::base() + ['execution_version' => 1],
            'present together or all absent',
        ];

        yield 'execution_commitment without a program rejected' => [
            self::base() + ['execution_commitment' => str_repeat('0', 64)],
            'present together or all absent',
        ];

        yield 'program without the commitment triplet rejected' => [
            self::base() + ['execution_program' => $program],
            'present together or all absent',
        ];

        // The protocol-vs-execution grammar: v2/v3 never carry execution.
        yield 'protocol v2 with an execution program rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => hash('sha256', $program)],
            'field combination',
        ];

        yield 'protocol v3 with an execution program rejected' => [
            self::mutate('protocol_version', 3) + ['decoy_field' => 'company_website', 'execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => hash('sha256', $program)],
            'field combination',
        ];

        // A v4 record without the execution triplet is malformed (the
        // stored-version-flip window closes).
        yield 'protocol v4 without the execution triplet rejected' => [
            self::mutate('protocol_version', 4),
            'field combination',
        ];

        // A program whose hash does not equal the signed commitment is
        // a corrupt/foreign record.
        yield 'program not matching its commitment rejected' => [
            self::base() + ['execution_program' => $program, 'execution_version' => 1, 'execution_commitment' => str_repeat('0', 64)],
            'does not match the signed "execution_commitment"',
        ];
    }

    /** A well-formed generated program, so the triplet cases isolate the grammar. */
    private static function validProgram(): string
    {
        return \KiwiCaptcha\ExecutionChallengeGenerator::generate(
            '0123456789abcdef0123456789abcdef',
            '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=',
            'login',
            'login-action',
            1,
        );
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

    public function testV4RecordWithTheExecutionTripletRoundTrips(): void
    {
        $program = self::validProgram();
        $data = self::base();
        $data['protocol_version'] = 4;
        $data['decoy_field'] = 'company_website';
        $data['execution_program'] = $program;
        $data['execution_version'] = 1;
        $data['execution_commitment'] = hash('sha256', $program);

        $record = ChallengeRecord::fromArray($data);

        self::assertSame(4, $record->protocolVersion);
        self::assertSame('company_website', $record->decoyField, 'a v4 record may carry the decoy (the decoy-capable canonical)');
        self::assertSame($program, $record->executionProgram);
        self::assertSame(1, $record->executionVersion);
        self::assertSame(hash('sha256', $program), $record->executionCommitment);

        // The round trip preserves the signed triplet byte-for-byte.
        $roundTripped = ChallengeRecord::fromArray($record->toArray());
        self::assertSame($record->executionProgram, $roundTripped->executionProgram);
        self::assertSame($record->executionVersion, $roundTripped->executionVersion);
        self::assertSame($record->executionCommitment, $roundTripped->executionCommitment);
        self::assertSame($data['execution_program'], $roundTripped->toArray()['execution_program']);
        self::assertSame(1, $roundTripped->toArray()['execution_version']);
        self::assertSame($data['execution_commitment'], $roundTripped->toArray()['execution_commitment']);
    }

    public function testV4RecordWithExecutionVersionThreeRoundTrips(): void
    {
        // The version-3 grammar is a canonical record version: a
        // protocol-v4 record carrying execution_version 3 with a
        // matching program and commitment parses and round-trips.
        $program = \KiwiCaptcha\ExecutionChallengeGenerator::generate('0123456789abcdef0123456789abcdef', '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=', 'login', 'login-action', 3);
        $record = ChallengeRecord::fromArray(self::mutate('protocol_version', 4) + [
            'execution_program' => $program,
            'execution_version' => 3,
            'execution_commitment' => hash('sha256', $program),
        ]);
        self::assertSame(3, $record->executionVersion);
        self::assertSame($program, $record->executionProgram);
        $reparsed = ChallengeRecord::fromArray($record->toArray());
        self::assertSame($program, $reparsed->executionProgram, 'the version-3 record round-trips');
    }

    public function testV4RecordWithExecutionVersionTwoRoundTrips(): void
    {
        // The record register accepts the canonical execution versions,
        // 1..ExecutionChallengeGenerator::MAX_EXECUTION_VERSION: 1 (the
        // legacy construction-to-probe grammar, exercised by the
        // fixtures above) and 2 (the causal observe grammar) both ride
        // the protocol-v4 triplet shape; the sibling test round-trips a
        // version-3 program the same way.
        $program = \KiwiCaptcha\ExecutionChallengeGenerator::generate(
            '0123456789abcdef0123456789abcdef',
            '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=',
            'login',
            'login-action',
            2,
        );
        $data = self::base();
        $data['protocol_version'] = 4;
        $data['execution_program'] = $program;
        $data['execution_version'] = 2;
        $data['execution_commitment'] = hash('sha256', $program);

        $record = ChallengeRecord::fromArray($data);

        self::assertSame(4, $record->protocolVersion);
        self::assertSame($program, $record->executionProgram);
        self::assertSame(2, $record->executionVersion);

        $roundTripped = ChallengeRecord::fromArray($record->toArray());
        self::assertSame($program, $roundTripped->executionProgram);
        self::assertSame(2, $roundTripped->executionVersion);
        self::assertSame($record->executionCommitment, $roundTripped->executionCommitment);
        self::assertSame(2, $roundTripped->toArray()['execution_version']);
    }

    public function testV4WithoutADecoyStillRoundTrips(): void
    {
        // The decoy is optional on v4 (execution without the decoy
        // surface): the canonical is base|execution_version|
        // execution_commitment.
        $program = self::validProgram();
        $data = self::base();
        $data['protocol_version'] = 4;
        $data['execution_program'] = $program;
        $data['execution_version'] = 1;
        $data['execution_commitment'] = hash('sha256', $program);

        $record = ChallengeRecord::fromArray($data);
        self::assertSame(4, $record->protocolVersion);
        self::assertNull($record->decoyField);
    }

    public function testProtocolVersionsOutsideTheCanonicalRangeAreRejected(): void
    {
        // The canonical protocol bounds are enforced at the parse
        // boundary, mirroring the Rust serde boundary: 0 is not a
        // protocol version, and everything above MAX_PROTOCOL_VERSION is
        // a corrupt or foreign value no conforming issuer writes. A bare
        // v5 (the identity-bearing grammar) without the rsw identity is
        // rejected too: the version exists but its grammar requires the
        // identity, so a version-only bump can never look valid.
        foreach ([0, 6, 99, 255] as $version) {
            try {
                ChallengeRecord::fromArray(self::mutate('protocol_version', $version));
                self::fail("protocol_version $version must be rejected at parse");
            } catch (MalformedRecordException $e) {
                self::assertStringContainsString('protocol_version', $e->getMessage());
            }
        }
        try {
            ChallengeRecord::fromArray(self::mutate('protocol_version', 5));
            self::fail('a v5 record without the rsw identity must be rejected at parse');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('protocol_version', $e->getMessage());
        }
    }

    public function testZeroKidAndZeroPolicyVersionStayParseable(): void
    {
        // The u32 widths are the parse boundary (the Rust serde
        // boundary agrees): epoch 0 is the legitimate pre-epoch state a
        // policy rotation walks forward from, and a stored 0 for either
        // field decodes while every out-of-width value still rejects.
        foreach (['kid', 'policy_version'] as $field) {
            $record = ChallengeRecord::fromArray(self::mutate($field, 0));
            self::assertSame(0, $field === 'kid' ? $record->kid : $record->policyVersion);
            try {
                ChallengeRecord::fromArray(self::mutate($field, 4_294_967_296));
                self::fail("$field above the u32 width must be rejected at parse");
            } catch (MalformedRecordException $e) {
                self::assertStringContainsString($field, $e->getMessage());
            }
        }
    }

    public function testProtocolOneExtensionCombinationsAreRejectedAtDecode(): void
    {
        // The decoder applies the same grammar matrix as the verifier:
        // the legacy v1 shape admits neither extension, so a stored v1
        // record carrying a decoy or the execution triplet fails
        // decode instead of parsing and failing later at verification.
        $v1Decoy = self::mutate('protocol_version', 1);
        $v1Decoy['decoy_field'] = 'company_website';
        try {
            ChallengeRecord::fromArray($v1Decoy);
            self::fail('a v1 record carrying a decoy must fail decode');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('field combination', $e->getMessage());
        }

        $v1Execution = self::mutate('protocol_version', 1);
        $program = self::validProgram();
        $v1Execution['execution_program'] = $program;
        $v1Execution['execution_version'] = 1;
        $v1Execution['execution_commitment'] = hash('sha256', $program);
        try {
            ChallengeRecord::fromArray($v1Execution);
            self::fail('a v1 record carrying the execution triplet must fail decode');
        } catch (MalformedRecordException $e) {
            self::assertStringContainsString('field combination', $e->getMessage());
        }

        // The valid shapes still decode: v1 bare, v3 with the decoy,
        // v4 with the triplet (and v4 with both).
        self::assertInstanceOf(ChallengeRecord::class, ChallengeRecord::fromArray(self::mutate('protocol_version', 1)));
        $v3 = self::mutate('protocol_version', 3);
        $v3['decoy_field'] = 'company_website';
        self::assertInstanceOf(ChallengeRecord::class, ChallengeRecord::fromArray($v3));
        $v4 = self::mutate('protocol_version', 4);
        $v4['execution_program'] = $program;
        $v4['execution_version'] = 1;
        $v4['execution_commitment'] = hash('sha256', $program);
        self::assertInstanceOf(ChallengeRecord::class, ChallengeRecord::fromArray($v4));
        $v4Both = $v4;
        $v4Both['decoy_field'] = 'company_website';
        self::assertInstanceOf(ChallengeRecord::class, ChallengeRecord::fromArray($v4Both));
    }

    public function testNonceSaltShapesAreValidatedAtParseTime(): void
    {
        // The decode boundary applies the full structural contract on
        // both sides of the wire (the Rust serde reconstruction calls
        // `validate_record` before any typed record surfaces — see
        // packages/kiwicaptcha/tests/corpus.rs, which pins that no
        // corpus mutation decodes). A nonce that is not the 44-char
        // standard-base64 encoding of 32 bytes, or a salt that is not
        // the 24-char encoding of 16 bytes, is corrupt or foreign and
        // must be refused here exactly like Rust refuses it — the old
        // "plain strings at parse" split was a parser differential.
        foreach ([
            'salt' => ['QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY', '44-char salt (32 bytes)'],
            'salt-short' => ['c2FsdA==', '8-char salt'],
            'nonce-short' => [str_repeat('A', 43), '43-char nonce'],
        ] as $label => [$value, $what]) {
            $key = str_starts_with($label, 'nonce') ? 'nonce' : 'salt';
            try {
                ChallengeRecord::fromArray(self::mutate($key, $value));
                self::fail("a {$what} must be refused at the parse boundary");
            } catch (MalformedRecordException) {
                self::assertTrue(true);
            }
        }
        // The wire-valid shapes parse byte-exactly.
        $record = ChallengeRecord::fromArray(self::base());
        self::assertSame(self::base()['salt'], $record->salt);
        self::assertSame(self::base()['nonce'], $record->nonce);
    }

    public function testWireKeySetIsPinnedTo29(): void
    {
        // decoy_field, execution_program, execution_version,
        // execution_commitment, rsw_modulus_sha256 and server_mac are the
        // Option keys omitted from toArray() when null (the Rust
        // skip_serializing_if mirror); every other key is always
        // present. The three execution keys are present together or all
        // absent, and the rsw identity rides only an rsw record.
        self::assertSame([
            'nonce', 'scope', 'binding_tag', 'issued_at', 'expires_at',
            'algorithm', 'm_kib', 't', 'p', 'target_bits', 'salt', 'prefix',
            'challenge', 'min_duration_ms', 'issued_at_ns', 'protocol_version',
            'attempts_used', 'region', 'policy_version', 'request_binding',
            'issuer', 'kid', 'hostname', 'decoy_field', 'execution_program',
            'execution_version', 'execution_commitment', 'rsw_modulus_sha256',
            'server_mac',
        ], ChallengeRecord::WIRE_KEYS);
    }

    public function testServerMacMustBeSixtyFourLowercaseHex(): void
    {
        $ok = self::base();
        $ok['server_mac'] = str_repeat('0a', 32);
        self::assertSame(str_repeat('0a', 32), ChallengeRecord::fromArray($ok)->serverMac);
        self::assertSame(str_repeat('0a', 32), ChallengeRecord::fromArray($ok)->toArray()['server_mac']);
        $absent = self::base();
        unset($absent['server_mac']);
        self::assertNull(ChallengeRecord::fromArray($absent)->serverMac);

        foreach ([str_repeat('0A', 32), str_repeat('0a', 31), str_repeat('0a', 32)."\n", 'zz'.str_repeat('0a', 31), 7, true, []] as $bad) {
            $data = self::base();
            $data['server_mac'] = $bad;
            try {
                ChallengeRecord::fromArray($data);
                self::fail('a malformed server_mac must fail decode: '.var_export($bad, true));
            } catch (MalformedRecordException) {
                self::addToAssertionCount(1);
            }
        }
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
