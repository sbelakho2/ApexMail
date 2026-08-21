<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\MalformedRecordException;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Narrow identifier alphabet: scope, issuer, region and request_binding
 * must match `[A-Za-z0-9._:-]+` with the length caps (scope <= 128,
 * request_binding <= 128, issuer <= 128, region <= 64). The issuer
 * rejects non-conforming values at issuance (\InvalidArgumentException);
 * the record parser rejects non-conforming deployment-bound identifiers
 * (region/request_binding/issuer) as MalformedRecord. The verifier's
 * validate_record enforces the alphabet for scope; fromArray
 * deliberately treats scope as an opaque string, a serde-parity choice
 * pinned by the differential fuzz corpus.
 */
final class IdentifierAlphabetTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function nonConforming(): iterable
    {
        yield 'unicode' => ["log\u{00FC}n"];
        yield 'space' => ['log in'];
        yield 'pipe separator' => ['login|admin'];
        yield 'invisible control char' => ["login\x00"];
        yield 'tab' => ["login\tx"];
        yield 'empty' => [''];
        yield 'leading dash-only invalid char' => ['!login'];
        yield 'question mark' => ['login?'];
    }

    /** @return iterable<string, array{string}> */
    public static function conforming(): iterable
    {
        yield 'plain' => ['login'];
        yield 'dots' => ['a.b'];
        yield 'colon' => ['eu:west'];
        yield 'dash' => ['us-east-1'];
        yield 'underscore' => ['a_b'];
        yield 'mixed' => ['a.b:c_d-e'];
        yield 'digits' => ['txn-9f3a'];
    }

    public function testConfigRejectsNonConformingIssuer(): void
    {
        $rejected = 0;
        foreach (self::nonConforming() as $label => [$value]) {
            try {
                new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: $value);
            } catch (\InvalidArgumentException) {
                $rejected++;
            }
        }
        self::assertSame(count(iterator_to_array(self::nonConforming())), $rejected, 'every non-conforming issuer must be rejected');
    }

    public function testConfigRejectsIssuerLongerThan128Bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: str_repeat('i', 129));
    }

    public function testConfigAcceptsIssuerAtThe128ByteBoundary(): void
    {
        $issuer = str_repeat('i', 128);
        $config = new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: $issuer);

        self::assertSame($issuer, $config->issuer);
    }

    public function testConfigAcceptsConformingIssuers(): void
    {
        foreach (self::conforming() as $label => [$value]) {
            $config = new Config(secretKey: Vectors::SECRET, targetBits: 8, issuer: $value);
            self::assertSame($value, $config->issuer, "issuer '$value' ($label) must be accepted");
        }
    }

    public function testIssuerRejectsNonConformingRegionAtConstruction(): void
    {
        $rejected = 0;
        foreach (self::nonConforming() as $label => [$value]) {
            try {
                new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), new ArrayStorage(), region: $value);
            } catch (\InvalidArgumentException) {
                $rejected++;
            }
        }
        self::assertSame(count(iterator_to_array(self::nonConforming())), $rejected, 'every non-conforming region must be rejected');
    }

    public function testIssuerRejectsRegionLongerThan64Bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), new ArrayStorage(), region: str_repeat('r', 65));
    }

    public function testIssuerAcceptsRegionAtThe64ByteBoundary(): void
    {
        $region = str_repeat('r', 64);
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), $storage, region: $region);

        $challenge = $issuer->issue('login', '198.51.100.7');
        self::assertSame($region, $storage->find($challenge->nonce)?->region);
    }

    public function testIssueRejectsNonConformingScope(): void
    {
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), new ArrayStorage());

        $rejected = 0;
        foreach (self::nonConforming() as $label => [$value]) {
            try {
                $issuer->issue($value, '198.51.100.7');
            } catch (\InvalidArgumentException) {
                $rejected++;
            }
        }
        self::assertSame(count(iterator_to_array(self::nonConforming())), $rejected, 'every non-conforming scope must be rejected');
    }

    public function testIssueAcceptsConformingScopes(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), $storage);

        foreach (self::conforming() as $label => [$value]) {
            $challenge = $issuer->issue($value, '198.51.100.7');
            self::assertSame($value, $storage->find($challenge->nonce)?->scope, "scope '$value' ($label) must be accepted");
        }
    }

    public function testIssueRejectsNonConformingRequestBinding(): void
    {
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), new ArrayStorage());

        $rejected = 0;
        foreach (self::nonConforming() as $label => [$value]) {
            try {
                $issuer->issue('login', '198.51.100.7', $value);
            } catch (\InvalidArgumentException) {
                $rejected++;
            }
        }
        self::assertSame(count(iterator_to_array(self::nonConforming())), $rejected, 'every non-conforming request_binding must be rejected');
    }

    public function testIssueRejectsRequestBindingLongerThan128Bytes(): void
    {
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), new ArrayStorage());

        $this->expectException(\InvalidArgumentException::class);
        $issuer->issue('login', '198.51.100.7', str_repeat('b', 129));
    }

    public function testIssueAcceptsConformingRequestBindings(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: Vectors::SECRET, targetBits: 8), $storage);

        foreach (self::conforming() as $label => [$value]) {
            $challenge = $issuer->issue('login', '198.51.100.7', $value);
            self::assertSame($value, $storage->find($challenge->nonce)?->requestBinding, "request_binding '$value' ($label) must be accepted");
        }
    }

    /** @return array<string, mixed> a fully valid record array */
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
        ];
    }

    /** @return array<string, mixed> */
    private static function mutate(string $key, mixed $value): array
    {
        $data = self::base();
        $data[$key] = $value;

        return $data;
    }

    public function testFromArrayRejectsNonConformingDeploymentIdentifiers(): void
    {
        foreach (['region' => 64, 'request_binding' => 128, 'issuer' => 128] as $field => $max) {
            foreach (self::nonConforming() as $label => [$value]) {
                try {
                    ChallengeRecord::fromArray(self::mutate($field, $value));
                    self::fail("record $field '$value' ($label) must be rejected by fromArray");
                } catch (MalformedRecordException $e) {
                    self::assertStringContainsString('[A-Za-z0-9._:-]', $e->getMessage());
                }
            }
            // Length caps beyond the type ceiling.
            try {
                ChallengeRecord::fromArray(self::mutate($field, str_repeat('x', $max + 1)));
                self::fail("record $field longer than $max must be rejected by fromArray");
            } catch (MalformedRecordException $e) {
                self::assertStringContainsString('[A-Za-z0-9._:-]', $e->getMessage());
            }
        }
    }

    public function testFromArrayAcceptsConformingDeploymentIdentifiers(): void
    {
        foreach (self::conforming() as $label => [$value]) {
            $data = self::mutate('region', $value);
            $data['request_binding'] = $value;
            $data['issuer'] = $value;

            $record = ChallengeRecord::fromArray($data);
            self::assertSame($value, $record->region, "region '$value' ($label) must parse");
            self::assertSame($value, $record->requestBinding);
            self::assertSame($value, $record->issuer);
        }
    }

    public function testFromArrayTreatsScopeAsOpaqueSerdeString(): void
    {
        // The differential fuzz corpus pins scope as an opaque string:
        // 'login|admin' and unicode scopes must still parse (exactly like
        // the Rust serde `String` field), so the 659-accepted split
        // holds.
        $record = ChallengeRecord::fromArray(self::mutate('scope', 'login|admin'));
        self::assertSame('login|admin', $record->scope);

        $record = ChallengeRecord::fromArray(self::mutate('scope', "log\u{00FC}n"));
        self::assertSame("log\u{00FC}n", $record->scope);
    }

    public function testVerifierRejectsNonConformingScopeRecords(): void
    {
        // The verifier's validate_record enforces the scope alphabet; a
        // parsed-but-non-conforming scope fails closed as MalformedRecord
        // before any crypto work. The record carries a structurally valid
        // 32-byte nonce and 16-byte salt so the scope alphabet check is
        // the only validation failure.
        foreach (['login|admin', "log\u{00FC}n", 'log in'] as $scope) {
            $data = self::mutate('scope', $scope);
            $data['nonce'] = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=';
            $data['salt'] = 'MTIzNDU2Nzg5MGFiY2RlZg==';
            $data['prefix'] = 'challenge|MTIzNDU2Nzg5MGFiY2RlZg==|';
            $record = ChallengeRecord::fromArray($data);
            $storage = new ArrayStorage();
            $storage->store($record);

            $verifier = new Verifier($storage, now: static fn (): int => 1_800_000_000);
            $outcome = $verifier->verify(
                \KiwiCaptcha\SolutionToken::create($record->nonce, 0, 5000, [])->encode(),
                Vectors::SECRET,
            );

            self::assertSame(VerifyError::MalformedRecord, $outcome->error, "scope '$scope' must be rejected by the verifier");
            self::assertNull($storage->find($record->nonce));
        }
    }

    public function testVerifierAcceptsConformingScopeRecords(): void
    {
        // Control: a conforming multi-character scope ('us-east-1' style)
        // passes validation and fails later at the signature check, never
        // at validate_record.
        $data = self::mutate('scope', 'a.b:c_d-e');
        $data['nonce'] = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=';
        $data['salt'] = 'MTIzNDU2Nzg5MGFiY2RlZg==';
        $data['prefix'] = 'challenge|MTIzNDU2Nzg5MGFiY2RlZg==|';
        $record = ChallengeRecord::fromArray($data);
        $storage = new ArrayStorage();
        $storage->store($record);

        $verifier = new Verifier($storage, now: static fn (): int => 1_800_000_000);
        $outcome = $verifier->verify(
            \KiwiCaptcha\SolutionToken::create($record->nonce, 0, 5000, [])->encode(),
            Vectors::SECRET,
        );

        self::assertSame(VerifyError::BadSignature, $outcome->error, 'the conforming scope passes validate_record (the garbage challenge fails the signature)');
    }
}
