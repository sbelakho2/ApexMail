<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Protocol v2: nonce-bound IP binding tags over the canonical IP form, the
 * full-parameter canonical payload, and the ChallengeRecord
 * binding_tag/protocol_version schema evolution.
 */
final class ProtocolV2Test extends TestCase
{
    private const NONCE = '2l0IVh1xuKNjzcCDyV+X0lrceMHlHvmqCs5MdDw8tw0=';

    /** @param array<string, mixed> $overrides */
    private function record(array $overrides = []): ChallengeRecord
    {
        return new ChallengeRecord(
            ...array_merge([
                'nonce' => self::NONCE,
                'scope' => 'login',
                'bindingTag' => 'tag123',
                'issuedAt' => 1_800_000_000,
                'expiresAt' => 1_800_000_120,
                'algorithm' => PoWAlgorithm::Sha256,
                'mKib' => 0,
                't' => 1,
                'p' => 1,
                'targetBits' => 8,
                'salt' => 'c2FsdA==',
                'prefix' => 'prefix',
                'challenge' => 'challenge',
                'minDurationMs' => 0,
            ], $overrides)
        );
    }

    public function testBindingTagIpv4MatchesCanonicalHmac(): void
    {
        $ip = '203.0.113.7';
        $expected = hash_hmac(
            'sha256',
            "kiwicaptcha/ip-bind/v2\0".self::NONCE."\0\x04".inet_pton($ip),
            \KiwiCaptcha\DerivedKeys::fromMaster(Vectors::SECRET)->ipBindKey(),
        );

        self::assertSame($expected, Issuer::bindingTag(self::NONCE, $ip, Vectors::SECRET));
    }

    public function testBindingTagIpv6MatchesCanonicalHmac(): void
    {
        $ip = '2001:db8::1';
        $expected = hash_hmac(
            'sha256',
            "kiwicaptcha/ip-bind/v2\0".self::NONCE."\0\x06".inet_pton($ip),
            \KiwiCaptcha\DerivedKeys::fromMaster(Vectors::SECRET)->ipBindKey(),
        );

        self::assertSame($expected, Issuer::bindingTag(self::NONCE, $ip, Vectors::SECRET));
    }

    public function testBindingTagNormalizesIpv4MappedIpv6(): void
    {
        $ipv4 = Issuer::bindingTag(self::NONCE, '203.0.113.7', Vectors::SECRET);
        self::assertSame($ipv4, Issuer::bindingTag(self::NONCE, '::ffff:203.0.113.7', Vectors::SECRET));
        self::assertSame($ipv4, Issuer::bindingTag(self::NONCE, '0:0:0:0:0:ffff:203.0.113.7', Vectors::SECRET));
    }

    public function testBindingTagIsDeterministicAndNonceBound(): void
    {
        $a = Issuer::bindingTag(self::NONCE, '203.0.113.7', Vectors::SECRET);
        self::assertSame($a, Issuer::bindingTag(self::NONCE, '203.0.113.7', Vectors::SECRET));
        self::assertNotSame($a, Issuer::bindingTag('different-nonce', '203.0.113.7', Vectors::SECRET));
        self::assertNotSame($a, Issuer::bindingTag(self::NONCE, '198.51.100.9', Vectors::SECRET));
    }

    public function testBindingTagRejectsInvalidIps(): void
    {
        foreach (['', 'not-an-ip', '999.1.1.1', '203.0.113', '300.1.1.1'] as $bad) {
            try {
                Issuer::bindingTag(self::NONCE, $bad, Vectors::SECRET);
                self::fail("'$bad' should have been rejected");
            } catch (\InvalidArgumentException $e) {
                self::assertSame('Invalid IP address', $e->getMessage());
            }
        }
    }

    public function testCanonicalPayloadExactFormat(): void
    {
        $canonical = Issuer::canonicalPayload(
            'nonce123',
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            'c2FsdA==',
            5,
        );

        // Canonical v2 layout: the canonical carries
        // region (empty when unset), policy_version, request_binding (empty
        // when unset), issuer (empty when unset), and the FINAL kid segment
        // (default 1) — byte-identical to the Rust canonical_signing_input_v2.
        self::assertSame('v2|nonce123|login|tag456|111|222|sha256|0|1|1|8|c2FsdA==|5||1|||1', $canonical);
    }

    public function testCanonicalPayloadCarriesIssuerThenKidAsFinalSegments(): void
    {
        // The issuer is appended AFTER request_binding, and
        // kid is the FINAL canonical field — issuer "prod" + kid 3 end the
        // canonical with |prod|3.
        $canonical = Issuer::canonicalPayload(
            'nonce123',
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            'c2FsdA==',
            5,
            null,
            2,
            'txn-1',
            'prod',
            3,
        );

        self::assertSame('v2|nonce123|login|tag456|111|222|sha256|0|1|1|8|c2FsdA==|5||2|txn-1|prod|3', $canonical);
    }

    public function testCanonicalPayloadKidDefaultsToOne(): void
    {
        $canonical = Issuer::canonicalPayload(
            'nonce123',
            'login',
            'tag456',
            111,
            222,
            PoWAlgorithm::Sha256,
            0,
            1,
            1,
            8,
            'c2FsdA==',
            5,
        );

        self::assertStringEndsWith('|1', $canonical, 'kid defaults to 1 and is always the final canonical field');
    }

    public function testNewRecordDefaultsToProtocolV2(): void
    {
        $record = $this->record();

        self::assertSame(2, $record->protocolVersion);
        self::assertSame('tag123', $record->bindingTag);
        self::assertSame('tag123', $record->ipHash(), 'compat accessor must expose the binding tag');
    }

    public function testToArrayEmitsBindingTagOnlyAndProtocolVersion(): void
    {
        $data = $this->record()->toArray();

        self::assertSame('tag123', $data['binding_tag']);
        // The legacy ip_hash key must NOT be emitted alongside binding_tag:
        // the Rust reader uses #[serde(alias = "ip_hash")] and serde rejects
        // a struct carrying both the field and its alias as a duplicate
        // field — a dual-key record would be unreadable by Rust (caught by
        // the live cross-language round trip). Writers emit the v2 key only;
        // readers still ACCEPT ip_hash-only legacy records.
        self::assertArrayNotHasKey('ip_hash', $data);
        self::assertSame(2, $data['protocol_version']);
        self::assertSame(1, $data['kid'], 'toArray must always emit the kid key');
    }

    public function testFromArrayBindingTagDefaultsToProtocolV2(): void
    {
        $record = ChallengeRecord::fromArray($this->record()->toArray());

        self::assertSame(2, $record->protocolVersion);
        self::assertSame('tag123', $record->bindingTag);
        self::assertSame('tag123', $record->ipHash());
    }

    public function testFromArrayAcceptsLegacyIpHashOnlyAsV1(): void
    {
        $data = $this->record()->toArray();
        unset($data['binding_tag'], $data['protocol_version']);
        $data['ip_hash'] = 'legacyhash';

        $record = ChallengeRecord::fromArray($data);

        self::assertSame(1, $record->protocolVersion, 'records carrying only ip_hash are protocol v1');
        self::assertSame('legacyhash', $record->bindingTag);
        self::assertSame('legacyhash', $record->ipHash());
    }

    public function testFromArrayRejectsBindingTagAlongsideIpHashAlias(): void
    {
        // The Rust reader uses serde #[serde(alias = "ip_hash")] and rejects
        // a struct carrying BOTH the field and its alias as a duplicate
        // field — the strict parser mirrors that.
        $data = $this->record()->toArray();
        $data['ip_hash'] = 'stale-mirror';

        try {
            ChallengeRecord::fromArray($data);
            self::fail('a record carrying both binding_tag and ip_hash must be rejected');
        } catch (\KiwiCaptcha\MalformedRecordException $e) {
            self::assertStringContainsString('binding_tag', $e->getMessage());
        }
    }

    public function testBindingModeNoneIssuesEmptyBindingTagAndVerifies(): void
    {
        $config = new \KiwiCaptcha\Config(
            secretKey: '0123456789abcdef0123456789abcdef',
            targetBits: 8,
            bindingMode: \KiwiCaptcha\BindingMode::None,
        );
        $storage = new \KiwiCaptcha\Storage\ArrayStorage();
        $issuer = new \KiwiCaptcha\Issuer($config, $storage);
        $challenge = $issuer->issue('login', '192.168.1.5');

        // The signed v2 canonical must carry an EMPTY binding-tag segment
        // (v2|nonce|scope|binding_tag|...).
        $canonical = base64_decode(explode('.', $challenge->challenge)[0], true);
        $parts = explode('|', (string) $canonical);
        self::assertSame('v2', $parts[0]);
        self::assertSame('', $parts[3], 'binding-mode none must produce an empty binding tag');

        $verifier = new \KiwiCaptcha\Verifier($storage);
        $counter = 0;
        do {
            $h = hash('sha256', $challenge->prefix . $counter . base64_decode($challenge->salt, true), true);
            $counter++;
        } while (\KiwiCaptcha\Verifier::leadingZeroBits($h) < $challenge->targetBits);
        --$counter;
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $outcome = $verifier->verify($token, '0123456789abcdef0123456789abcdef', 'login', '10.0.0.99', (int) (microtime(true) * 1_000_000) + 1_000_000);
        self::assertTrue($outcome->isOk(), sprintf('expected valid with any IP, got %s', $outcome->code()));
    }
}
