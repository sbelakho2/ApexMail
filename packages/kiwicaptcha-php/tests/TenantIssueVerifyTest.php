<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\DerivedKeys;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * Tenant-scoped issuance and verification: a non-null tenant id derives
 * the challenge-signing and IP-binding purpose keys under the per-tenant
 * root ("kiwi/v2/tenant/" + tenant id, the DerivedKeys tenant path whose
 * t1 root is pinned by the DerivedKeysTest reference vector). Tenants
 * of a shared master secret cannot forge each other's challenges. A null
 * tenant (the default) keeps the global keys, byte-identical to the
 * tenantless construction.
 */
final class TenantIssueVerifyTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /** @return array{0: ArrayStorage, 1: string} [storage, solved token] */
    private function issueAndSolve(?string $tenantId): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0, tenantId: $tenantId),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    private static function clock(): \Closure
    {
        return static fn (): int => self::ISSUED_AT;
    }

    public function testIssueAndVerifyRoundTripUnderTenantT1(): void
    {
        // The master secret is the DerivedKeys reference vector's
        // (0123456789abcdef0123456789abcdef); 't1' is the vector's
        // tenant, so both key derivations of this round trip are
        // anchored by the pinned tenant root.
        [$storage, $token] = $this->issueAndSolve('t1');
        $verifier = new Verifier($storage, now: self::clock(), tenantId: 't1');

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: 1_800_000_000_000_000);

        self::assertTrue($outcome->isOk(), sprintf('the tenant-scoped round trip must verify, got %s', $outcome->code()));
    }

    public function testTenantSignaturesUseTheTenantChallengeKey(): void
    {
        // The tenant-scoped signature is the HMAC under the t1 challenge
        // key exactly as DerivedKeys derives it, pinned to the shared
        // tenant-root reference vector and exercised through the
        // issuer's public signing helper.
        $payload = 'v2|payload';
        self::assertSame(
            hash_hmac('sha256', $payload, DerivedKeys::fromMaster(Vectors::SECRET, 't1')->challengeKey()),
            Issuer::signPayloadV2($payload, Vectors::SECRET, 't1'),
            'the tenant signing helper uses the per-tenant challenge key',
        );
        self::assertNotSame(
            Issuer::signPayloadV2($payload, Vectors::SECRET, 't1'),
            Issuer::signPayloadV2($payload, Vectors::SECRET, 't2'),
            'two tenants of one master sign differently',
        );
    }

    public function testAT1RecordFailsUnderT2AndUnderTheGlobalKeys(): void
    {
        // One fresh issuance per probe: a failed signature burns the
        // pending record (the one-shot model), so each verifier sees its
        // own t1 record.
        [$storageT1, $token] = $this->issueAndSolve('t1');
        $underT2 = new Verifier($storageT1, now: self::clock(), tenantId: 't2');
        $outcome = $underT2->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: 1_800_000_000_000_000);
        self::assertSame(VerifyError::BadSignature, $outcome->error, sprintf('a t1 record must fail the signature check under t2, got %s', $outcome->code()));

        [$storageT1b, $tokenB] = $this->issueAndSolve('t1');
        $underGlobal = new Verifier($storageT1b, now: self::clock());
        $outcome = $underGlobal->verify($tokenB, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: 1_800_000_000_000_000);
        self::assertSame(VerifyError::BadSignature, $outcome->error, sprintf('a t1 record must fail the signature check under the global keys, got %s', $outcome->code()));
    }

    public function testAGlobalRecordFailsUnderT1(): void
    {
        [$storage, $token] = $this->issueAndSolve(null);

        $underT1 = new Verifier($storage, now: self::clock(), tenantId: 't1');
        $outcome = $underT1->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: 1_800_000_000_000_000);
        self::assertSame(VerifyError::BadSignature, $outcome->error, sprintf('a global record must fail the signature check under t1, got %s', $outcome->code()));
    }

    public function testTheNullTenantIssuanceStaysByteIdentical(): void
    {
        // Default null = the tenantless behavior: the explicitly-null
        // tenant signature equals the no-argument helper, and a null
        // round trip verifies under a plain tenantless verifier.
        $payload = 'v2|payload';
        self::assertSame(Issuer::signPayloadV2($payload, Vectors::SECRET), Issuer::signPayloadV2($payload, Vectors::SECRET, null));

        [$storage, $token] = $this->issueAndSolve(null);
        $verifier = new Verifier($storage, now: self::clock());
        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', self::CLIENT_IP, nowNs: 1_800_000_000_000_000);
        self::assertTrue($outcome->isOk(), sprintf('the tenantless round trip keeps verifying, got %s', $outcome->code()));
    }

    /**
     * @dataProvider provideInvalidTenantIds
     */
    public function testAnInvalidTenantIdIsRejectedAtConstruction(string $tenantId): void
    {
        try {
            new Config(secretKey: Vectors::SECRET, tenantId: $tenantId);
            self::fail('an invalid tenant id must be rejected by Config');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('tenantId', $e->getMessage());
        }
        try {
            new Verifier(new ArrayStorage(), tenantId: $tenantId);
            self::fail('an invalid tenant id must be rejected by the Verifier');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('tenantId', $e->getMessage());
        }
    }

    /** @return iterable<string, array{0: string}> */
    public static function provideInvalidTenantIds(): iterable
    {
        yield 'empty string' => [''];
        yield '65 bytes' => [str_repeat('a', 65)];
        yield 'whitespace inside' => ['tenant one'];
        yield 'unicode' => ['tenanté'];
        yield 'canonical separator' => ['tenant|1'];
    }
}
