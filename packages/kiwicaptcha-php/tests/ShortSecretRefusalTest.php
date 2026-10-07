<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The documented 16-byte HMAC secret minimum is enforced at every
 * verification seam, fail closed.
 *
 * The constructor already refuses a sub-16-byte secretsByKid entry; the
 * legacy single-secret path is a per-call parameter, and
 * signPayloadV2() deliberately does not re-check the length, so without
 * the checkAuthenticatedShape gate a caller passing a short secret
 * would verify a record signed under that same short secret (the
 * pre-fix behavior this test pins). The Rust production verifier
 * enforces the identical minimum at its resolve_signing_secret seam
 * (BadSignature), so both languages fail the same way.
 */
final class ShortSecretRefusalTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    /** 32 bytes: the ordinary conforming secret. */
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** 12 bytes: below the documented 16-byte minimum. */
    private const SHORT = 'short-secret';

    private const IP = '198.51.100.7';

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    /**
     * An otherwise fully authentic record re-signed under the short
     * secret: the canonical payload is unchanged, the challenge
     * signature and the IP-binding tag are recomputed with the short
     * secret's derived keys, and the prefix is rebuilt to match. Every
     * other gate (shape, TTL, scope, IP binding, timing floor, PoW) is
     * satisfiable, so only the secret minimum can reject it.
     *
     * @return array{0: ArrayStorage, 1: ChallengeRecord, 2: string}
     */
    private function shortSecretFixture(): array
    {
        self::assertLessThan(16, \strlen(self::SHORT));

        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        // Recompute the binding tag under the short secret first, then
        // sign the canonical the verifier will reconstruct from those
        // patched fields (the binding tag is part of the canonical).
        $patched = $record->toArray();
        $patched['binding_tag'] = Issuer::bindingTag($patched['nonce'], self::IP, self::SHORT);
        $canonical = Issuer::canonicalPayload(
            $patched['nonce'],
            $patched['scope'],
            $patched['binding_tag'],
            $patched['issued_at'],
            $patched['expires_at'],
            PoWAlgorithm::from($patched['algorithm']),
            $patched['m_kib'],
            $patched['t'],
            $patched['p'],
            $patched['target_bits'],
            $patched['salt'],
            $patched['min_duration_ms'],
            $patched['region'],
            $patched['policy_version'] ?? 1,
            $patched['request_binding'],
            $patched['issuer'],
            $patched['kid'] ?? 1,
            $patched['decoy_field'] ?? null,
            $patched['execution_version'] ?? null,
            $patched['execution_commitment'] ?? null,
        );
        $patched['challenge'] = base64_encode($canonical).'.'.Issuer::signPayloadV2($canonical, self::SHORT);
        $patched['prefix'] = $patched['challenge'].'|'.$patched['salt'].'|';
        $forged = ChallengeRecord::fromArray($patched);

        $fresh = new ArrayStorage();
        $fresh->store($forged);
        $counter = $this->solve($forged->prefix, $forged->salt, $forged->targetBits);
        $token = SolutionToken::create($forged->nonce, $counter, 5000, [])->encode();

        return [$fresh, $forged, $token];
    }

    public function testShortLegacySecretIsRefusedAtVerifyTime(): void
    {
        // Pre-fix this record verified as Valid: every other gate passes
        // (the signature and the binding tag are internally consistent
        // under the short secret), so the secret minimum is the only
        // check that can reject it.
        [$storage, $record, $token] = $this->shortSecretFixture();

        $outcome = (new Verifier($storage, null, static fn (): int => self::ISSUED_AT))->verify(
            $token,
            self::SHORT,
            'login',
            self::IP,
            $record->issuedAtNs + 10_000_000,
        );

        self::assertFalse($outcome->isOk(), 'a sub-16-byte secret must never verify');
        self::assertSame(
            VerifyError::BadSignature,
            $outcome->error(),
            'the short-secret refusal is the BadSignature class, the Rust production verifier twin'
        );
    }

    public function testShortPerKidSecretIsRefusedAtConstruction(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 16 bytes');

        new Verifier(new ArrayStorage(), secretsByKid: [1 => self::SHORT]);
    }

    public function testConformingSecretStillVerifiesTheSameShape(): void
    {
        // The control: the identical fixture flow signed with a
        // conforming secret verifies as Valid, proving the refusal above
        // comes from the length gate, not from the fixture being
        // unsatisfiable.
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::IP);
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $counter = $this->solve($record->prefix, $record->salt, $record->targetBits);
        $token = SolutionToken::create($record->nonce, $counter, 5000, [])->encode();

        $outcome = (new Verifier($storage, null, static fn (): int => self::ISSUED_AT))->verify(
            $token,
            self::SECRET,
            'login',
            self::IP,
            $record->issuedAtNs + 10_000_000,
        );

        self::assertTrue($outcome->isOk(), 'a conforming secret verifies the same flow');
    }
}
