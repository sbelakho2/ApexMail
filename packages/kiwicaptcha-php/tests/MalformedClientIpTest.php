<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * A bound record presented with a client IP that cannot be canonicalized
 * at all — a non-address string, a zoned IPv6 like `fe80::1%eth0`, an
 * empty string — resolves to the typed IpMismatch. This holds on every
 * path that re-derives the binding tag, never an escaped exception. The
 * binding-tag derivation throws {@see \InvalidArgumentException} on such
 * inputs; the verifier maps that to the mismatch vocabulary because a
 * non-canonicalizable IP can never equal the tag an issuer derived from
 * a canonical address.
 */
final class MalformedClientIpTest extends TestCase
{
    private const ISSUED_AT = 1_800_000_000;

    private const IDENTITY = 'op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const BAD_IPS = ['not-an-ip-at-all!!', 'fe80::1%eth0', ''];

    /** @return array{0: ArrayStorage, 1: string} [storage, solved token] */
    private function issueAndSolve(): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: Vectors::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return [$storage, SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode()];
    }

    /**
     * @dataProvider provideBadIps
     */
    public function testVerifyWithAMalformedClientIpIsTheTypedIpMismatch(string $badIp): void
    {
        [$storage, $token] = $this->issueAndSolve();
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', $badIp, nowNs: 1_800_000_000_000_000);

        self::assertSame(VerifyError::IpMismatch, $outcome->error, sprintf('a non-canonicalizable client IP must yield the typed ip_mismatch, got %s', $outcome->code()));
        self::assertNull($storage->find(SolutionToken::decode($token)->nonce), 'the pending record is burned by the one-shot failure');
    }

    /**
     * @dataProvider provideBadIps
     */
    public function testVerifyOnAConsumedRecordWithAMalformedClientIpNeverEscapesAnException(string $badIp): void
    {
        // The IP binding is a replay-exempt circumstance: on a consumed
        // record the malformed IP routes into the identity-gated consumed
        // branch exactly like a valid-format wrong IP does, resolving the
        // stored result for the proven operation — never an escaped
        // InvalidArgumentException from the tag derivation.
        [$storage, $token] = $this->issueAndSolve();
        $nonce = SolutionToken::decode($token)->nonce;
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        \KiwiCaptcha\Tests\Fixtures\ServerState::commit($storage, $nonce, true, null);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->verify($token, Vectors::SECRET, 'login', $badIp, nowNs: 1_800_000_000_000_000, operationIdentity: self::IDENTITY);

        self::assertTrue($outcome->isOk(), sprintf('the exempt malformed-IP replay resolves the stored success for the proven operation, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the resolution is the stored result, never a fresh derivation');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives');
    }

    /**
     * @dataProvider provideBadIps
     */
    public function testResumeConsumedOperationWithAMalformedClientIpIsTheTypedIpMismatch(string $badIp): void
    {
        [$storage, $token] = $this->issueAndSolve();
        $nonce = SolutionToken::decode($token)->nonce;
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->resumeConsumedOperation($token, Vectors::SECRET, self::IDENTITY, 'login', $badIp);

        self::assertSame(VerifyError::IpMismatch, $outcome->error, sprintf('the resumed recovery with a non-canonicalizable IP must yield the typed ip_mismatch, got %s', $outcome->code()));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function provideBadIps(): iterable
    {
        foreach (self::BAD_IPS as $i => $ip) {
            yield sprintf('bad-ip-%d: %s', $i, $ip === '' ? '(empty string)' : $ip) => [$ip];
        }
    }
}
