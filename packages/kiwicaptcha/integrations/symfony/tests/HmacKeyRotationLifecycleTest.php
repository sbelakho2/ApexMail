<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\VerificationSecurityContext;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end HMAC key-rotation lifecycle against the real php-core Issuer
 * and Verifier, using the exact keyring the bundle wires (the
 * VerificationSecurityContext->acceptedKeys() effective ring). This is the
 * regression test for the security-audit finding: the verifier used to
 * receive only the historical secrets_by_kid map, so a freshly issued
 * challenge under the rotated (current) kid failed UnknownKid the moment
 * the map was non-empty.
 *
 * The lifecycle mirrors the documented rotation procedure:
 *  1. issue under kid 2 / key A, verify OK;
 *  2. rotate to kid 3 / key B: the still-outstanding kid-2 challenge still
 *     verifies (rotation grace) and a fresh kid-3 challenge verifies;
 *  3. revoke kid 2: the kid-2 challenge now fails UnknownKid while the
 *     kid-3 challenge still passes;
 *  4. a future kid-4 challenge fails UnknownKid under the {2, 3} ring
 *     (the core rollback/forward guard).
 *
 * Every stage uses fresh records (each verify consumes its record).
 */
final class HmacKeyRotationLifecycleTest extends TestCase
{
    private const KEY_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const KEY_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const KEY_C = 'cccccccccccccccccccccccccccccccc';
    private const IP = '198.51.100.7';

    public function testRotationGraceRevocationAndForwardGuardLifecycle(): void
    {
        // ── Stage 1: issue under kid 2 / key A ──────────────────────────
        $storage = new ArrayStorage();
        $issuer2 = $this->issuer($storage, 2, self::KEY_A);
        $challenge1 = $issuer2->issue('login', self::IP);
        // Two further kid-2 records stay outstanding: one exercises the
        // rotation grace (stage 2), one the revocation (stage 3).
        $graceChallenge = $issuer2->issue('login', self::IP);
        $revokedChallenge = $issuer2->issue('login', self::IP);

        $context1 = new VerificationSecurityContext(2, self::KEY_A, [], []);
        self::assertSame([], $context1->acceptedKeys(), 'stage 1: no historical secrets means the legacy single-secret path (empty ring)');
        $verifier1 = $this->verifier($storage, $context1, []);
        $outcome = $verifier1->verify($this->solveToken($challenge1), self::KEY_A, 'login', self::IP);
        self::assertTrue($outcome->isOk(), sprintf(
            'stage 1: a fresh kid-2 challenge signed with key A must verify (got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));

        // ── Stage 2: rotate to kid 3 / key B ────────────────────────────
        $context2 = new VerificationSecurityContext(3, self::KEY_B, [2 => self::KEY_A], []);
        self::assertSame(
            [2 => self::KEY_A, 3 => self::KEY_B],
            $context2->acceptedKeys(),
            'stage 2: the effective ring must merge the historical map with the current signing key, kid-sorted'
        );
        $verifier2 = $this->verifier($storage, $context2, []);
        $outcome = $verifier2->verify($this->solveToken($graceChallenge), self::KEY_B, 'login', self::IP);
        self::assertTrue($outcome->isOk(), sprintf(
            'stage 2: the still-outstanding kid-2 challenge must verify under the rotated ring (rotation grace, got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));

        $issuer3 = $this->issuer($storage, 3, self::KEY_B);
        $challenge3 = $issuer3->issue('login', self::IP);
        $outcome = $verifier2->verify($this->solveToken($challenge3), self::KEY_B, 'login', self::IP);
        self::assertTrue($outcome->isOk(), sprintf(
            'stage 2: a fresh kid-3 challenge signed with key B must verify (the audit-fix regression: got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));

        // ── Stage 3: revoke kid 2 ───────────────────────────────────────
        $context3 = new VerificationSecurityContext(3, self::KEY_B, [2 => self::KEY_A], [2]);
        $verifier3 = $this->verifier($storage, $context3, [2]);
        $outcome = $verifier3->verify($this->solveToken($revokedChallenge), self::KEY_B, 'login', self::IP);
        self::assertSame(VerifyError::UnknownKid, $outcome->error, sprintf(
            'stage 3: the kid-2 challenge must fail UnknownKid once kid 2 is revoked, even though key A is still in the ring (got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));

        $challenge3b = $issuer3->issue('login', self::IP);
        $outcome = $verifier3->verify($this->solveToken($challenge3b), self::KEY_B, 'login', self::IP);
        self::assertTrue($outcome->isOk(), sprintf(
            'stage 3: a fresh kid-3 challenge must still verify after the kid-2 revocation (got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));

        // ── Stage 4: future key rejected by the rollback/forward guard ──
        $issuer4 = $this->issuer($storage, 4, self::KEY_C);
        $challenge4 = $issuer4->issue('login', self::IP);
        $verifier4 = $this->verifier($storage, $context2, []);
        $outcome = $verifier4->verify($this->solveToken($challenge4), self::KEY_B, 'login', self::IP);
        self::assertSame(VerifyError::UnknownKid, $outcome->error, sprintf(
            'stage 4: a kid-4 challenge (future key) must fail UnknownKid under the {2, 3} ring: the rollback/forward guard rejects a record whose kid exceeds the newest ring key (got %s: %s)',
            $outcome->code(),
            (string) $outcome->detail,
        ));
    }

    private function issuer(ArrayStorage $storage, int $kid, string $secret): Issuer
    {
        return new Issuer(new Config(
            $secret,
            targetBits: 8,
            minDurationMs: 0,
            kid: $kid,
        ), $storage);
    }

    private function verifier(ArrayStorage $storage, VerificationSecurityContext $context, array $revokedKids): Verifier
    {
        return new Verifier(
            $storage,
            secretsByKid: $context->acceptedKeys(),
            revokedKids: $revokedKids,
        );
    }

    private function solveToken(Challenge $challenge): string
    {
        $salt = base64_decode($challenge->salt, true);
        $base = hash_init('sha256');
        hash_update($base, $challenge->prefix);
        $counter = 0;
        do {
            $ctx = hash_copy($base);
            hash_update($ctx, (string) $counter);
            hash_update($ctx, $salt);
            $hash = hash_final($ctx, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

        return SolutionToken::create($challenge->nonce, $counter - 1, 5000, [])->encode();
    }
}
