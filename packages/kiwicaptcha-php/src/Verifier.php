<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Verifies client-submitted solutions — byte-for-byte compatible with the
 * Rust crate's `verify_solution`.
 *
 * Check order:
 *   0. Attempt cap (optional): an atomic per-nonce attempt counter is
 *      incremented BEFORE the record is consumed; exceeding the cap fails
 *      with TooManyAttempts. Backends without atomic counters (PSR-6,
 *      in-memory) only track attempts — consume()'s single-use semantics are
 *      the actual gate.
 *   1. Re-check the challenge HMAC signature (constant-time compare).
 *   2. TTL: now < expires_at.
 *   3. Scope: challenge scope matches the expected flow.
 *   4. Minimum duration: measured SERVER-SIDE from the record's issued_at_ns
 *      to the verification timestamp — the client-reported duration can no
 *      longer be forged to bypass the floor. Records without issued_at_ns
 *      (pre-upgrade) fall back to the legacy client-duration check.
 *   5. Telemetry (optional, opt-in): when enforceTelemetry is set, the
 *      client-controlled telemetry is scored and bot signals rejected.
 *   6. Re-derive the hash (SHA-256 or Argon2id per the record's algorithm)
 *      and require >= target_bits leading zero bits.
 */
final class Verifier
{
    /**
     * @var \Closure|null clock override for tests
     */
    private $now;

    public function __construct(private readonly StorageInterface $storage, ?\Closure $now = null)
    {
        $this->now = $now;
    }

    /**
     * @param string      $rawToken        base64 solution token from the widget
     * @param string      $secretKey       HMAC secret key
     * @param string|null $expectedScope   required challenge scope (null = any)
     * @param string|null $clientIp        client IP for the optional IP binding
     * @param int|null    $nowNs           server receipt time in nanoseconds
     *                                     (defaults to hrtime(true)); used for
     *                                     the server-measured minimum-duration
     *                                     check. Test hook.
     * @param bool        $enforceTelemetry when true, bot-signal telemetry is
     *                                     rejected with TelemetryRejected.
     *                                     Telemetry is client-controlled, so
     *                                     enforcement is opt-in defense-in-depth
     *                                     only.
     * @param int|null    $maxAttempts     when set, an atomic per-nonce attempt
     *                                     counter is enforced before the record
     *                                     is consumed; exceeded caps fail with
     *                                     TooManyAttempts
     */
    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
        ?int $maxAttempts = null,
    ): VerifyOutcome {
        try {
            $token = SolutionToken::decode($rawToken);
        } catch (DecodeError $e) {
            return VerifyOutcome::malformedToken($e->getMessage());
        }

        // 0. Attempt cap (checked BEFORE consume so the counter is
        //    incremented even for tokens whose records are already gone —
        //    replay floods still count).
        if ($maxAttempts !== null && !$this->storage->incrementAttempts($token->nonce, $maxAttempts)) {
            return VerifyOutcome::invalid(VerifyError::TooManyAttempts);
        }

        $record = $this->storage->consume($token->nonce);
        if ($record === null) {
            return VerifyOutcome::invalid(VerifyError::RecordNotFound);
        }

        // 1. Signature re-check: reconstruct the payload from the record and
        //    compare against the signature embedded in the challenge string.
        $payload = sprintf(
            '%s|%s|%s|%d',
            $record->nonce,
            $record->scope,
            $record->ipHash,
            $record->issuedAt,
        );
        $signature = self::signatureFromChallenge($record->challenge);
        $expected = Issuer::signPayload($payload, $secretKey);
        if (!self::constantTimeEquals($expected, $signature)) {
            return VerifyOutcome::invalid(VerifyError::BadSignature);
        }

        // 2. TTL.
        $now = $this->now !== null ? (int) ($this->now)() : time();
        if ($now >= $record->expiresAt) {
            return VerifyOutcome::invalid(VerifyError::Expired);
        }

        // 2b. Scope validation.
        if ($expectedScope !== null && $record->scope !== $expectedScope) {
            return VerifyOutcome::invalid(VerifyError::WrongScope);
        }

        // 2c. IP binding (optional but recommended): challenge issued to one
        //     client, submitted from another = relay attack.
        if ($clientIp !== null) {
            $expectedIp = Issuer::hashIp($clientIp, $secretKey);
            if ($record->ipHash !== $expectedIp) {
                return VerifyOutcome::invalid(VerifyError::IpMismatch);
            }
        }

        // 3. Minimum duration, measured on the SERVER: elapsed_ns is the gap
        //    between the record's high-resolution issuance timestamp and the
        //    verification timestamp. The client-reported durationMs is
        //    forgeable, so it no longer drives the TooFast check — it is kept
        //    only as telemetry input below.
        //
        //    Backward compatibility: records without issued_at_ns (issued by
        //    older builds) fall back to the legacy client-duration check so
        //    pre-upgrade stored challenges keep behaving predictably.
        $floor = max(0, $record->minDurationMs);
        $tooFast = false;
        if ($record->issuedAtNs > 0) {
            // hrtime(true) is already nanoseconds; no scaling (1e9 would
            // overflow int64 within seconds of uptime).
            $receiptNs = $nowNs ?? (int) hrtime(true);
            $tooFast = $floor > 0 && $receiptNs - $record->issuedAtNs < $floor * 1_000_000;
        } else {
            $tooFast = $floor > 0 && $token->durationMs < $floor;
        }
        if ($tooFast) {
            return VerifyOutcome::invalid(VerifyError::TooFast);
        }

        // 3b. Telemetry scoring (opt-in). The telemetry is client-controlled,
        //     so this is a defense-in-depth signal, not a hard gate — it only
        //     runs when the caller explicitly opts in.
        if ($enforceTelemetry && !empty($token->telemetry) && Telemetry::score($token->telemetry, $token->durationMs)) {
            return VerifyOutcome::invalid(VerifyError::TelemetryRejected);
        }

        // 4. Re-derive the hash and check leading zero bits.
        $hash = $this->deriveHash($record, $token->counter);
        if ($hash === null) {
            return VerifyOutcome::invalid(VerifyError::MalformedRecord);
        }
        if (self::leadingZeroBits($hash) < $record->targetBits) {
            return VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }

        return VerifyOutcome::valid();
    }

    /**
     * Re-derive the proof-of-work hash.
     *
     * SHA-256: hash(prefix || decimal(counter) || salt_bytes)
     * Argon2id: argon2id(password=prefix||decimal(counter), salt=salt_bytes,
     *           m_cost=m_kib KiB, t_cost=t, p_cost=p, output=32 bytes)
     *
     * Returns null when the record is malformed or the algorithm cannot be
     * computed (e.g. Argon2id parameters outside libsodium's representable
     * range — t < 3 or p != 1).
     */
    private function deriveHash(ChallengeRecord $record, int $counter): ?string
    {
        $saltBytes = base64_decode($record->salt, true);
        if ($saltBytes === false) {
            return null;
        }
        $password = $record->prefix.$counter;

        return match ($record->algorithm) {
            PoWAlgorithm::Sha256 => hash('sha256', $password.$saltBytes, true),
            PoWAlgorithm::Argon2id => $this->argon2id($password, $saltBytes, $record),
        };
    }

    private function argon2id(string $password, string $saltBytes, ChallengeRecord $record): ?string
    {
        // libsodium maps opslimit == t_cost and memlimit == bytes, but only
        // supports p == 1 and t >= 3 (opslimit minimum). Parameters outside
        // this range cannot be reproduced by libsodium, so fail closed with a
        // distinguishable error instead of silently verifying wrong bytes.
        if ($record->p !== 1 || $record->t < 3) {
            return null;
        }
        $memlimit = $record->mKib * 1024;
        if ($memlimit < 8192) {
            return null;
        }

        $hash = sodium_crypto_pwhash(
            32,
            $password,
            $saltBytes,
            $record->t,
            $memlimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        return $hash === false ? null : $hash;
    }

    /**
     * The signature is the hex tag after the last '.' in the challenge string
     * (the base64 payload contains no dots).
     */
    private static function signatureFromChallenge(string $challenge): string
    {
        $pos = strrpos($challenge, '.');
        if ($pos === false) {
            return '';
        }

        return substr($challenge, $pos + 1);
    }

    /**
     * Constant-time string comparison (XOR accumulation, no short-circuit).
     */
    public static function constantTimeEquals(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * Count leading zero BITS of a 32-byte hash (big-endian bit order) —
     * identical to Rust's leading_zero_bits.
     */
    public static function leadingZeroBits(string $hash): int
    {
        $count = 0;
        $len = \strlen($hash);
        for ($i = 0; $i < $len; $i++) {
            $byte = \ord($hash[$i]);
            if ($byte === 0) {
                $count += 8;
                continue;
            }
            $b = $byte;
            while (($b & 0x80) === 0) {
                $count++;
                $b <<= 1;
            }
            break;
        }

        return $count;
    }
}
