<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Verifies client-submitted solutions — byte-for-byte compatible with the
 * Rust crate's `verify_solution`.
 *
 * Verification is ONE-SHOT: consume-on-verify removes the challenge record
 * BEFORE the proof is checked, so a wrong candidate burns the challenge —
 * the client must fetch and solve a fresh one. This deliberately bounds the
 * server-side cost of memory-hard verification: each submitted token can
 * cost at most one Argon2id (or SHA-256) hash, and replaying a token always
 * fails with RecordNotFound. There is no maxAttempts parameter: the
 * one-shot model IS the attempt bound.
 *
 * Check order:
 *   1. Re-check the challenge HMAC signature (constant-time compare).
 *   2. TTL: now < expires_at.
 *   3. Scope: challenge scope matches the expected flow.
 *   4. Minimum duration: measured SERVER-SIDE from the record's issued_at_ns
 *      (epoch microseconds) to the verification receipt time — the
 *      client-reported duration can no longer be forged to bypass the floor.
 *      Records without issued_at_ns (pre-upgrade) fall back to the legacy
 *      client-duration check. Host clock skew up to SKEW_TOLERANCE_US is
 *      absorbed (the floor check is skipped, the PoW check still applies);
 *      a receipt time that precedes issuance beyond the tolerance is
 *      impossible and rejected as TooFast.
 *   5. Telemetry (optional, opt-in): when enforceTelemetry is set, the
 *      client-controlled telemetry is scored and bot signals rejected.
 *   6. Re-derive the hash (SHA-256 or Argon2id per the record's algorithm)
 *      and require >= target_bits leading zero bits.
 */
final class Verifier
{
    /**
     * Host-clock skew tolerance for the server-measured minimum-duration
     * check, in MICROSECONDS.
     *
     * issued_at_ns is a wall-clock timestamp written by whichever host
     * issued the challenge; verification may run on a different host whose
     * clock is slightly behind. A receipt time that precedes issuance by
     * less than the tolerance is therefore treated as unmeasurable elapsed
     * time (the floor check is skipped for that verification — the PoW
     * check still applies), while a receipt time preceding issuance by
     * MORE than the tolerance is physically impossible and rejected as
     * TooFast. Hosts should be NTP-synced; 5s of skew is a generous bound.
     */
    private const SKEW_TOLERANCE_US = 5_000_000;

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
     * @param int|null    $nowNs           server receipt time in epoch
     *                                     MICROSECONDS (defaults to
     *                                     microtime(true) * 1e6); used for
     *                                     the server-measured minimum-duration
     *                                     check. Test hook.
     * @param bool        $enforceTelemetry when true, bot-signal telemetry is
     *                                     rejected with TelemetryRejected.
     *                                     Telemetry is client-controlled, so
     *                                     enforcement is opt-in defense-in-depth
     *                                     only.
     *
     * One-shot model: the record is consumed BEFORE any check, so a failed
     * verification burns the challenge (no maxAttempts parameter — the
     * consume-on-verify semantics ARE the attempt bound).
     */
    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        bool $enforceTelemetry = false,
    ): VerifyOutcome {
        try {
            $token = SolutionToken::decode($rawToken);
        } catch (DecodeError $e) {
            return VerifyOutcome::malformedToken($e->getMessage());
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

        // 3. Minimum duration, measured on the SERVER: elapsed_us is the gap
        //    between the record's high-resolution issuance timestamp (epoch
        //    microseconds) and the verification receipt time. The
        //    client-reported durationMs is forgeable, so it no longer drives
        //    the TooFast check — it is kept only as telemetry input below.
        //
        //    Backward compatibility: records without issued_at_ns (issued by
        //    older builds) fall back to the legacy client-duration check so
        //    pre-upgrade stored challenges keep behaving predictably.
        $floor = max(0, $record->minDurationMs);
        $tooFast = false;
        if ($record->issuedAtNs > 0) {
            // Epoch-microsecond domain: both values are wall clock, so the
            // elapsed delta is comparable across hosts (unlike the per-host
            // monotonic hrtime() domain).
            $receiptNs = $nowNs ?? (int) (microtime(true) * 1_000_000);
            $elapsedUs = $receiptNs - $record->issuedAtNs;
            if ($elapsedUs < 0) {
                if ($elapsedUs < -self::SKEW_TOLERANCE_US) {
                    // Receipt before issuance by more than the skew bound is
                    // physically impossible — reject as TooFast.
                    $tooFast = true;
                } else {
                    // Receipt before issuance within the skew bound: the two
                    // hosts' clocks are slightly unsynced, so the elapsed
                    // time cannot be measured reliably. Skip the floor check
                    // for this verification — the proof-of-work check still
                    // applies, so no attacker advantage is gained.
                    $tooFast = false;
                }
            } else {
                $tooFast = $floor > 0 && $elapsedUs < $floor * 1_000;
            }
        } else {
            $tooFast = $floor > 0 && $token->durationMs < $floor;
        }
        if ($tooFast) {
            return VerifyOutcome::invalid(VerifyError::TooFast);
        }

        // 3b. Telemetry scoring (opt-in). The telemetry is client-controlled,
        //     so this is a defense-in-depth signal, not a hard gate — it only
        //     runs when the caller explicitly opts in. An EMPTY telemetry
        //     payload ({} or []) is itself a bot signal (a real widget always
        //     reports fields): it must not bypass strict mode.
        if ($enforceTelemetry && (empty($token->telemetry) || Telemetry::score($token->telemetry, $token->durationMs))) {
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
     * computed (e.g. Argon2id parameters outside KiwiCaptcha's protocol
     * profile — t < 3 or p != 1).
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
        // KiwiCaptcha's protocol profile is p == 1 && t >= 3 (t >= 3 is
        // intentional, not a libsodium limit — libsodium accepts t >= 1).
        // Parameters outside the profile cannot be reproduced by the
        // libsodium-backed verifier, so fail closed with a distinguishable
        // error instead of silently verifying wrong bytes.
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
