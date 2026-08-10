<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Verifies client-submitted solutions — byte-for-byte compatible with the
 * Rust crate's `verify_solution`.
 *
 * Check order (mirrors Rust exactly):
 *   1. Re-check the challenge HMAC signature (constant-time compare).
 *   2. TTL: now < expires_at.
 *   3. Scope: challenge scope matches the expected flow.
 *   4. Minimum duration: duration_ms >= floor (per-challenge derived value).
 *   5. Re-derive the hash (SHA-256 or Argon2id per the record's algorithm)
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

    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
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

        // 3. Minimum duration.
        $floor = max(0, $record->minDurationMs);
        if ($floor > 0 && $token->durationMs < $floor) {
            return VerifyOutcome::invalid(VerifyError::TooFast);
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
