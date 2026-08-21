<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Admission control for memory-hard (Argon2id) verifications.
 *
 * `acquire()` returns an opaque lease token when capacity is available,
 * or null when capacity is exhausted. On exhaustion the verification is
 * rejected with {@see VerifyError::CapacityExceeded} and the challenge
 * record is left untouched; the client may retry shortly.
 *
 * `release()` must be called exactly once per successful acquire; the
 * lease token identity protects against stale releases (e.g. a release
 * that outlived its acquire, or a double-release of an already-expired
 * lease).
 */
interface VerificationAdmissionGate
{
    /**
     * Acquire an Argon2 admission slot. Returns an opaque lease token,
     * or null when capacity is exhausted (the challenge stays intact and
     * can be retried). Implementations must not throw for ordinary
     * capacity exhaustion; a backend outage may throw, and the verifier
     * translates it into a typed, non-consuming AdmissionUnavailable
     * result.
     */
    public function acquire(): ?string;

    /**
     * Release an acquired lease. Must not throw into verification: a
     * failed release is best-effort (a leaked slot is recovered by the
     * lease TTL) and must not override a completed verification result.
     */
    public function release(string $lease): void;
}
