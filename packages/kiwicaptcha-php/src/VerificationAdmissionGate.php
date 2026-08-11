<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Admission control for memory-hard (Argon2id) verifications.
 *
 * `acquire()` returns an opaque lease token when capacity is available, or
 * null when capacity is exhausted. On exhaustion the verification is
 * rejected with {@see VerifyError::CapacityExceeded} and the challenge
 * record is left untouched — the client may retry shortly.
 *
 * `release()` must be called exactly once per successful acquire; the lease
 * token identity protects against stale releases (e.g. a release that
 * outlived its acquire, or a double-release of an already-expired lease).
 */
interface VerificationAdmissionGate
{
    public function acquire(): ?string;

    public function release(string $lease): void;
}
