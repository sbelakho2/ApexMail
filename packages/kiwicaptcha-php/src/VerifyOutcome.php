<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Result of a solution verification.
 *
 * A valid outcome exposes the decoded solution token's nonce, the
 * canonical replay id (jti), via {@see self::nonce()}; the bundle
 * surfaces it so the consuming application can correlate accepted
 * proofs. Null for every non-valid outcome (including MalformedToken,
 * where no nonce could be decoded).
 *
 * A valid outcome also exposes the consumed record's application-supplied
 * transaction binding via {@see self::requestBinding()}. The host
 * application generated this nonce at issuance and must present it again
 * on the final protected POST, correlating the result with the exact
 * application transaction.
 *
 * A valid outcome additionally exposes the server-measured solve
 * duration via {@see self::solveDurationMs()}: the span between the
 * record's signed issuance clock (issued_at_ns) and the verification
 * receipt, computed without trusting any client-reported timing, the
 * token's durationMs is forgeable and never consulted. The value is
 * computed only for a fresh derivation, a first redemption or a fresh
 * resultless-resume derivation, where the receipt clock is the span's
 * true endpoint. On an identity-proven stored-result replay,
 * {@see self::fromStoredResult()}, the retry's receipt is not a
 * legitimate endpoint (the solve happened earlier), so the duration is
 * deliberately null rather than a confidently incorrect value, exactly
 * the Rust mirror's stored-result semantics. Null also when no duration
 * was measurable on a fresh derivation: a record without issued_at_ns,
 * or a receipt preceding issuance within the verifier's clock-skew
 * tolerance, see the Verifier docblock. Null for every non-valid
 * outcome; absent always meant "unmeasurable" in older consumers, so
 * the field is purely additive.
 *
 * A valid outcome additionally exposes the authenticated decoy
 * (honeypot) form-field name of the verified record via
 * {@see self::decoyField()}: the exact server-issued name the challenge
 * response carried, taken from the verified record. Fresh derivation
 * and stored-result replay alike: the ConsumedRecord carries the
 * record, so both can populate it. The validator compares the submitted
 * form field against this authenticated name; it is never reconstructed
 * from the nonce. Null when no decoy was armed (the surface disabled).
 */
final class VerifyOutcome
{
    private function __construct(
        public readonly bool $valid,
        public readonly ?VerifyError $error,
        public readonly ?string $detail,
        public readonly ?string $nonce,
        public readonly ?string $requestBinding,
        public readonly bool $fromStoredResult = false,
        public readonly ?int $solveDurationMs = null,
        public readonly ?string $decoyField = null,
    ) {
    }

    public static function valid(?string $nonce = null, ?string $requestBinding = null, bool $fromStoredResult = false, ?int $solveDurationMs = null, ?string $decoyField = null): self
    {
        return new self(true, null, null, $nonce, $requestBinding, $fromStoredResult, $solveDurationMs, $decoyField);
    }


    public static function invalid(VerifyError $error): self
    {
        return new self(false, $error, null, null, null);
    }

    public static function malformedToken(string $detail): self
    {
        return new self(false, VerifyError::MalformedToken, $detail, null, null);
    }

    public function isOk(): bool
    {
        return $this->valid;
    }

    /** Machine-readable error code ("" when valid). */
    public function code(): string
    {
        return $this->error?->value ?? '';
    }

    /**
     * The decoded solution token's nonce — the canonical replay id (jti) of
     * the verified challenge. Only non-null when the outcome is valid.
     */
    public function nonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * The consumed record's application-supplied transaction binding when
     * the outcome is valid, else null.
     */
    public function requestBinding(): ?string
    {
        return $this->requestBinding;
    }

    /**
     * The server-measured solve duration in milliseconds when the
     * outcome is valid AND a duration was measurable, else null.
     *
     * The value is the gap between the record's issued_at_ns and the
     * verification receipt clock: unforgeable behavioral evidence the
     * risk layer can consume as a graded signal, the client-reported
     * duration never feeds it. It is computed only for a fresh
     * derivation, a first redemption or a fresh resultless-resume
     * derivation. On an identity-proven stored-result replay,
     * {@see self::fromStoredResult()}, the retry's receipt is not the
     * solve's endpoint, so the duration is null rather than a
     * confidently incorrect value, the Rust mirror's stored-result
     * semantics. Null on every non-valid outcome, for a record whose
     * issuance clock is unknown, and for a receipt that precedes
     * issuance within the verifier's clock-skew tolerance, where the
     * elapsed time cannot be measured reliably. This mirrors the
     * semantics of the verifier's minimum-duration floor.
     */
    public function solveDurationMs(): ?int
    {
        return $this->solveDurationMs;
    }

    /**
     * The authenticated decoy (honeypot) form-field name of the verified
     * record when the outcome is valid, else null.
     *
     * The exact server-issued name the challenge response carried, taken
     * from the verified record: the consuming validator must compare the
     * submitted form field against this authenticated name and never
     * reconstruct it from the nonce (the audit's "no second nonce-hash
     * scheme"). Populated on fresh derivations and stored-result replays
     * alike. Null when no decoy was armed (the surface disabled) and on
     * every non-valid outcome.
     */
    public function decoyField(): ?string
    {
        return $this->decoyField;
    }

    /**
     * The failure reason when the outcome is invalid, else null —
     * used by the provider-compatible Siteverify error mapping.
     */
    public function error(): ?VerifyError
    {
        return $this->error;
    }
}
