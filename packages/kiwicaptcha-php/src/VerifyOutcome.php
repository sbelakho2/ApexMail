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
    ) {
    }

    public static function valid(?string $nonce = null, ?string $requestBinding = null, bool $fromStoredResult = false): self
    {
        return new self(true, null, null, $nonce, $requestBinding, $fromStoredResult);
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
     * The failure reason when the outcome is invalid, else null —
     * used by the provider-compatible Siteverify error mapping.
     */
    public function error(): ?VerifyError
    {
        return $this->error;
    }
}
