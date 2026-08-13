<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Result of a solution verification.
 *
 * A VALID outcome exposes the decoded solution token's nonce — the
 * canonical replay id (jti) — via {@see self::nonce()}; the bundle surfaces
 * it so the consuming application can correlate accepted proofs. Null for
 * every non-valid outcome (including MalformedToken, where no nonce could
 * be decoded).
 */
final class VerifyOutcome
{
    private function __construct(
        public readonly bool $valid,
        public readonly ?VerifyError $error,
        public readonly ?string $detail,
        public readonly ?string $nonce,
    ) {
    }

    public static function valid(?string $nonce = null): self
    {
        return new self(true, null, null, $nonce);
    }

    public static function invalid(VerifyError $error): self
    {
        return new self(false, $error, null, null);
    }

    public static function malformedToken(string $detail): self
    {
        return new self(false, VerifyError::MalformedToken, $detail, null);
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
}
