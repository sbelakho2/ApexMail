<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Result of a solution verification.
 */
final class VerifyOutcome
{
    private function __construct(
        public readonly bool $valid,
        public readonly ?VerifyError $error,
        public readonly ?string $detail,
    ) {
    }

    public static function valid(): self
    {
        return new self(true, null, null);
    }

    public static function invalid(VerifyError $error): self
    {
        return new self(false, $error, null);
    }

    public static function malformedToken(string $detail): self
    {
        return new self(false, VerifyError::MalformedToken, $detail);
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
}
