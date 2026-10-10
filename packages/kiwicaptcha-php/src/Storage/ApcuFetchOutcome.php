<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The answer of one backend fetch: whether a live entry exists under the
 * key, and its value when it does. A TTL-expired entry answers exactly
 * like an absent one, mirroring the APCu contract where expiry is
 * observed on read.
 *
 * A value object instead of a by-ref success flag, so the
 * {@see ApcuBackendInterface} seam stays a plain method call and the
 * emulated test backend answers the identical shape the real one does.
 */
final class ApcuFetchOutcome
{
    /**
     * @param bool  $found whether a live entry exists under the key
     * @param mixed $value the entry's value, meaningful only when found
     */
    private function __construct(
        public readonly bool $found,
        private readonly mixed $value,
    ) {
    }

    /** The absent-or-expired answer. */
    public static function notFound(): self
    {
        return new self(false, null);
    }

    /** The live-entry answer carrying the stored value. */
    public static function found(mixed $value): self
    {
        return new self(true, $value);
    }

    /** The entry's value; only meaningful after a found answer. */
    public function value(): mixed
    {
        return $this->value;
    }
}
