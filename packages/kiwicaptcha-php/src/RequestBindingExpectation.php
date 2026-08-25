<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The explicit request-binding enforcement policy, replacing the ambiguous
 * nullable "expected request binding" (null previously meant BOTH "the
 * transaction is explicitly unbound" AND "do not enforce", which let a
 * bound record escape comparison whenever the authoritative transaction
 * resolved to null).
 *
 * The exact semantics are Option-equality:
 *
 *   Record binding | Expectation     | Result
 *   -------------- | --------------- | ------------------------------
 *   bound A        | exact A         | pass
 *   bound A        | exact B         | RequestBindingMismatch
 *   bound A        | exact null      | RequestBindingMismatch
 *   unbound        | exact null      | pass
 *   unbound        | exact A         | RequestBindingMismatch
 *   bound/unbound  | unenforced      | pass (no enforcement)
 *
 * `legacy()` reproduces the pre-migration nullable behavior exactly (a
 * null expected binding disables enforcement; a non-null expected binding
 * only ever compares BOUND records), so existing callers keep their
 * semantics until they migrate to `exact()`.
 */
final readonly class RequestBindingExpectation
{
    private function __construct(
        public bool $enforced,
        public ?string $expected,
        public bool $requireBindingPresence,
    ) {
    }

    /** No request-binding enforcement at all (legacy null behavior). */
    public static function unenforced(): self
    {
        return new self(false, null, false);
    }

    /**
     * Require exact Option equality between the record's binding and the
     * authoritative transaction's binding: null == explicitly unbound,
     * a string == the same bound transaction. Never ambiguous.
     */
    public static function exact(?string $binding): self
    {
        return new self(true, $binding, true);
    }

    /**
     * The temporary compatibility mode for the historical nullable
     * argument: a null expected binding means unenforced; a non-null
     * expected binding only compares records that actually carry one
     * (unbound records pass regardless).
     */
    public static function legacy(?string $binding): self
    {
        return new self($binding !== null, $binding, false);
    }
}
