<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Asn;

/**
 * ASN dataset failure. Every code fails closed: the dataset either
 * keeps serving its table or refuses the load. The serving table
 * survives every rejected reload.
 */
final class AsnDatasetException extends \RuntimeException
{
    public const UNREADABLE = 1;

    public const EMPTY = 2;

    public const DIGEST_MISMATCH = 3;

    /** The failure code: one of the class constants above. */
    public function kind(): int
    {
        return $this->code;
    }
}
