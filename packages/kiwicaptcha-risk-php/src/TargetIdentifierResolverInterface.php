<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Resolves the raw target identifier of one assessment.
 *
 * The resolver reads the request's submitted form fields and returns the
 * raw value bound to the scope's target dimension, or null when the scope
 * carries no target dimension. It never normalizes and never derives a
 * pseudonym. The raw value crosses exactly one boundary, into the
 * normalization pipeline of {@see TargetIdentifierNormalizer}. The
 * normalized value crosses exactly one more, into the HMAC, so no other
 * stage ever holds the raw identifier.
 */
interface TargetIdentifierResolverInterface
{
    /**
     * @param int $scope           the risk scope (u32) of the assessment.
     * @param array<string, string> $fields the request's submitted form
     *                             field values, keyed by field name.
     *
     * @return string|null the raw target identifier. Null when the scope
     *                    has no configured target field, the field is
     *                    absent from $fields, or its value is empty: no
     *                    target dimension for this assessment.
     */
    public function resolve(int $scope, array $fields): ?string;
}
