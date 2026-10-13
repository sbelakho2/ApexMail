<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The operation material a finalization caller supplies: the canonical
 * inputs of every recipe the stored binding kind could name. A caller
 * hands in what its plane owns (the validator the form fields and the
 * resolved binding, the login controller the principal pseudonym) and
 * the finalizer picks the recipe the demand's stored kind prescribes.
 * An input the stored recipe needs but the caller did not supply
 * refuses the finalization, fail closed, so no plane can answer a
 * demand through a canonicalization it does not own.
 */
final class StepUpOperationMaterial
{
    /**
     * @param array<string, string> $formFields          the canonical
     *                                                   operation fields
     *                                                   of the protected
     *                                                   form, keyed by
     *                                                   field name
     * @param array<string, string> $targetFields        the submitted
     *                                                   target field
     *                                                   values of the
     *                                                   reassessment,
     *                                                   keyed by field
     *                                                   name
     */
    public function __construct(
        public readonly array $formFields = [],
        public readonly array $targetFields = [],
        public readonly ?string $requestBinding = null,
        public readonly ?string $principalPseudonym = null,
    ) {
    }

    /** The material of the login plane: the principal pseudonym only. */
    public static function login(string $principalPseudonym): self
    {
        return new self(principalPseudonym: $principalPseudonym);
    }
}
