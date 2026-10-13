<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The provenance discriminator of a step-up demand's operation digest:
 * which of the canonical operation identities minted the digest the
 * record carries. There are exactly three canonical operation
 * identities plus the unbound case:
 *
 *  - form_fields: the canonical operation fields of the protected
 *    form (the scope's email field and target fields, canonically
 *    sorted). The digest is minted from the submitted values and
 *    finalization reruns the form-field canonicalization.
 *  - request_binding: the authoritative transaction binding the
 *    binding authority resolved. The digest is minted from (scope,
 *    binding) and finalization reruns the binding recipe.
 *  - login: the principal pseudonym of the interactive login the
 *    pending token carries. The digest is minted from (scope,
 *    principal) and finalization reruns the principal recipe.
 *  - none: no operation identity applies; the digest covers the scope
 *    alone.
 *
 * Finalization reads the kind off the stored demand and recomputes the
 * digest with that kind's recipe, so a demand minted from one identity
 * can never be finalized through another identity's canonicalization.
 */
enum StepUpOperationBindingKind: string
{
    case None = 'none';
    case FormFields = 'form_fields';
    case RequestBinding = 'request_binding';
    case Login = 'login';

    /** The kind of a wire value, null when the value names no kind. */
    public static function of(string $value): ?self
    {
        $kind = self::tryFrom($value);

        return $kind === null ? null : $kind;
    }
}
