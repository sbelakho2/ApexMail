<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The operation digest recipes of the demand plane. One recipe per
 * {@see StepUpOperationBindingKind}: the canonical operation identity
 * of the protected operation, hashed into the 64 hex chars a demand
 * record carries. The mint site and the finalizer share this one
 * implementation, and finalization reruns exactly the recipe the
 * stored binding kind names, so a demand minted from one operation
 * identity can never be finalized through another identity's
 * canonicalization.
 *
 * The recipes are domain-separated under one purpose string and cover
 * the scope, so the same operation under another scope hashes
 * differently. The form-field recipe sorts the field names, so the
 * submission order is irrelevant and the canonical form is stable.
 */
final class StepUpOperationDigest
{
    private const PURPOSE = 'kiwi/v1/stepup-operation-digest';

    private const IDENTITY_INFO = 'kiwi/v1/stepup-op-identity';

    private const CONTENT_INFO = 'kiwi/v1/stepup-op-content';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private const HEX = '/^[0-9a-f]{64}$/D';

    /**
     * The digest of the form-field identity: the scope plus the
     * canonical operation fields sorted by name. Values are trimmed;
     * the caller hands them in their canonical spelling (the email
     * field lowercased exactly like the factor canonicalizes it).
     *
     * @param array<string, string> $fields
     */
    public static function formFields(string $scope, array $fields): string
    {
        ksort($fields);
        $material = '';
        foreach ($fields as $name => $value) {
            $material .= $name.'='.trim($value)."\0";
        }

        return self::hash(StepUpOperationBindingKind::FormFields, $scope, $material);
    }

    /** The digest of the authoritative transaction binding identity. */
    public static function requestBinding(string $scope, string $binding): string
    {
        return self::hash(StepUpOperationBindingKind::RequestBinding, $scope, $binding);
    }

    /** The digest of the login principal identity. */
    public static function login(string $scope, string $principalPseudonym): string
    {
        return self::hash(StepUpOperationBindingKind::Login, $scope, $principalPseudonym);
    }

    /** The digest of the unbound case: the scope alone. */
    public static function none(string $scope): string
    {
        return self::hash(StepUpOperationBindingKind::None, $scope, '');
    }

    /**
     * The digest a demand's stored binding kind prescribes, computed
     * from the material the caller supplies. Null when the material
     * cannot feed the stored recipe: a missing binding, a missing
     * principal, or no form fields. The finalizer treats null as a
     * refusal, fail closed, so a demand minted from one identity is
     * never answered with another identity's canonicalization.
     *
     * @param StepUpOperationMaterial $material
     */
    public static function rerun(string $scope, StepUpOperationBindingKind $kind, StepUpOperationMaterial $material): ?string
    {
        return match ($kind) {
            StepUpOperationBindingKind::FormFields => $material->formFields === [] ? null : self::formFields($scope, $material->formFields),
            StepUpOperationBindingKind::RequestBinding => $material->requestBinding === null ? null : self::requestBinding($scope, $material->requestBinding),
            StepUpOperationBindingKind::Login => $material->principalPseudonym === null ? null : self::login($scope, $material->principalPseudonym),
            StepUpOperationBindingKind::None => self::none($scope),
        };
    }

    /** Whether a value is the canonical digest shape. */
    public static function isDigestShape(string $value): bool
    {
        return preg_match(self::HEX, $value) === 1;
    }

    /**
     * The split financial/action binding. The operation identity
     * digest is an HMAC over the server-owned unique logical operation
     * id (the operation id attribute concept: an idempotency key the
     * application mints, never a raw client value alone). The operation
     * content digest is an HMAC over the canonical contents (amount /
     * currency / recipient / ...). Both are keyed under
     * purpose-separated HKDF derivations of the step-up master, never
     * the master itself, and both cover the scope, so the same
     * operation under another scope hashes differently.
     *
     * Two transfers with identical contents but different logical
     * operation ids therefore carry identical content digests and
     * different identity digests: the split is exactly what refuses the
     * cross-authorization.
     *
     * @return array{identity: string, content: string}
     */
    public static function financialBinding(string $master, string $scope, string $serverOwnedOperationId, string $canonicalContent): array
    {
        if ($serverOwnedOperationId === '') {
            throw new \InvalidArgumentException('The logical operation id of a financial binding must be non-empty (server-owned, never a raw client value alone)');
        }

        return [
            'identity' => self::hmac($master, self::IDENTITY_INFO, $scope, $serverOwnedOperationId),
            'content' => self::hmac($master, self::CONTENT_INFO, $scope, $canonicalContent),
        ];
    }

    /**
     * The canonical operation content encoding: the named fields sorted
     * by name so the submission order is irrelevant, each trimmed. The
     * caller names the fields the protected operation carries (amount,
     * currency, recipient, ...); the encoding is stable across machines
     * and workers.
     *
     * @param array<string, string> $fields
     */
    public static function canonicalOperationContent(array $fields): string
    {
        ksort($fields);
        $material = '';
        foreach ($fields as $name => $value) {
            $material .= $name.'='.trim((string) $value)."\0";
        }

        return $material;
    }

    private static function hash(StepUpOperationBindingKind $kind, string $scope, string $material): string
    {
        return hash('sha256', self::PURPOSE."\0".$kind->value."\0".$scope."\0".$material);
    }

    private static function hmac(string $master, string $info, string $scope, string $material): string
    {
        $key = hash_hkdf('sha256', $master, 32, $info, self::HKDF_SALT);

        return hash_hmac('sha256', $scope."\0".$material, $key);
    }
}
