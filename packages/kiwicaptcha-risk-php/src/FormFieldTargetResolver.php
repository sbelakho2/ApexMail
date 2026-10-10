<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * Default target resolver: one configured form field name per scope.
 *
 * The map is the deployment's per-scope choice of the form field that
 * carries the target identifier, e.g. [1 => 'username', 2 => 'email'] for
 * a login scope and a signup scope. A scope without a configured field
 * resolves null: that assessment simply carries no target dimension.
 */
final class FormFieldTargetResolver implements TargetIdentifierResolverInterface
{
    /**
     * @param array<int, string> $fieldNames scope id => the form field
     *                                       name carrying the target
     *                                       identifier for that scope
     *
     * @throws \InvalidArgumentException when a configured field name is
     *                                   not a non-empty string
     */
    public function __construct(private readonly array $fieldNames = [])
    {
        foreach ($fieldNames as $scope => $field) {
            if (!\is_string($field) || $field === '') {
                throw new \InvalidArgumentException(sprintf(
                    'The target field name for scope %s must be a non-empty string',
                    var_export($scope, true),
                ));
            }
        }
    }

    /**
     * The raw value of the scope's configured field, or null when the
     * scope is unconfigured or the field is absent/empty. The raw value
     * is returned verbatim; the caller owns the normalization boundary.
     *
     * @param array<string, string> $fields
     */
    public function resolve(int $scope, array $fields): ?string
    {
        $field = $this->fieldNames[$scope] ?? null;
        if ($field === null) {
            return null;
        }
        $value = $fields[$field] ?? null;
        if (!\is_string($value) || $value === '') {
            return null;
        }

        return $value;
    }
}
