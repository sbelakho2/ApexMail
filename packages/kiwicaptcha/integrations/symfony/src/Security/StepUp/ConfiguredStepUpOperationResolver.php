<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Http\RequestFieldResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The default operation resolver. The server-owned logical operation id
 * comes from the request attribute the application mints. The protected
 * contents come from the explicit per-scope field recipe
 * (risk.scopes.<name>.operation_content_fields), read through the
 * nested-aware field resolver, so a form-named submission resolves at
 * any depth. The principal comes from the wired resolver. The recipe is
 * data: the deployment names the fields its own protected forms submit,
 * and the canonicalization is the one shared implementation, so the
 * mint and every finalization rerun hash the same bytes.
 *
 * A missing operation id, a scope without a recipe, and a configured
 * field with no submitted value all throw: a demand whose business
 * contents did not resolve must never exist, because a content digest
 * over nothing would authorize anything.
 */
final class ConfiguredStepUpOperationResolver implements StepUpOperationResolverInterface
{
    /**
     * @param array<string, list<string>> $contentFieldsByScope the
     *        protected-content recipe per scope, keyed by scope name
     */
    public function __construct(
        private readonly array $contentFieldsByScope,
        private readonly ?PrincipalResolverInterface $principalResolver = null,
        private readonly string $operationIdAttribute = '_kiwi_captcha_operation_id',
    ) {
        foreach ($contentFieldsByScope as $scope => $fields) {
            if (!\is_string($scope) || $scope === '' || !\array_is_list($fields)) {
                throw new \InvalidArgumentException('The protected-content recipe must map every scope name to a list of field names');
            }
            foreach ($fields as $field) {
                if (!\is_string($field) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $field) !== 1) {
                    throw new \InvalidArgumentException('The protected-content recipe entries must be field names of 1-128 chars of [A-Za-z0-9._:-]');
                }
            }
        }
    }

    public function resolve(Request $request, string $scope): StepUpOperation
    {
        $operationId = $request->attributes->get($this->operationIdAttribute);
        if (!\is_string($operationId) || $operationId === '') {
            throw new \InvalidArgumentException(sprintf('The server-owned logical operation id is missing under "%s"; the application mints it itself', $this->operationIdAttribute));
        }
        $fields = $this->contentFieldsByScope[$scope] ?? [];
        if ($fields === []) {
            throw new \InvalidArgumentException(sprintf('The scope "%s" carries no protected-content recipe (risk.scopes.%s.operation_content_fields)', $scope, $scope));
        }
        $contents = [];
        foreach ($fields as $field) {
            $value = RequestFieldResolver::string($request, $field);
            if ($value === null || trim($value) === '') {
                throw new \InvalidArgumentException(sprintf('The protected content field "%s" resolved to no value for the scope "%s"', $field, $scope));
            }
            $contents[$field] = $value;
        }
        $principal = null;
        try {
            $principal = $this->principalResolver?->resolve($request, $scope);
        } catch (\Throwable) {
            $principal = null;
        }

        return new StepUpOperation(
            $operationId,
            StepUpOperationDigest::canonicalOperationContent($contents),
            $principal,
        );
    }
}
