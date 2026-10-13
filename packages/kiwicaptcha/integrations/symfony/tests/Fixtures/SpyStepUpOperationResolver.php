<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperation;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationResolverInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test double: the domain-backed resolver a deployment re-points the
 * StepUpOperationResolverInterface alias at. Every resolution is
 * recorded, so the compiled-container test can assert the validator
 * drives the replacement, and the answered operation is fixed by the
 * test through $operation.
 */
final class SpyStepUpOperationResolver implements StepUpOperationResolverInterface
{
    /**
     * The resolutions the replacement answered, in order. Reset it
     * before the call under assertion.
     *
     * @var list<array{scope: string, operationId: string}>
     */
    public static array $resolved = [];

    /** The operation the next resolution answers. */
    public static ?StepUpOperation $operation = null;

    public function resolve(Request $request, string $scope): StepUpOperation
    {
        $operation = self::$operation ?? new StepUpOperation('tx-spy-001', '', null);
        self::$resolved[] = ['scope' => $scope, 'operationId' => $operation->logicalOperationId];

        return $operation;
    }
}
