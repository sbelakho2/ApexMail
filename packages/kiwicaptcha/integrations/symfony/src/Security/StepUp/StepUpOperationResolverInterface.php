<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The source of the protected operation a step-up demand binds to. An
 * operation-bound scope demands a durable binding over the real
 * business operation: the server-owned logical operation id and the
 * canonical contents the protected submission carries. The bundle
 * ships one implementation, configured through
 * risk.scopes.<name>.operation_content_fields, registered behind the
 * alias StepUpOperationResolverInterface::class. Every consumer
 * references the interface, so an application with a deeper operation
 * registry replaces that one alias. A domain-backed resolver loads
 * the business object from the server operation id, and the canonical
 * bytes run over the actual executable fields.
 *
 * A resolution answers or throws: a missing server-owned operation id
 * and a configured content field with no submitted value are
 * refusals, and every caller treats a thrown resolution as no demand,
 * fail closed.
 */
interface StepUpOperationResolverInterface
{
    /**
     * The protected operation the request presents under the scope.
     *
     * @throws \InvalidArgumentException when the operation id or a
     *                                   configured content field does
     *                                   not resolve
     */
    public function resolve(Request $request, string $scope): StepUpOperation;
}
