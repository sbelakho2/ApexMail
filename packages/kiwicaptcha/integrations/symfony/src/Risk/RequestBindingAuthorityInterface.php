<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Request;

/**
 * The authoritative transaction-binding resolver
 * (risk.request_binding_authority).
 *
 * A chained transaction must be anchored on a binding the server can
 * attest, never on an unexamined client-supplied string. When an
 * authority is configured, the challenge controller resolves the
 * transaction binding only through it: the client's presented
 * request_binding field is a hint, never a value the server signs
 * unexamined. The authority decides the binding of the transaction from
 * its own trusted inputs (session, cookies, authenticated headers,
 * server state).
 *
 * The resolution must be stable across the lifetime of one transaction:
 * the stage-1 issuance, the `CHAIN_REQUIRED` re-render and the stage-2
 * resumption must resolve to the same authoritative binding. The chain
 * obligation index is keyed on the (policy-epoch, scope, binding)
 * triple. A binding the authority cannot confirm for this transaction
 * throws \InvalidArgumentException (the controller refuses with 422
 * `INVALID_REQUEST_BINDING` before any state is touched); null means the
 * transaction is unbound.
 *
 * The returned binding (when non-null) must match the bundle's identifier
 * shape ([A-Za-z0-9._:-]{1,128}); a value outside it is refused by the
 * controller like any other malformed binding.
 */
interface RequestBindingAuthorityInterface
{
    /**
     * Resolve the authoritative transaction binding of a challenge
     * request.
     *
     * @param Request    $request          the challenge request (trusted
     *                                     inputs: session, cookies,
     *                                     server-attested headers).
     * @param string     $scope            the canonical security scope of
     *                                     the request.
     * @param string|null $presentedBinding the client-presented
     *                                     request_binding field (a hint,
     *                                     never trusted unexamined).
     *
     * @return string|null the authoritative binding, or null when the
     *                     transaction is unbound.
     *
     * @throws \InvalidArgumentException when the presented binding (or the
     *                                   request) cannot be attributed to
     *                                   this transaction's authoritative
     *                                   binding: the controller refuses
     *                                   the issuance with 422
     *                                   `INVALID_REQUEST_BINDING`.
     */
    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string;
}
