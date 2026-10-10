<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The default quarantine marker: request-scoped state on the
 * RequestStack main request, keyed by
 * {@see QuarantineMarkerInterface::ATTRIBUTE}. The validator writes the
 * flag when the final disposition was a quarantined pass; the
 * application's persistence layer reads it back through
 * {@see isHeld()} right before the publication write.
 *
 * The request attribute plane is the deliberate storage choice. It is
 * server-side only (never a cookie, header or body field, so the wire
 * stays byte-identical to allow). It is scoped to exactly the request
 * the hold belongs to (a long-running worker can never leak one
 * request's hold into the next). It needs no storage backend. A
 * deployment that wants the hold to survive the request (a review
 * queue) decorates or replaces this service; the validator only
 * consumes the interface.
 */
final class RequestQuarantineMarker implements QuarantineMarkerInterface
{
    public function __construct(
        private readonly ?RequestStack $requestStack = null,
    ) {
    }

    public function hold(): void
    {
        $this->requestStack?->getMainRequest()?->attributes->set(self::ATTRIBUTE, true);
    }

    public function isHeld(): bool
    {
        $request = $this->requestStack?->getMainRequest();
        if ($request === null) {
            return false;
        }

        return $this->isHeldOn($request);
    }

    public function isHeldOn(Request $request): bool
    {
        return $request->attributes->get(self::ATTRIBUTE) === true;
    }
}
