<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Symfony\Component\HttpFoundation\Request;

/**
 * The app-facing quarantine hold (change.md 1.3 and 3.3.4).
 *
 * A quarantined verification passes exactly like an allow: the form
 * validates, the submission processes with HTTP-200-class behavior, and
 * every browser-visible byte is identical. What the application does
 * differently is publication: the persistence layer asks this marker
 * whether the current request's submission must be withheld, and skips
 * the publish write while everything else proceeds. The flag itself
 * never travels on the wire: it lives on the server-side request
 * attribute plane (the same surface as the verified jti), so a
 * middleware can examine it without any browser-visible difference.
 *
 * The interface is Doctrine-independent and storage-free on purpose:
 * holding a submission is the application's persistence decision, the
 * bundle only tells it when. Applications that need a durable hold
 * (a review queue, a moderation state) wrap or replace the default
 * {@see RequestQuarantineMarker}; the validator consumes whatever
 * implementation the container carries.
 */
interface QuarantineMarkerInterface
{
    /**
     * The server-side request attribute carrying the quarantine flag
     * (`kiwi.quarantine`, boolean true when the current request's
     * verified submission is quarantined). Middleware-examinable,
     * never a browser-visible surface.
     */
    public const ATTRIBUTE = 'kiwi.quarantine';

    /**
     * Marks the current request's accepted submission as quarantined:
     * the app must withhold it from publication. Never throws.
     */
    public function hold(): void;

    /**
     * True when the current request carries a quarantined submission:
     * the persistence layer withholds the publication write. Never
     * throws; false when no request is in scope or nothing was held.
     */
    public function isHeld(): bool;

    /**
     * The quarantine flag of an arbitrary request (the same attribute
     * contract), for callers that resolve the request themselves.
     */
    public function isHeldOn(Request $request): bool;
}
