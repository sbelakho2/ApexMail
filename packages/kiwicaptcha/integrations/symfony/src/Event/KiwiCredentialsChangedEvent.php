<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Event;

/**
 * Dispatched by the application when a user's credentials changed: a
 * password change, a passkey added or removed, an admin lockout, or any
 * other event that must end every device trust the old credentials had
 * established. The bundle's subscriber answers by revoking the user's
 * session and device trust tags through
 * {@link \KiwiCaptcha\Risk\Outcomes\KiwiOutcomes::forgetDevicesForUser()},
 * so a stolen credential can no longer ride a device binding minted
 * before the change.
 *
 * The event carries the raw user identifier only as an in-process
 * argument: the revocation derives the principal pseudonym through the
 * keyed identity factory inside the outcomes facade, and the identifier
 * is never logged, stored or keyed by this surface.
 */
final class KiwiCredentialsChangedEvent
{
    public function __construct(
        public readonly string $userIdentifier,
    ) {
    }
}
