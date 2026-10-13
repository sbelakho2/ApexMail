<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Event\KiwiCredentialsChangedEvent;
use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * The revocation lane of the outcomes plane: it wires the two
 * application moments that must end device trust to the facade's
 * forgetDevicesForUser() (which was otherwise an uncalled surface).
 *
 * KiwiCredentialsChangedEvent revokes the user's session and device
 * tags: the application dispatches it on a password change, a passkey
 * change or an admin lockout. Every device bound under the old
 * credentials stops vouching, and the next login from it is judged by
 * the first-attempt gate on its own evidence.
 *
 * LogoutEvent with the request attribute
 * {@see self::LOGOUT_EVERYWHERE_ATTRIBUTE} (the application sets it
 * before triggering logout) revokes the same state for the logging-out
 * user: the sign-out-everywhere moment.
 *
 * Like the bridge, this subscriber never breaks the application flow:
 * every listener body is a try/catch that logs and returns, so a
 * revocation failure is a missing risk signal, never a failed logout.
 */
final class KiwiCredentialsChangedSubscriber implements EventSubscriberInterface
{
    /** The request attribute the application sets for a logout that must end device trust everywhere. */
    public const LOGOUT_EVERYWHERE_ATTRIBUTE = '_kiwi_logout_everywhere';

    public function __construct(
        private readonly KiwiOutcomes $outcomes,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KiwiCredentialsChangedEvent::class => 'onCredentialsChanged',
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onCredentialsChanged(KiwiCredentialsChangedEvent $event): void
    {
        try {
            $this->outcomes->forgetDevicesForUser($event->userIdentifier);
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi credentials-changed revocation failed: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }

    public function onLogout(LogoutEvent $event): void
    {
        $request = $event->getRequest();
        if ($request === null || !$request->attributes->get(self::LOGOUT_EVERYWHERE_ATTRIBUTE)) {
            return;
        }
        $user = $event->getToken()?->getUser();
        if ($user === null || !method_exists($user, 'getUserIdentifier')) {
            return;
        }
        try {
            $this->outcomes->forgetDevicesForUser((string) $user->getUserIdentifier());
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi logout-everywhere revocation failed: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }
}
