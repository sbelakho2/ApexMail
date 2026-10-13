<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\EventSubscriber;

use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * The response side of the trusted-device cookie lifecycle.
 *
 * The login gate (FirstAttemptLoginGuard) and the step-up session
 * restore (SessionRestorer) stage a device value on the request under
 * the {@see FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE} attribute
 * (`_kiwi_device_mint`); this subscriber attaches the cookie to the
 * response. One writer keeps the browser contract in one place:
 * HttpOnly, SameSite from the configured service, __Host- Secure
 * forcing included.
 *
 * Runs at a low priority so later middleware sees the final header set.
 * Only a well-formed 32-hex value is ever issued; anything else is
 * ignored, never sent to the wire.
 */
final class DeviceCookieSubscriber implements EventSubscriberInterface
{
    /** Low priority: the cookie rides the fully built response. */
    public const RESPONSE_PRIORITY = -10;

    public function __construct(private readonly TrustedDeviceCookie $device)
    {
    }

    /**
     * @return array<string, list<string>|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => ['onKernelResponse', self::RESPONSE_PRIORITY],
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        $value = $request->attributes->get(FirstAttemptLoginGuard::DEVICE_MINT_ATTRIBUTE);
        if (!\is_string($value) || preg_match(TrustedDeviceCookie::VALUE_PATTERN, $value) !== 1) {
            return;
        }
        $event->getResponse()->headers->setCookie($this->device->cookie($request, $value));
    }
}
