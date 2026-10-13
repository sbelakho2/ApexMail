<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipDeliveryMetadata;

/**
 * The carrier kernels' anonymous email-ownership delivery seam: a real
 * sender class (not the bundle's logging dev sender), so the doctor's
 * carrier answerability sees real delivery. The codes are recorded,
 * never delivered anywhere.
 */
final class DoctorCarrierOwnershipSender implements EmailOwnershipCodeSenderInterface
{
    /** @var list<string> */
    public array $codes = [];

    public function send(string $email, string $code, int $ttlSecs, EmailOwnershipDeliveryMetadata $delivery): void
    {
        $this->codes[] = $code;
    }
}
