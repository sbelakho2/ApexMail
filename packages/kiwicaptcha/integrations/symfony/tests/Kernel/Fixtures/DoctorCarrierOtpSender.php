<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;

/**
 * The carrier kernels' email one-time-passcode delivery seam: a real
 * sender class (not the bundle's logging dev sender), so the doctor's
 * carrier answerability sees real delivery. The codes are recorded,
 * never delivered anywhere.
 */
final class DoctorCarrierOtpSender implements StepUpCodeSenderInterface
{
    /** @var list<string> */
    public array $codes = [];

    public function send(string $code, StepUpContext $context, int $ttlSecs): void
    {
        $this->codes[] = $code;
    }
}
