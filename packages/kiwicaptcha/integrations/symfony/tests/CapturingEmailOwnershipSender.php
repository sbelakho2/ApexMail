<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipDeliveryMetadata;

/**
 * The capturing delivery seam of the tests: records every code so the
 * journey can complete the factor without a mailer. Lives in its own
 * autoloadable file, so every test file of the suite resolves the same
 * class under the Tests namespace.
 */
final class CapturingEmailOwnershipSender implements EmailOwnershipCodeSenderInterface
{
    /** @var list<string> */
    public array $codes = [];

    public function send(string $email, string $code, int $ttlSecs, EmailOwnershipDeliveryMetadata $delivery): void
    {
        $this->codes[] = $code;
    }

    public function lastCode(): ?string
    {
        return $this->codes === [] ? null : $this->codes[\count($this->codes) - 1];
    }
}
