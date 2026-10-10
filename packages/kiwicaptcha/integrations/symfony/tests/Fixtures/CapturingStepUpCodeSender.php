<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCodeSenderInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;

/**
 * Capturing code sender: records every delivery call so tests can
 * complete the email one-time-passcode flow without a mailer, and can
 * assert the raw principal never rides the call. Optionally throws, to
 * prove the fail-closed delivery refusal of begin().
 */
final class CapturingStepUpCodeSender implements StepUpCodeSenderInterface
{
    /** @var list<array{code: string, context: StepUpContext, ttl: int}> */
    public array $deliveries = [];

    public ?\Throwable $throwOnSend = null;

    public function send(string $code, StepUpContext $context, int $ttlSecs): void
    {
        if ($this->throwOnSend !== null) {
            throw $this->throwOnSend;
        }
        $this->deliveries[] = ['code' => $code, 'context' => $context, 'ttl' => $ttlSecs];
    }

    /** The most recently delivered code, or null when nothing was delivered. */
    public function lastCode(): ?string
    {
        return $this->deliveries === [] ? null : $this->deliveries[\count($this->deliveries) - 1]['code'];
    }
}
