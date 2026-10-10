<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * The default code sender: a dev and test lane that logs the code. The
 * production deployment binds its own sender over its mailer, through
 * the risk.step_up.handlers.email_otp.sender service knob of
 * {@see StepUpCodeSenderInterface}. This default exists so a dev
 * kernel and the test suite observe delivery without a mailer. The
 * configuration info of the sender knob names the production
 * expectation.
 */
final class LoggingStepUpCodeSender implements StepUpCodeSenderInterface
{
    public function __construct(
        private readonly ?LoggerInterface $logger = null,
        private readonly string $level = LogLevel::DEBUG,
    ) {
    }

    public function send(string $code, StepUpContext $context, int $ttlSecs): void
    {
        $this->logger?->log(
            $this->level,
            'KiwiCaptcha step-up code (dev sender): scope {scope}, principal pseudonym {principal}, code {code}, ttl {ttl}s',
            ['scope' => $context->scope, 'principal' => $context->principalPseudonym, 'code' => $code, 'ttl' => $ttlSecs],
        );
    }
}
