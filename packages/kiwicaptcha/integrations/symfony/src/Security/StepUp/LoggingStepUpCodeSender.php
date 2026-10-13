<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * The default code sender: a dev and test lane that logs the code. The
 * production deployment binds its own sender over its mailer (or
 * installs symfony/mailer, which arms the bundle's own mailer adapter)
 * through the risk.step_up.handlers.email_otp.sender service knob of
 * {@see StepUpCodeSenderInterface}. This default exists so a dev
 * kernel and the test suite observe delivery without a mailer.
 *
 * The seam receives pseudonyms only, because the context validates the
 * shapes at construction, so the log line can never carry a raw
 * identifier or address. The principal rides as the engine's keyed
 * pseudonym, and the code is the dev lane's whole point. The doctor
 * FAILs a production deployment whose factor resolves to this sender.
 * A logged code is a code delivered to nobody.
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
