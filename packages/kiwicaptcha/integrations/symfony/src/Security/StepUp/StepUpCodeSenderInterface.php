<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The delivery seam of the email one-time-passcode handler. The
 * application binds exactly one implementation: it maps the principal
 * pseudonym to the delivery address through its own records and hands
 * the code to its own mailer. The bundle deliberately carries no
 * mailer dependency of its own.
 *
 * The sender receives the context's pseudonyms and scope, never a raw
 * identifier from the bundle side: the pseudonym-to-address mapping is
 * the application's own lookup, and the code is the only secret on the
 * call. A throwing sender fails the begin() call (the challenge record
 * is never left behind for an undelivered code), fail-closed.
 */
interface StepUpCodeSenderInterface
{
    /**
     * Deliver one one-time passcode for the step-up demand of the
     * context. The code is the raw digit string; the TTL the handler
     * configured is passed so the message can state the deadline.
     *
     * @throws \Throwable when delivery failed; begin() then answers a
     *                    refusal and removes the challenge record
     */
    public function send(string $code, StepUpContext $context, int $ttlSecs): void;
}
