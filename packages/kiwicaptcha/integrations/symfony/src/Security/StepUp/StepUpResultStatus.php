<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The verdict of one completion attempt. String-backed so the wire
 * format of a json-mode completion answer stays stable.
 */
enum StepUpResultStatus: string
{
    /** The challenge stays live: the proof was rejected but attempts remain, retry. */
    case Pending = 'pending';

    /** The proof was accepted and the completion credit was booked. */
    case Succeeded = 'succeeded';

    /** Terminal refusal: the challenge is dead (consumed, expired, exhausted or refused). */
    case Failed = 'failed';
}
