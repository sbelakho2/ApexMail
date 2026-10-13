<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The mint-time assurance failure: the completion history or the
 * factor resolver could not be consulted, so the mint cannot know what
 * its demand must require.
 *
 * "There is no prior stronger factor" and "the assurance state could
 * not be determined" are different states, and a security-sensitive
 * mint must never conflate them. A store or resolver failure answered
 * as an empty history would silently mint a demand with no assurance
 * snapshot, exactly as if no escalation were ever owed. The mint that
 * catches this refusal answers its own failure: no demand id and no
 * record, fail closed. A genuinely empty history is a null answer,
 * never an exception, and mints normally.
 */
final class StepUpAssuranceUnavailable extends \RuntimeException
{
}
