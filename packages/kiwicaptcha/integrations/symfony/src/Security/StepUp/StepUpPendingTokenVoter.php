<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * The pending-token voter: a {@see StepUpPendingToken} is never
 * "authenticated" for the purposes of IS_AUTHENTICATED_* attribute
 * checks. Without this voter Symfony's authenticated-voter logic sees
 * a real user on the token and treats a stuffer's pending token as a
 * full session. Only the dedicated step-up role is ever granted; every
 * authenticated-fully / authenticated / authenticated-remember-me
 * attribute is denied while the token is pending.
 */
final class StepUpPendingTokenVoter implements VoterInterface
{
    private const DENIED = [
        'IS_AUTHENTICATED_FULLY',
        'IS_AUTHENTICATED',
        'IS_AUTHENTICATED_REMEMBERED',
        'IS_AUTHENTICATED_ANONYMOUSLY',
    ];

    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?\Symfony\Component\Security\Core\Authorization\Voter\Vote $vote = null): int
    {
        if (!$token instanceof StepUpPendingToken) {
            return self::ACCESS_ABSTAIN;
        }
        foreach ($attributes as $attribute) {
            if (\in_array($attribute, self::DENIED, true)) {
                return self::ACCESS_DENIED;
            }
        }

        return self::ACCESS_ABSTAIN;
    }
}
