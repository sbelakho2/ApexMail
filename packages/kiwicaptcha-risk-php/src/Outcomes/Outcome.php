<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

/**
 * The typed outcome vocabulary of the outcomes plane: the eight
 * application-reported outcomes, each mapped onto the risk-v1 event
 * channels, the outcome-ledger confirmation and the long-memory marks
 * through the single versioned table {@see OutcomeMap}.
 *
 * The wire values are the contract names and are shared with the Rust
 * mirror and the cross-language vectors (protocol/risk-v1/
 * outcomes-vectors.json); they must stay stable across versions of the
 * mapping table.
 */
enum Outcome: string
{
    case ConfirmedLegitimate = 'confirmedLegitimate';
    case StepUpCompleted = 'stepUpCompleted';
    case AuthenticationSuccess = 'authenticationSuccess';
    case AuthenticationFailure = 'authenticationFailure';
    case SpamReported = 'spamReported';
    case Chargeback = 'chargeback';
    case AccountBanned = 'accountBanned';
    case FraudConfirmed = 'fraudConfirmed';

    /**
     * Resolves a wire name to the outcome. Unknown names answer null so
     * callers on the report boundary can reject them with their own
     * fail-closed diagnostics.
     */
    public static function fromWireName(string $name): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->value === $name) {
                return $case;
            }
        }

        return null;
    }
}
