<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * A chained-challenge state record that violates the strict v2 schema or
 * its state invariants. The chain state decode is ALL-OR-NOTHING: a
 * missing/malformed field or a state-invariant violation throws this
 * exception instead of defaulting (a corrupt requiredAction must never
 * become '', policyVersion never 1, chainDepth never 2, state never
 * available). A malformed SERVER record is a server-side anomaly — the
 * callers fail closed with the temporary-unavailable response (503 / the
 * validator's temporary_unavailable), the detail goes to the server log
 * only, and the record is NEVER treated as valid state.
 */
final class MalformedChainedChallengeStateException extends \RuntimeException
{
}
