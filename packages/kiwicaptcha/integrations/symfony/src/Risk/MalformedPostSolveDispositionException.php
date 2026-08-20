<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * A post-solve disposition record that violates the strict v1 schema or
 * its state invariants. The disposition decode is ALL-OR-NOTHING: a
 * missing/malformed field or a state-invariant violation throws this
 * exception instead of defaulting (an unknown state must never become
 * pending, a corrupt kind never Pass, a missing disposition never a
 * silent pass). A malformed SERVER record is a server-side anomaly — the
 * validator fails closed with the temporary_unavailable violation (the
 * client did not corrupt the Redis structure — never a 422), the detail
 * goes to the server log only, and the record is NEVER treated as valid
 * state.
 */
final class MalformedPostSolveDispositionException extends \RuntimeException
{
}
