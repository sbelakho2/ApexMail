<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * A post-solve disposition record that violates the strict v1 schema or
 * its state invariants. The disposition decode is all-or-nothing: a
 * missing/malformed field or a state-invariant violation throws this
 * exception instead of defaulting (an unknown state must never become
 * pending, a corrupt kind never Pass, a missing disposition never a
 * silent pass). A malformed server record is a server-side anomaly: the
 * validator fails closed with the temporary_unavailable violation, never
 * a 422. The client did not corrupt the Redis structure. The detail goes
 * to the server log only, and the record is never treated as valid
 * state.
 */
final class MalformedPostSolveDispositionException extends \RuntimeException
{
}
