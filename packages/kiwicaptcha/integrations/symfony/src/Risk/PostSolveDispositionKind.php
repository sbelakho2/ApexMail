<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The final disposition kinds. String-backed so the persisted wire format
 * is stable and machine-readable.
 */
enum PostSolveDispositionKind: string
{
    /** The protected action is accepted (the solve passes). */
    case Pass = 'pass';

    /** The post-solve assessment rejects the submission. */
    case Deny = 'deny';

    /** Application-level step-up is required. */
    case StepUp = 'step_up';

    /** A stronger PoW stage is required via a one-shot chain ticket. */
    case ChainRequired = 'chain_required';
}
