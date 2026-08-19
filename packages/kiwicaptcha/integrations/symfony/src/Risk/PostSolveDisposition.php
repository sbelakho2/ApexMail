<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * THE FINAL DISPOSITION of a verified proof.
 *
 * The core's retained verification result answers ONLY "was the PoW
 * cryptographically valid?" — it never answers "should the application
 * accept this protected action?". The latter is decided by the Symfony
 * layer's post-solve policy (fresh risk assessment, chaining, honeypot)
 * and persisted PER NONCE in a {@see PostSolveDispositionStore}, so a
 * replay of a valid proof reproduces the SAME final disposition instead
 * of bypassing the post-solve policy.
 *
 * The disposition carries ONLY the final disposition itself — kind,
 * optional decision id (the post-solve assessment's decision handle, or
 * the consumed original pre-issue decision id on the plain pass path) and
 * optional chain id (CHAIN_REQUIRED). Raw risk vectors, fingerprints and
 * descriptors are NEVER persisted.
 */
final readonly class PostSolveDisposition
{
    public function __construct(
        public PostSolveDispositionKind $kind,
        public ?string $decisionId = null,
        public ?string $chainId = null,
    ) {
        if ($kind === PostSolveDispositionKind::ChainRequired && ($chainId === null || $chainId === '')) {
            throw new \InvalidArgumentException('a ChainRequired disposition must carry a chain id');
        }
    }
}

/**
 * The final disposition kinds. String-backed so the persisted wire format
 * is stable and machine-readable.
 */
enum PostSolveDispositionKind: string
{
    /** The protected action is accepted (the solve passes). */
    case Pass = 'pass';

    /** The post-solve assessment rejects the submission (POST_SOLVE_REJECTED). */
    case Deny = 'deny';

    /** Application-level step-up is required (POST_SOLVE_STEP_UP_REQUIRED). */
    case StepUp = 'step_up';

    /** A stronger PoW stage is required via a one-shot chain ticket (CHAIN_REQUIRED). */
    case ChainRequired = 'chain_required';
}
