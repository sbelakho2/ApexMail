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
 * the optional chain binding of a CHAIN_REQUIRED disposition: the exact
 * chain id AND the chain's ORIGINAL server-held expiry
 * (chainExpiresAt — persisted as chain_expires_at). The expiry is bound
 * to the disposition's exact chain at finalize time, so the ticket
 * signing NEVER consults the current obligation again: a concurrently
 * opened chain of the same transaction can never leak its expiry into
 * this disposition's ticket, and a completed chain (record retained)
 * keeps re-signing its deterministic ticket. Raw risk vectors,
 * fingerprints and descriptors are NEVER persisted.
 */
final readonly class PostSolveDisposition
{
    public function __construct(
        public PostSolveDispositionKind $kind,
        public ?string $decisionId = null,
        public ?string $chainId = null,
        public ?int $chainExpiresAt = null,
    ) {
        if ($kind === PostSolveDispositionKind::ChainRequired && ($chainId === null || $chainId === '')) {
            throw new \InvalidArgumentException('a ChainRequired disposition must carry a chain id');
        }
        if ($kind === PostSolveDispositionKind::ChainRequired && $chainExpiresAt !== null && $chainExpiresAt <= 0) {
            throw new \InvalidArgumentException('a ChainRequired disposition chain expiry must be a positive unix bound');
        }
        if ($kind !== PostSolveDispositionKind::ChainRequired && $chainExpiresAt !== null) {
            throw new \InvalidArgumentException('a chain expiry is only meaningful on the ChainRequired kind');
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
