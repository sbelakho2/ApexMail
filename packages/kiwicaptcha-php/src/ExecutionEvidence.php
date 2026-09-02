<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The execution evidence a solution presents for an
 * ExecutionChallengeV1-armed record: the digest and the trace the
 * decoded token carries, held together as one immutable value.
 *
 * The digest is the 64-lowercase-hex execution digest; the trace is
 * the base64url form that travels on the wire, exactly the two fields
 * of {@see SolutionToken}. The verifier's execution binding checks
 * consume the pair together: an armed record demands both, and a call
 * site cannot hand over the digest while dropping the trace once the
 * evidence object is the argument. Both members may be absent on an
 * unarmed submission; a partial pair cannot arise from a decoded
 * wire token.
 */
final class ExecutionEvidence
{
    public function __construct(
        public readonly ?string $digest,
        public readonly ?string $trace,
    ) {
    }

    /**
     * The evidence a decoded solution token carries.
     */
    public static function fromToken(SolutionToken $token): self
    {
        return new self($token->executionDigest, $token->executionTrace);
    }

    /**
     * True when neither the digest nor the trace is present: an
     * unarmed submission carries no execution evidence.
     */
    public function isEmpty(): bool
    {
        return $this->digest === null && $this->trace === null;
    }
}
