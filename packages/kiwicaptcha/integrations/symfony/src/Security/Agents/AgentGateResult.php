<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * The outcome of one verified-agents gate consultation: either a
 * verified agent (the request is a machine client of a configured
 * agent, cryptographically identified) or a typed refusal. A
 * refusal carries the HTTP status, the machine-readable error code,
 * a safe message and an optional Retry-After hint. Every refusal is
 * fail-closed: the controller answers it and nothing further in the
 * issuance pipeline runs.
 */
final class AgentGateResult
{
    /**
     * @param int|null $retryAfterSecs the Retry-After hint of a quota
     *                                 refusal, whole seconds
     */
    private function __construct(
        private readonly ?VerifiedAgentRequest $verified = null,
        private readonly int $status = 0,
        private readonly string $code = '',
        private readonly string $message = '',
        private readonly ?int $retryAfterSecs = null,
    ) {
    }

    public static function verified(VerifiedAgentRequest $request): self
    {
        return new self(verified: $request);
    }

    public static function refused(int $status, string $code, string $message, ?int $retryAfterSecs = null): self
    {
        return new self(status: $status, code: $code, message: $message, retryAfterSecs: $retryAfterSecs);
    }

    public function isVerified(): bool
    {
        return $this->verified !== null;
    }

    /** @throws \LogicException when this result is a refusal */
    public function agent(): VerifiedAgentRequest
    {
        return $this->verified ?? throw new \LogicException('The agent gate refused the request; there is no verified agent');
    }

    public function statusCode(): int
    {
        return $this->status;
    }

    public function errorCode(): string
    {
        return $this->code;
    }

    public function errorMessage(): string
    {
        return $this->message;
    }

    public function retryAfterSecs(): ?int
    {
        return $this->retryAfterSecs;
    }
}
