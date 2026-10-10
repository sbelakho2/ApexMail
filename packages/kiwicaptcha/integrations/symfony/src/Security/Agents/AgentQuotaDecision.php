<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * The decision of one agent-quota admission: admitted, or the
 * window that bound (minute or day) with the Retry-After hint in
 * whole seconds. On admission the counts are the post-admission
 * live window counts; on a refusal the live count is the binding
 * window's count, for the escalation log context.
 */
final class AgentQuotaDecision
{
    public function __construct(
        public readonly bool $admitted,
        public readonly ?string $bindingWindow,
        public readonly ?int $retryAfterSecs,
        public readonly int $liveCount,
        public readonly int $secondCount,
    ) {
    }
}
