<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The verified-agents gate the challenge controller consults: the
 * RFC 9421 verification of the presented signature, then the scope
 * authorization and quota of the verified agent.
 *
 * The seam mirrors how the scope cap is injected: the controller
 * holds one nullable service and asks it before the browser flow
 * runs. A request carrying a Signature-Input header on a deployment
 * with configured agents must verify — there is no silent
 * fallthrough to the widget flow, since the signature headers name
 * the machine-client plane and a widget request never carries them.
 *
 * Quota overrun escalates: the 429 refusal is paired with an
 * agent-dimension abuse mark through the typed outcomes surface and
 * a log line. The mark attributes the overrun on the agent's
 * long-memory identity exactly like any other confirmed abuse
 * reporter would attribute it. The escalation is best-effort on the
 * marks write (a valid 429 must never become a 500 because the
 * observability plane failed) and never blocks the refusal.
 */
final class AgentsVerifier
{
    public const CODE_SCOPE_NOT_ALLOWED = 'AGENT_SCOPE_NOT_ALLOWED';
    public const CODE_QUOTA_EXCEEDED = 'AGENT_QUOTA_EXCEEDED';
    public const CODE_QUOTA_UNAVAILABLE = 'AGENT_QUOTA_UNAVAILABLE';

    public function __construct(
        private readonly AgentSignatureVerifier $signatures,
        private readonly AgentQuota $quota,
        private readonly ?OutcomeReporterInterface $outcomes = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * Verifies the presented RFC 9421 signature. The typed 401
     * refusals of {@see AgentSignatureVerifier} surface here
     * unchanged; a verified result carries the agent the request
     * authenticated as.
     */
    public function verifySignature(Request $request, string $rawBody): AgentGateResult
    {
        return $this->signatures->verify($request, $rawBody);
    }

    /**
     * Authorizes the scope and consumes the quota of one verified
     * agent. The requested scope must be inside the agent's allowed
     * set (403 with the typed code otherwise). The per-minute or
     * per-day window must have room (429 with Retry-After plus the
     * escalation otherwise). The quota admission consumes the slot
     * of the issuance the caller then performs.
     */
    public function authorize(VerifiedAgentRequest $agent, string $scope): AgentGateResult
    {
        if (!$agent->definition()->allowsScope($scope)) {
            $this->log(
                'kiwicaptcha: verified agent {agent} requested scope {scope} outside its allowed set',
                ['agent' => $agent->name(), 'scope' => $scope],
            );

            return AgentGateResult::refused(
                Response::HTTP_FORBIDDEN,
                self::CODE_SCOPE_NOT_ALLOWED,
                'The verified agent is not allowed to request challenges for this scope.',
            );
        }

        try {
            $decision = $this->quota->admit($agent->definition());
        } catch (\Throwable $e) {
            // Fail closed: no quota proof means no agent issuance.
            // The detail goes to the server log only.
            $this->log('kiwicaptcha: agent quota backend unavailable for agent {agent}: {error}', [
                'agent' => $agent->name(),
                'error' => $e->getMessage(),
            ]);

            return AgentGateResult::refused(
                Response::HTTP_SERVICE_UNAVAILABLE,
                self::CODE_QUOTA_UNAVAILABLE,
                'Challenge issuance is temporarily unavailable. Try again later.',
            );
        }
        if (!$decision->admitted) {
            $this->escalateQuotaOverrun($agent, $decision);

            return AgentGateResult::refused(
                Response::HTTP_TOO_MANY_REQUESTS,
                self::CODE_QUOTA_EXCEEDED,
                sprintf(
                    'The verified agent has exceeded its per-%s challenge quota. Try again later.',
                    (string) $decision->bindingWindow,
                ),
                $decision->retryAfterSecs,
            );
        }

        return AgentGateResult::verified($agent);
    }

    /**
     * The escalation of one quota overrun: the agent-dimension abuse
     * mark through the outcomes surface (the same marks stage every
     * other abuse report writes) plus the log line. Best-effort by
     * contract: the refusal has already been decided, and a failing
     * marks write or a raising logger must never turn the 429 into
     * an unhandled error.
     */
    private function escalateQuotaOverrun(VerifiedAgentRequest $agent, AgentQuotaDecision $decision): void
    {
        $this->log('kiwicaptcha: verified agent {agent} exceeded its per-{window} quota (live {live}, retry after {retry}s) — the overrun is recorded as an abuse mark on the agent identity', [
            'agent' => $agent->name(),
            'window' => (string) $decision->bindingWindow,
            'live' => $decision->liveCount,
            'retry' => (string) $decision->retryAfterSecs,
        ]);
        if ($this->outcomes === null) {
            return;
        }
        try {
            $this->outcomes->report(Outcome::SpamReported, $agent->outcomeHandle());
        } catch (\Throwable $e) {
            $this->log('kiwicaptcha: agent quota escalation mark failed for agent {agent}: {error}', [
                'agent' => $agent->name(),
                'error' => $e->getMessage(),
            ]);
        }
    }

    /** @param array<string,mixed> $context */
    private function log(string $message, array $context = []): void
    {
        try {
            $this->logger?->warning($message, $context);
        } catch (\Throwable) {
            // A raising logger must never break the gate.
        }
    }
}
