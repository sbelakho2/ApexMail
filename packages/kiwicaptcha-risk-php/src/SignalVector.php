<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * 13 fixed-point signal fields (each 0..1000), in the EXACT contract order.
 *
 * JSON key order in the fixtures and `toArray()` must match:
 *   source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
 *   replay, action_failure, scope_switch, global_pressure, network_risk,
 *   trust_credit, principal_credit
 */
final class SignalVector
{
    public function __construct(
        public readonly int $sourceFast,
        public readonly int $sourceSlow,
        public readonly int $subnetFast,
        public readonly int $issueDebt,
        public readonly int $badProof,
        public readonly int $malformed,
        public readonly int $replay,
        public readonly int $actionFailure,
        public readonly int $scopeSwitch,
        public readonly int $globalPressure,
        public readonly int $networkRisk,
        public readonly int $trustCredit,
        public readonly int $principalCredit,
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 0 || $value > 1000) {
                throw new \InvalidArgumentException(
                    sprintf('Signal values must be within 0..1000 (got %d)', $value)
                );
            }
        }
    }

    public static function zero(): self
    {
        return new self(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    /** Accepts snake_case keys per the fixtures (missing keys default to 0). */
    public static function fromArray(array $data): self
    {
        return new self(
            sourceFast: (int) ($data['source_fast'] ?? 0),
            sourceSlow: (int) ($data['source_slow'] ?? 0),
            subnetFast: (int) ($data['subnet_fast'] ?? 0),
            issueDebt: (int) ($data['issue_debt'] ?? 0),
            badProof: (int) ($data['bad_proof'] ?? 0),
            malformed: (int) ($data['malformed'] ?? 0),
            replay: (int) ($data['replay'] ?? 0),
            actionFailure: (int) ($data['action_failure'] ?? 0),
            scopeSwitch: (int) ($data['scope_switch'] ?? 0),
            globalPressure: (int) ($data['global_pressure'] ?? 0),
            networkRisk: (int) ($data['network_risk'] ?? 0),
            trustCredit: (int) ($data['trust_credit'] ?? 0),
            principalCredit: (int) ($data['principal_credit'] ?? 0),
        );
    }

    /** Snake_case keys in contract order. */
    public function toArray(): array
    {
        return [
            'source_fast' => $this->sourceFast,
            'source_slow' => $this->sourceSlow,
            'subnet_fast' => $this->subnetFast,
            'issue_debt' => $this->issueDebt,
            'bad_proof' => $this->badProof,
            'malformed' => $this->malformed,
            'replay' => $this->replay,
            'action_failure' => $this->actionFailure,
            'scope_switch' => $this->scopeSwitch,
            'global_pressure' => $this->globalPressure,
            'network_risk' => $this->networkRisk,
            'trust_credit' => $this->trustCredit,
            'principal_credit' => $this->principalCredit,
        ];
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new \InvalidArgumentException('SignalVector JSON must decode to an object');
        }
        return self::fromArray($data);
    }
}
