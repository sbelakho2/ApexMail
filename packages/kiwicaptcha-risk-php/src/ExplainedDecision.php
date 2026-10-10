<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * An assessed decision with its explanation attached: the additive
 * explanation surface of the engine's assess result. The serialized
 * form is the decision's public fields plus one explanation object,
 * so existing consumers of the decision JSON keep parsing unchanged.
 */
final class ExplainedDecision implements \JsonSerializable
{
    public function __construct(
        public readonly RiskDecision $decision,
        public readonly DecisionExplanation $explanation,
    ) {
    }

    /**
     * Wraps an assessed decision with the explanation built from the
     * given dimension names and optional price rung.
     *
     * @param list<string> $dimensions
     */
    public static function wrap(RiskDecision $decision, array $dimensions = [], ?string $priceRung = null): self
    {
        return new self($decision, DecisionExplanation::forDecision($decision, $dimensions, $priceRung));
    }

    /**
     * @return array<string, mixed> the decision's public fields plus
     *                              the additive explanation object
     */
    public function jsonSerialize(): array
    {
        return $this->decision->jsonSerialize() + ['explanation' => $this->explanation->jsonSerialize()];
    }
}
