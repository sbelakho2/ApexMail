<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * The names-only decision explanation (change.md 3.8.3).
 *
 * A decision log carries the top contributing reasons, the identity
 * dimensions involved, the chosen action and, when a pricing stage is
 * composed, the chosen price rung. Every field is a name: reason
 * identifiers, dimension names, action and rung names. Pseudonym
 * values, raw identifiers and HMAC digests have no path into this
 * type, so a serialized explanation cannot leak them by construction.
 */
final class DecisionExplanation implements \JsonSerializable
{
    /**
     * @param list<RiskReason> $reasons   the decision's top contributors
     * @param list<string>     $dimensions contract dimension names only
     * @param string|null      $priceRung rung name when a pricing stage
     *                                     is composed
     */
    private function __construct(
        public readonly RiskAction $action,
        public readonly array $reasons,
        public readonly array $dimensions,
        public readonly ?string $priceRung,
    ) {
    }

    /** The names-only empty explanation (allow, nothing composed). */
    public static function empty(): self
    {
        return new self(RiskAction::Allow, [], [], null);
    }

    /**
     * Builds the explanation of an assessed decision. $dimensions
     * carries the contract names of the identity dimensions involved
     * in the assessment, for example the present dimensions of the
     * request's IdentityVector. Names outside the contract vocabulary
     * are dropped, so an unknown name can never smuggle a value onto
     * the wire. $priceRung carries the rung name when a pricing stage
     * chose one.
     *
     * @param list<string> $dimensions
     */
    public static function forDecision(RiskDecision $decision, array $dimensions, ?string $priceRung = null): self
    {
        return new self(
            action: $decision->action,
            reasons: $decision->reasons,
            dimensions: array_values(array_intersect(IdentityVector::DIMENSIONS, $dimensions)),
            priceRung: $priceRung,
        );
    }

    /** True when nothing is composed (no reasons, no dimensions, no rung). */
    public function isEmpty(): bool
    {
        return $this->reasons === [] && $this->dimensions === [] && $this->priceRung === null;
    }

    /**
     * @return array{action: string, reasons: list<string>, dimensions: list<string>, price_rung: string|null}
     */
    public function jsonSerialize(): array
    {
        return [
            'action' => $this->action->value,
            'reasons' => array_map(static fn (RiskReason $r): string => $r->value, $this->reasons),
            'dimensions' => $this->dimensions,
            'price_rung' => $this->priceRung,
        ];
    }
}
