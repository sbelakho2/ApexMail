<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Pricing;

/**
 * The value class of the priced request: what the protected action is
 * worth to the deployment. Weights are per-mille multipliers of the risk
 * score, held in PriceModel::CONSTS in this enum's order.
 */
enum ValueClass: string
{
    case Low = 'low';
    case Standard = 'standard';
    case High = 'high';
    case Critical = 'critical';

    /** The per-mille value weight of the class. */
    public function weight(): int
    {
        return PriceModel::CONSTS['value_weights'][$this->index()];
    }

    /** The class index inside the consts table's weight list. */
    public function index(): int
    {
        return match ($this) {
            self::Low => 0,
            self::Standard => 1,
            self::High => 2,
            self::Critical => 3,
        };
    }
}
