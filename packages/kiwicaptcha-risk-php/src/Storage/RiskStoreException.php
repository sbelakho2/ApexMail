<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Raised when the risk state backend cannot serve an assessment; the engine
 * treats this as a circuit-breaker failure and degrades.
 */
class RiskStoreException extends \RuntimeException
{
}
