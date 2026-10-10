<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;
use KiwiCaptcha\Risk\Evidence\RedisScriptRunnerInterface;

/**
 * The bundle's adapter from the decoy-escalation store's tiny runner
 * contract to the shared Redis seam: {@see RedisEval} already knows the
 * phpredis and Predis eval() packing conventions, so this class is the
 * one bundle-side implementation the store needs. The wired client is
 * the risk Redis client reference (the same connection the risk state
 * store and the calibrator use).
 */
final class DecoyEscalationScriptRunner implements RedisScriptRunnerInterface
{
    public function __construct(
        private readonly \Predis\Client|\Redis $client,
    ) {
    }

    public function evalScript(string $script, array $keys, array $args): int|string|null
    {
        return RedisEval::eval($this->client, $script, $keys, $args);
    }
}
