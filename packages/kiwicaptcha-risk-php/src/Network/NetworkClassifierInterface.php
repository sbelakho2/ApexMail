<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Network;

interface NetworkClassifierInterface
{
    /**
     * @throws \InvalidArgumentException on malformed IP input
     */
    public function classify(string $ip): NetworkFlags;
}
