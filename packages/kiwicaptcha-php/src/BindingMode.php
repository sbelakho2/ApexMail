<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Client-binding mode for issued challenges. Lives in its own file so the
 * PSR-4 autoloader resolves it independently of Config.
 */
enum BindingMode: string
{
    /** Bind challenges to a nonce-bound HMAC tag of the client IP. */
    case Bound = 'bound';

    /** No client binding at all (maximum privacy; relay protection off). */
    case None = 'none';
}
