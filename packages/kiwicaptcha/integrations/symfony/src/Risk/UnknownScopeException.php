<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Thrown by the risk gateway when a scope that is not configured in
 * kiwi_captcha.risk.scopes is assessed while unknown_scope.mode is
 * "reject" (the default).
 *
 * The challenge controller catches this and issues the default challenge
 * profile: baseline Kiwi verification still applies, the adaptive engine
 * simply declines to evaluate the request. Never a 500 — unknown scopes
 * are an application naming issue, not an outage.
 */
final class UnknownScopeException extends \RuntimeException
{
}
