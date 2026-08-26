<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Security metadata exists but is malformed or version-unknown: it is
 * never transformed into "missing metadata" (which would let a challenge
 * proceed without its action/cData/chain evidence). The caller maps this
 * typed exception to the fail-closed 503.
 */
final class SiteVerifyMetadataCorruptException extends \RuntimeException
{
}
