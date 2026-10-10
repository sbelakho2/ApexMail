<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

/**
 * The target-mark probe of the success-trust gate: true when the risk
 * store holds a live long-memory mark for the target pseudonym. The
 * caller passes the canonical 64-hex target pseudonym. The mark key is
 * its one derived spelling, {@see TargetMarkKey::of()}. It is the same
 * projection every mark writer uses, so a read can only miss because
 * the mark is absent. That miss is never because the two sides spelled
 * the key differently. Marks are written only by server-confirmed outcomes, so
 * a live mark is the deployment's own evidence that this target is
 * under attack; the gate then withholds session and source credit. A
 * read failure propagates and the gate refuses the credit, fail closed.
 */
final class TargetMarkProbe
{
    public function __construct(
        private readonly RedisRiskStateStore $store,
    ) {
    }

    public function __invoke(string $targetPseudonym): bool
    {
        return $this->store->readMark('target', TargetMarkKey::of($targetPseudonym)) !== null;
    }
}
