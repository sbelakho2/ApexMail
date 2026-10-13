<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;

/**
 * The store-backed default marks reader: the session and principal
 * marks of the engine-derived pseudonyms, plus the agent mark for a
 * configured agent name and the ASN bucket mark when a dataset is
 * attached. The attacked-target record of the request's resolved target
 * pseudonym (when the engine carries one) is read from the live failure
 * state, so a stuffed target forces the interactive step-up.
 */
final class StoreMarksReader implements MarksReaderInterface
{
    public function __construct(
        private readonly OutcomeMarksStoreInterface $marks,
        private readonly ?string $agent = null,
        private readonly ?AsnDataset $asn = null,
        private readonly int $markTtlMs = MarksEscalation::DEFAULT_MARK_TTL_MS,
    ) {
    }

    public function requestMarks(MarksRequest $request): MarksView
    {
        $own = [];
        if ($request->session !== null) {
            $own['session'] = $request->session;
        }
        if ($request->principal !== null) {
            $own['principal'] = $request->principal;
        }
        if ($this->agent !== null) {
            $own['agent'] = $this->agent;
        }
        if ($this->asn !== null) {
            $own['asn'] = $this->asn->bucketId($request->sourceIp);
        }

        return MarksView::read($this->marks, $own, $request->target);
    }

    public function markTtlMs(): int
    {
        return $this->markTtlMs;
    }
}
