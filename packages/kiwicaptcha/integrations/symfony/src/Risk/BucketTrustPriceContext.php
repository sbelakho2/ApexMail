<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\Pricing\PriceContextSourceInterface;
use KiwiCaptcha\Risk\Pricing\PriceInputs;
use KiwiCaptcha\Risk\Pricing\PriceRequest;
use KiwiCaptcha\Risk\Pricing\ValueClass;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;

/**
 * The bundle's price-context seam over the risk package's pricing stage
 * (the marks-reader precedent: the core defines the stage, the bundle
 * composes the deployment's own inputs).
 *
 * Two inputs resolve here:
 *  - the value class of the protected action: the operator's per-scope
 *    mapping (risk.scopes.<name>.value_class) of what the scope protects,
 *    keyed by the canonical scope id. An unlisted scope prices standard.
 *  - the session's raw bucket-trust credit in its current ASN bucket,
 *    read through the wired ContextBoundTrust facade (trust.lua). A
 *    sessionless request has no trust record to read, so it prices at
 *    zero credit, exactly the fail-closed default of an unreadable
 *    surface: the pressure gate treats the identity as unproven and the
 *    price may only raise the composed action.
 *
 * Without an ASN dataset the trust read is structurally impossible (a
 * bucket needs the dataset to resolve), so the context prices zero
 * credit for every request: the pricing stage stays live, just
 * permanently unproven, until the deployment ships a dataset. No raw
 * identifier and no pseudonym ever leaves this boundary: the read
 * returns a plain integer on the trust plane's raw scale.
 */
final class BucketTrustPriceContext implements PriceContextSourceInterface
{
    /**
     * @param array<int, ValueClass> $scopeValueClasses canonical scope id
     *                                                => value class
     * @param ContextBoundTrust|null $trust             the bucket-trust
     *                                                facade, wired only
     *                                                when an ASN dataset
     *                                                is configured
     */
    public function __construct(
        private readonly array $scopeValueClasses,
        private readonly ?ContextBoundTrust $trust,
    ) {
    }

    public function priceInputs(PriceRequest $request): PriceInputs
    {
        $valueClass = $this->scopeValueClasses[$request->scope] ?? ValueClass::Standard;
        if ($this->trust === null || $request->session === null) {
            return new PriceInputs(valueClass: $valueClass, bucketTrust: 0);
        }

        return new PriceInputs(
            valueClass: $valueClass,
            bucketTrust: $this->trust->creditFor($request->session, $request->sourceIp)->rawTrust,
        );
    }
}
