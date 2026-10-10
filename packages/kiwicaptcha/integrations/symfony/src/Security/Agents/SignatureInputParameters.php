<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * The parsed value of one Signature-Input header field (RFC 9421
 * §4): the label, the covered-component identifier list and the
 * signature parameters, with the parameter order preserved.
 *
 * The parameter order matters because the signature base's final
 * @signature-params line carries the serialization of exactly this
 * inner list: a verifier that reordered parameters would rebuild a
 * different base and every signature would fail. The canonical
 * re-serialization {@see self::serializedInnerList()} therefore
 * walks the parsed items and parameters in the order they appeared.
 */
final class SignatureInputParameters
{
    /**
     * @param list<string>                    $covered    the covered-component
     *                                                    identifiers, in
     *                                                    order.
     * @param list<array{0: string, 1: string|int, 2: string}> $parameters the signature
     *                                                    parameters in
     *                                                    order: [key,
     *                                                    value, kind],
     *                                                    where kind is
     *                                                    "string" or
     *                                                    "integer".
     * @param string                          $serialized the canonical
     *                                                    re-serialization
     *                                                    of the inner
     *                                                    list (without
     *                                                    the label).
     */
    public function __construct(
        public readonly string $label,
        public readonly array $covered,
        public readonly array $parameters,
        private readonly string $serialized,
    ) {
    }

    /** The canonical inner-list serialization for the base's last line. */
    public function serializedInnerList(): string
    {
        return $this->serialized;
    }

    /**
     * The value of one parameter, or null when the parameter is
     * absent. A repeated parameter is refused by the parser, so at
     * most one value exists per key.
     */
    public function parameter(string $key): string|int|null
    {
        foreach ($this->parameters as [$parameterKey, $value]) {
            if ($parameterKey === $key) {
                return $value;
            }
        }

        return null;
    }
}
