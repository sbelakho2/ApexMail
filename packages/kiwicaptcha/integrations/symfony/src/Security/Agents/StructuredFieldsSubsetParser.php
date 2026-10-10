<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * A minimal RFC 8941 structured-fields parser for the covered
 * subset only, documented as such. It parses exactly one inner list
 * of string items carrying string and integer parameters (the shape
 * a Signature-Input field takes in this plane) and exactly one
 * label-equals-byte-sequence member (the shape of the Signature
 * field). Everything else the RFC defines — tokens, booleans,
 * decimals, dictionaries, nested lists, multiple list members,
 * byte-sequence parameters — is refused, not skipped. A narrower
 * parser is the fail-closed posture: nothing outside the documented
 * signing profile can reach the signature-base construction.
 *
 * The grammar walks RFC 8941 §4.1.1 for keys, §4.1.2 for display
 * strings (printable ASCII plus the backslash escapes) and §4.1.3
 * for integers (at most 15 digits, so a crafted parameter can never
 * overflow into a wrong created/expires comparison). Serialization
 * follows §4.1.2.2 and the inner-list rules of §4.1.1.2: single SP
 * between items, parameters glued to their item, no incidental
 * whitespace anywhere.
 */
final class StructuredFieldsSubsetParser
{
    /** The exact Ed25519 signature length the byte-sequence must decode to. */
    private const ED25519_SIGNATURE_BYTES = 64;

    /**
     * Parses one Signature-Input field value into its single labeled
     * inner list. Exactly one member is accepted: a field carrying
     * two labels describes two signatures, and this plane verifies
     * one signature per request, so the ambiguity is refused.
     *
     * @throws \InvalidArgumentException on any shape outside the
     *                                   documented subset
     */
    public function parseSignatureInput(string $value): SignatureInputParameters
    {
        $value = trim($value);
        $label = $this->parseKey($value);
        $this->expect($value, '=');
        if ($value === '' || $value[0] !== '(') {
            throw new \InvalidArgumentException('Signature-Input must carry an inner list of covered components');
        }
        $value = substr($value, 1);

        $covered = [];
        while ($value !== '' && $value[0] === '"') {
            $covered[] = $this->parseString($value);
            $value = ltrim($value, ' ');
        }
        if ($covered === []) {
            throw new \InvalidArgumentException('Signature-Input inner list must cover at least one component');
        }
        $this->expect($value, ')');

        $parameters = [];
        while ($value !== '' && $value[0] === ';') {
            $value = substr($value, 1);
            $key = $this->parseKey($value);
            if ($value === '' || $value[0] !== '=') {
                // A bare parameter is RFC 8941 boolean true; this
                // subset parses strings and integers only, so it is
                // refused, never coerced to "".
                throw new \InvalidArgumentException(sprintf('Signature-Input parameter "%s" must carry a string or integer value; bare boolean parameters are refused', $key));
            }
            $value = substr($value, 1);
            if ($value !== '' && $value[0] === '"') {
                $parameterValue = $this->parseString($value);
                $kind = 'string';
            } elseif ($value !== '' && ($value[0] === '-' || ctype_digit($value[0]))) {
                $parameterValue = $this->parseInteger($value);
                $kind = 'integer';
            } else {
                throw new \InvalidArgumentException(sprintf('Signature-Input parameter "%s" carries an unsupported value', $key));
            }
            foreach ($parameters as [$existingKey]) {
                if ($existingKey === $key) {
                    throw new \InvalidArgumentException(sprintf('Signature-Input parameter "%s" appears twice', $key));
                }
            }
            $parameters[] = [$key, $parameterValue, $kind];
        }

        if (trim($value, ' ') !== '') {
            throw new \InvalidArgumentException('Signature-Input carries more than one labeled signature; exactly one is accepted');
        }

        return new SignatureInputParameters($label, $covered, $parameters, $this->serializeInnerList($covered, $parameters));
    }

    /**
     * Parses one Signature field value into the label and the raw
     * signature bytes. Exactly one member, matching the one
     * Signature-Input label this plane verifies.
     *
     * @return array{0: string, 1: string} [label, raw signature bytes]
     *
     * @throws \InvalidArgumentException on any shape outside the
     *                                   documented subset
     */
    public function parseSignature(string $value): array
    {
        $value = trim($value);
        $label = $this->parseKey($value);
        $this->expect($value, '=');
        if ($value === '' || $value[0] !== ':') {
            throw new \InvalidArgumentException('Signature must carry a byte-sequence value');
        }
        $end = strpos($value, ':', 1);
        if ($end === false) {
            throw new \InvalidArgumentException('Signature byte-sequence is not terminated');
        }
        $encoded = substr($value, 1, $end - 1);
        $value = substr($value, $end + 1);
        if (trim($value, ' ') !== '') {
            throw new \InvalidArgumentException('Signature carries more than one labeled member; exactly one is accepted');
        }
        if (preg_match('/^[A-Za-z0-9+\/]*={0,2}$/D', $encoded) !== 1) {
            throw new \InvalidArgumentException('Signature byte-sequence is not canonical base64');
        }
        $bytes = base64_decode($encoded, true);
        if ($bytes === false) {
            throw new \InvalidArgumentException('Signature byte-sequence is not valid base64');
        }
        if (\strlen($bytes) !== self::ED25519_SIGNATURE_BYTES) {
            throw new \InvalidArgumentException('Signature byte-sequence must be exactly 64 bytes (one Ed25519 signature)');
        }

        return [$label, $bytes];
    }

    /** @throws \InvalidArgumentException when the next byte is not the expected one */
    private function expect(string &$value, string $byte): void
    {
        if ($value === '' || $value[0] !== $byte) {
            throw new \InvalidArgumentException(sprintf('Structured field syntax error: expected "%s"', $byte));
        }
        $value = substr($value, 1);
    }

    /**
     * A parameter or label key: lowercase lcalpha start, then the
     * key character set, per RFC 8941 §4.1.1.1.
     */
    private function parseKey(string &$value): string
    {
        if ($value === '' || preg_match('/^[a-z]/', $value) !== 1) {
            throw new \InvalidArgumentException('Structured field keys must start with a lowercase letter');
        }
        $length = strspn($value, 'abcdefghijklmnopqrstuvwxyz0123456789_-.');
        $key = substr($value, 0, $length);
        $value = substr($value, $length);

        return $key;
    }

    /**
     * A display string: printable ASCII between the quotes, with
     * backslash escaping for the backslash and the quote, per RFC
     * 8941 §4.1.2. Every other byte is refused.
     */
    private function parseString(string &$value): string
    {
        $this->expect($value, '"');
        $out = '';
        $length = \strlen($value);
        for ($i = 0; $i < $length; ++$i) {
            $byte = $value[$i];
            if ($byte === '"') {
                $value = substr($value, $i + 1);

                return $out;
            }
            if ($byte === '\\') {
                $next = $value[$i + 1] ?? '';
                if ($next !== '\\' && $next !== '"') {
                    throw new \InvalidArgumentException('Structured field strings may only escape the backslash and the quote');
                }
                $out .= $next;
                ++$i;
                continue;
            }
            if (\ord($byte) < 0x20 || \ord($byte) > 0x7E) {
                throw new \InvalidArgumentException('Structured field strings may carry printable ASCII only');
            }
            $out .= $byte;
        }
        throw new \InvalidArgumentException('Structured field string is not terminated');
    }

    /** An integer: at most 15 digits with an optional sign. */
    private function parseInteger(string &$value): int
    {
        if (preg_match('/^(-?)([0-9]{1,15})/D', $value, $m) !== 1) {
            throw new \InvalidArgumentException('Structured field integers carry at most 15 digits');
        }
        $value = substr($value, \strlen($m[0]));

        return (int) ($m[1].$m[2]);
    }

    /**
     * The canonical serialization of the inner list, RFC 8941
     * §4.1.2.2: items separated by single SP, parameters appended
     * without whitespace, strings re-escaped.
     *
     * @param list<string> $covered
     * @param list<array{0: string, 1: string|int, 2: string}> $parameters
     */
    private function serializeInnerList(array $covered, array $parameters): string
    {
        $out = '(';
        foreach ($covered as $i => $component) {
            $out .= ($i > 0 ? ' ' : '').'"'.$this->escapeString($component).'"';
        }
        $out .= ')';
        foreach ($parameters as [$key, $parameterValue, $kind]) {
            $out .= ';'.$key;
            $out .= $kind === 'integer' ? '='.$parameterValue : '="'.$this->escapeString((string) $parameterValue).'"';
        }

        return $out;
    }

    private function escapeString(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
