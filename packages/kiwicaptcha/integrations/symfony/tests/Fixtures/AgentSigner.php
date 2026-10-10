<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * The RFC 9421 test signer of the verified-agents plane. It derives
 * a deterministic Ed25519 key pair from a label and builds the
 * signature base independently of the verifier: the base string is
 * constructed here per the RFC 9421 §2.3 grammar, never by calling
 * the bundle's code under test. It signs the base detached.
 *
 * Vector provenance, honestly labeled: the deterministic seeds and
 * the signed bases are self-vectors constructed by this fixture,
 * not the published RFC 9421 Appendix B byte vectors. The
 * grammar-rule assertions (the hand-written expected base strings)
 * pin the construction against the RFC's rules. The round trips pin
 * the Ed25519 verification.
 */
final class AgentSigner
{
    private string $secretKey;
    private string $publicKey;

    public function __construct(string $seed)
    {
        if (\strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('the seed must be exactly 32 bytes');
        }
        $pair = sodium_crypto_sign_seed_keypair($seed);
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = sodium_crypto_sign_publickey($pair);
    }

    /** A deterministic 32-byte seed from a test label. */
    public static function seed(string $label): string
    {
        return hash('sha256', 'kiwi-agents-test|'.$label, true);
    }

    /** The raw 32-byte Ed25519 public key (for the agent configuration). */
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    /** The base64 form for the risk.agents.<name>.public_keys list. */
    public function publicKeyBase64(): string
    {
        return base64_encode($this->publicKey);
    }

    /**
     * Signs one signature base and returns the wire headers.
     *
     * @param list<string>  $covered  the covered-component identifiers
     * @param array<string, string|int> $parameters the signature parameters,
     *                                in serialization order
     */
    public function signedHeaders(array $covered, array $parameters, string $base): array
    {
        $items = [];
        foreach ($covered as $component) {
            $items[] = '"'.$this->escape($component).'"';
        }
        $parameterString = '';
        foreach ($parameters as $key => $value) {
            $parameterString .= \is_int($value)
                ? ';'.$key.'='.$value
                : ';'.$key.'="'.$this->escape((string) $value).'"';
        }
        $signatureInput = 'sig1=('.implode(' ', $items).')'.$parameterString;
        $signature = sodium_crypto_sign_detached($base, $this->secretKey);

        return [
            'Signature-Input' => $signatureInput,
            'Signature' => 'sig1=:'.base64_encode($signature).':',
        ];
    }

    /**
     * The RFC 9530 content-digest header value of one body under one
     * algorithm name ('sha-256' or 'sha-512').
     */
    public static function contentDigest(string $body, string $algorithm = 'sha-256'): string
    {
        $hash = $algorithm === 'sha-512' ? 'sha512' : 'sha256';

        return $algorithm.'=:'.base64_encode(hash($hash, $body, true)).':';
    }

    /**
     * The signature base per RFC 9421 §2.3, constructed here from
     * the raw component values. The tests therefore assert the
     * verifier's construction against an independent implementation
     * of the same grammar: one line per covered component, then the
     * @signature-params line carrying the serialized parameters.
     *
     * @param list<string>                $covered
     * @param array<string, string|int>   $parameters
     * @param array<string, string|null>  $values   component id => value
     */
    public static function signatureBase(array $covered, array $parameters, array $values): string
    {
        $lines = [];
        foreach ($covered as $component) {
            $lines[] = sprintf('"%s" %s', $component, (string) $values[$component]);
        }
        $parameterString = '';
        foreach ($parameters as $key => $value) {
            $parameterString .= \is_int($value)
                ? ';'.$key.'='.$value
                : ';'.$key.'="'.self::escapeString((string) $value).'"';
        }
        $lines[] = sprintf('"@signature-params" (%s)%s', implode(' ', array_map(
            static fn (string $component): string => '"'.$component.'"',
            $covered,
        )), $parameterString);

        return implode("\n", $lines)."\n";
    }

    private function escape(string $value): string
    {
        return self::escapeString($value);
    }

    private static function escapeString(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
