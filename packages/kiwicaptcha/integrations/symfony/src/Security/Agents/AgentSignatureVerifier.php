<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

use Symfony\Component\HttpFoundation\Request;

/**
 * The RFC 9421 Ed25519 verifier of the verified-agents plane.
 *
 * The signature base is built per RFC 9421 section 2.3. One line per
 * covered component. Behind a reverse proxy that strips a mount
 * prefix, the configured base URL must include that prefix.
 */
final class AgentSignatureVerifier
{
    /** The default created-parameters skew window, ± seconds. */
    public const DEFAULT_CLOCK_SKEW_SECS = 300;

    /** The required signature tag: signatures of any other plane do not verify here. */
    public const REQUIRED_TAG = 'kiwi-agents-v1';

    /** The only accepted alg parameter value. */
    public const REQUIRED_ALG = 'ed25519';

    public const CODE_MALFORMED = 'AGENT_SIGNATURE_MALFORMED';
    public const CODE_UNKNOWN_KEY = 'AGENT_UNKNOWN_KEY';
    public const CODE_ALG_REJECTED = 'AGENT_ALG_REJECTED';
    public const CODE_COVERAGE_INVALID = 'AGENT_COVERAGE_INVALID';
    public const CODE_SKEW = 'AGENT_SIGNATURE_SKEW';
    public const CODE_EXPIRED = 'AGENT_SIGNATURE_EXPIRED';
    public const CODE_INVALID = 'AGENT_SIGNATURE_INVALID';
    public const CODE_REPLAYED = 'AGENT_SIGNATURE_REPLAYED';
    public const CODE_NONCE_UNAVAILABLE = 'AGENT_NONCE_UNAVAILABLE';
    public const CODE_ORIGIN_UNCONFIGURED = 'AGENT_ORIGIN_UNCONFIGURED';

    private const METHOD = '@method';
    private const TARGET_URI = '@target-uri';
    private const CONTENT_DIGEST = 'content-digest';

    /** The nonce ledger's minimum TTL: bounded replay protection. */
    private const NONCE_TTL_FLOOR_SECS = 300;

    /** The slack added past the signature acceptance deadline when sizing the nonce TTL. */
    private const NONCE_TTL_MARGIN_SECS = 60;

    private const CONTENT_LENGTH = 'content-length';

    /**
     * The RFC 9530 digest algorithms this verifier computes. The
     * strongest present in the header wins nothing extra: the
     * request verifies when any one provided algorithm matches the
     * recomputed digest of the exact body bytes.
     */
    private const DIGEST_ALGORITHMS = ['sha-256' => 'sha256', 'sha-512' => 'sha512'];

    /**
     * @param int              $clockSkewSecs the ± window the created
     *                                        parameter must sit inside
     * @param \Closure|null    $now           the epoch-seconds clock
     *                                        override for tests
     */
    public function __construct(
        private readonly AgentRegistry $agents,
        private readonly AgentNonceStore $nonceStore,
        private readonly int $clockSkewSecs = self::DEFAULT_CLOCK_SKEW_SECS,
        private readonly ?\Closure $now = null,
        private readonly ?string $publicOrigin = null,
    ) {
        if ($this->publicOrigin !== null) {
            $normalized = rtrim($this->publicOrigin, '/');
            if (preg_match('#^https?://[A-Za-z0-9.-]+(:[0-9]+)?$#D', $normalized) !== 1) {
                throw new \InvalidArgumentException('risk.agents public origin must be an absolute origin like https://api.example.com');
            }
        }
    }

    /**
     * Verifies one request's Signature-Input / Signature pair
     * against the configured agents and consumes its nonce.
     */
    public function verify(Request $request, string $rawBody): AgentGateResult
    {
        foreach (['signature-input', 'signature', self::CONTENT_DIGEST] as $singularHeader) {
            if (\count($request->headers->all($singularHeader)) > 1) {
                return $this->refused(self::CODE_MALFORMED, sprintf('The %s header must appear at most once.', $singularHeader));
            }
        }
        $signatureInputRaw = $request->headers->get('Signature-Input');
        $signatureRaw = $request->headers->get('Signature');
        if (!\is_string($signatureInputRaw) || !\is_string($signatureRaw)) {
            return $this->refused(self::CODE_MALFORMED, 'The request must carry one Signature-Input and one Signature header.');
        }

        $parser = new StructuredFieldsSubsetParser();
        try {
            $input = $parser->parseSignatureInput($signatureInputRaw);
            [$signatureLabel, $signatureBytes] = $parser->parseSignature($signatureRaw);
        } catch (\InvalidArgumentException $e) {
            return $this->refused(self::CODE_MALFORMED, 'The signature headers are malformed: '.$e->getMessage());
        }
        if ($signatureLabel !== $input->label) {
            return $this->refused(self::CODE_MALFORMED, 'The Signature label must match the Signature-Input label.');
        }

        $alg = $input->parameter('alg');
        if (!\is_string($alg) || $alg !== self::REQUIRED_ALG) {
            return $this->refused(self::CODE_ALG_REJECTED, 'The signature alg parameter must name ed25519.');
        }
        $tag = $input->parameter('tag');
        if (!\is_string($tag) || $tag !== self::REQUIRED_TAG) {
            return $this->refused(self::CODE_MALFORMED, 'The signature tag parameter must name '.self::REQUIRED_TAG.'.');
        }
        if ($this->publicOrigin === null) {
            return $this->refused(self::CODE_ORIGIN_UNCONFIGURED, 'The agent plane needs the configured public origin (public_base_url) so @target-uri can never be forged through the Host header.');
        }

        $keyId = $input->parameter('keyid');
        if (!\is_string($keyId) || $keyId === '') {
            return $this->refused(self::CODE_MALFORMED, 'The signature parameters must carry a keyid.');
        }
        $agent = $this->agents->agentByKeyId($keyId);
        if ($agent === null) {
            return $this->refused(self::CODE_UNKNOWN_KEY, 'The presented key id is not configured.');
        }

        $nonce = $input->parameter('nonce');
        if (!\is_string($nonce) || preg_match(AgentNonceStore::NONCE_PATTERN, $nonce) !== 1) {
            return $this->refused(self::CODE_MALFORMED, 'The signature nonce parameter is required, 1-128 characters of [A-Za-z0-9._~+=-].');
        }
        $created = $input->parameter('created');
        $expires = $input->parameter('expires');
        if (!\is_int($created) || !\is_int($expires)) {
            return $this->refused(self::CODE_MALFORMED, 'The signature parameters must carry integer created and expires values.');
        }

        $now = (int) ($this->now !== null ? ($this->now)() : time());
        // The created parameter is capped in both directions by the
        // skew window; the future bound matters for the nonce TTL
        // below (a far-future created would stretch the ledger entry
        // without bound), so it is stated explicitly rather than
        // implied by abs().
        if ($created > $now + $this->clockSkewSecs) {
            return $this->refused(self::CODE_SKEW, sprintf('The signature created parameter is more than %d seconds in the future.', $this->clockSkewSecs));
        }
        if ($created < $now - $this->clockSkewSecs) {
            return $this->refused(self::CODE_SKEW, sprintf('The signature created parameter is outside the ±%d second window.', $this->clockSkewSecs));
        }
        if ($expires <= $now || $expires < $created) {
            return $this->refused(self::CODE_EXPIRED, 'The signature has expired.');
        }

        $bodyPresent = $rawBody !== '';
        $coverage = $this->coverage($input->covered, $bodyPresent);
        if ($coverage !== null) {
            return $this->refused(self::CODE_COVERAGE_INVALID, $coverage);
        }

        // The covered content-length is an integrity commitment, not
        // a passthrough: the declared length must equal the actual
        // body length, so a body-swapping proxy that leaves the
        // signed framing intact while replacing the bytes (the
        // digest catches that too) or replays the framing around a
        // different length is refused here.
        if (\in_array(self::CONTENT_LENGTH, $input->covered, true)) {
            $declaredLength = $request->headers->get(self::CONTENT_LENGTH);
            if (!\is_string($declaredLength) || ctype_digit($declaredLength) !== true || (int) $declaredLength !== \strlen($rawBody)) {
                return $this->refused(self::CODE_INVALID, 'The covered content-length does not match the request body.');
            }
        }

        // The digest is required, never optional: a request that drops
        // the covered header would otherwise keep only length integrity,
        // and RFC 9421 treats a missing covered component as a failure.
        $digestHeader = $request->headers->get(self::CONTENT_DIGEST);
        if (!\is_string($digestHeader) || trim($digestHeader) === '') {
            return $this->refused(self::CODE_INVALID, 'The covered content-digest header is required.');
        }
        if (!$this->contentDigestMatches($digestHeader, $rawBody)) {
            return $this->refused(self::CODE_INVALID, 'The content-digest does not match the request body.');
        }

        try {
            $base = $this->signatureBase($request, $input, $rawBody);
        } catch (\Throwable) {
            return $this->refused(self::CODE_INVALID, 'A covered component is missing from the request.');
        }
        if (!$this->signatureVerifies($signatureBytes, $base, $agent)) {
            return $this->refused(self::CODE_INVALID, 'The signature does not verify.');
        }

        // The nonce must outlive the whole acceptance window, or the
        // same signature could be replayed after the ledger entry
        // expired but while created ± skew still admits it. The
        // acceptance window ends at min(expires, created + skew); the
        // TTL covers that deadline plus a margin, floored so the
        // ledger entry is always worth its write and capped so no
        // crafted created/expires pair can stretch it past twice the
        // skew window (the future-created bound above is what makes
        // that ceiling hold).
        $acceptanceEndsAt = min($expires, $created + $this->clockSkewSecs);
        $nonceTtl = max(self::NONCE_TTL_FLOOR_SECS, $acceptanceEndsAt - $now + self::NONCE_TTL_MARGIN_SECS);
        $nonceTtl = min($nonceTtl, max(self::NONCE_TTL_FLOOR_SECS, 2 * $this->clockSkewSecs + self::NONCE_TTL_MARGIN_SECS));
        try {
            if (!$this->nonceStore->claim($agent->keyId, $nonce, $nonceTtl)) {
                return $this->refused(self::CODE_REPLAYED, 'The signature nonce was already used.');
            }
        } catch (\Throwable) {
            return $this->refused(
                self::CODE_NONCE_UNAVAILABLE,
                'The nonce ledger is unavailable; the signature cannot be confirmed single-use.',
            );
        }

        return AgentGateResult::verified(new VerifiedAgentRequest($agent, $input->label));
    }

    /**
     * The signature base per RFC 9421 §2.3: one line per covered
     * component in the Signature-Input order, then the
     * @signature-params line carrying the serialized parameters.
     * Component identifiers serialize in the exact case they were
     * covered with (the covered set was already validated to the
     * fixed lowercase identifiers).
     */
    public function signatureBase(Request $request, SignatureInputParameters $input, string $rawBody): string
    {
        $lines = [];
        foreach ($input->covered as $component) {
            $lines[] = sprintf('"%s" %s', $component, $this->componentValue($request, $component, $rawBody));
        }
        $lines[] = sprintf('"@signature-params" %s', $input->serializedInnerList());

        return implode("\n", $lines)."\n";
    }

    /**
     * One covered component's value: the derived @method and
     * @target-uri per RFC 9421 §2.2, the covered header field values
     * trimmed per §2.1 (each covered header arrived as exactly one
     * field line, enforced by the singularity check).
     */
    private function componentValue(Request $request, string $component, string $rawBody): string
    {
        return match ($component) {
            self::METHOD => $request->getMethod(),
            // The configured origin, never the request's Host header:
            // a signature captured for one environment must not replay
            // against another through a loosely trusted proxy.
            self::TARGET_URI => $this->publicOrigin.$request->getRequestUri(),
            // A covered component that is absent from the message is a
            // failure, never an empty value: an empty content-digest
            // line would silently drop body integrity, and an empty
            // content-length line would drop length integrity. The
            // verify() path refuses these earlier; this keeps
            // signatureBase() honest for every caller.
            self::CONTENT_DIGEST => $this->requiredHeader($request, self::CONTENT_DIGEST),
            self::CONTENT_LENGTH => $request->headers->has(self::CONTENT_LENGTH)
                ? trim((string) $request->headers->get(self::CONTENT_LENGTH))
                : (string) \strlen($rawBody),
            default => throw new \LogicException(sprintf('The covered component "%s" was not validated', $component)),
        };
    }

    private function requiredHeader(Request $request, string $name): string
    {
        $value = $request->headers->get($name);
        if (!\is_string($value) || trim($value) === '') {
            throw new \LogicException(sprintf('The covered component "%s" is missing from the request; a covered component must be present', $name));
        }

        return trim($value);
    }

    /**
     * Validates the covered-component list against the fixed set:
     * @method, @target-uri and content-digest are always required;
     * content-length is required exactly when a body is present;
     * unknown components, derived-component parameters and
     * duplicates are refused. Returns the refusal message or null
     * when the coverage is valid.
     *
     * @param list<string> $covered
     */
    private function coverage(array $covered, bool $bodyPresent): ?string
    {
        if (\count($covered) !== \count(array_unique($covered))) {
            return 'The covered component list must not repeat a component.';
        }
        foreach ($covered as $component) {
            if (!\in_array($component, [self::METHOD, self::TARGET_URI, self::CONTENT_DIGEST, self::CONTENT_LENGTH], true)) {
                return sprintf('The covered component "%s" is not part of the verified-agents signing profile.', $component);
            }
        }
        foreach ([self::METHOD, self::TARGET_URI, self::CONTENT_DIGEST] as $required) {
            if (!\in_array($required, $covered, true)) {
                return sprintf('The signature must cover "%s".', $required);
            }
        }
        if ($bodyPresent && !\in_array(self::CONTENT_LENGTH, $covered, true)) {
            return 'The signature must cover "content-length" when a request body is present.';
        }

        return null;
    }

    /**
     * The RFC 9530 content-digest check: the header is a dictionary
     * of algorithm=:base64-digest: entries; the request passes when
     * at least one entry matches the digest of the exact raw body
     * bytes under this verifier's implemented algorithms. The
     * comparison is constant-time over the raw digest bytes.
     */
    private function contentDigestMatches(string $header, string $rawBody): bool
    {
        foreach (explode(',', $header) as $entry) {
            $entry = trim($entry);
            if ($entry === '' || preg_match('/^([a-z0-9-]+)=:([A-Za-z0-9+\/]*={0,2}):$/D', $entry, $m) !== 1) {
                return false;
            }
            $algorithm = self::DIGEST_ALGORITHMS[$m[1]] ?? null;
            if ($algorithm === null) {
                continue;
            }
            $provided = base64_decode($m[2], true);
            if ($provided !== false && hash_equals(hash($algorithm, $rawBody, true), $provided)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The detached Ed25519 verification against every configured
     * public key of the agent (the rotation window): any one match
     * verifies.
     */
    private function signatureVerifies(string $signatureBytes, string $base, AgentDefinition $agent): bool
    {
        if (\strlen($signatureBytes) !== \SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        foreach ($agent->publicKeys as $publicKey) {
            if (\strlen($publicKey) !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                continue;
            }
            try {
                if (sodium_crypto_sign_verify_detached($signatureBytes, $base, $publicKey)) {
                    return true;
                }
            } catch (\Throwable) {
                // A sodium refusal (a malformed key the registry did
                // not catch) is a failed verification, never a 500.
                continue;
            }
        }

        return false;
    }

    private function refused(string $code, string $message): AgentGateResult
    {
        return AgentGateResult::refused(401, $code, $message);
    }
}
