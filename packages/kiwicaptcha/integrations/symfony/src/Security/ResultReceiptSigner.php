<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * OPTIONAL Ed25519 signer for EXPORTED verification results (audit #80).
 *
 * The result verification itself is CENTRAL-ONLY by design: the HMAC secret
 * never leaves the server, so a third party can never re-derive a
 * verification result on its own. What this signer enables is an ASYMMETRIC
 * receipt of a server-verified result: when risk.result_receipt_signing_key
 * (base64 32-byte Ed25519 seed) is configured, the validator signs every
 * valid verification into the canonical payload
 *
 *     {jti, scope, binding, outcome, issued_at_ms}
 *
 * with sodium_crypto_sign_detached, and the application can hand the payload
 * + signature to any party holding the PUBLIC key (derived from the seed via
 * {@see publicKeyBase64()}) — never the private key. The payload is fully
 * public by construction: it carries the challenge jti, the flow scope, the
 * signed transaction binding, the fixed outcome "valid" and the issuance
 * (receipt) timestamp in ms — no secret material, no client identity beyond
 * what the challenge already carried.
 *
 * The signature format is the raw 64-byte Ed25519 detached signature,
 * base64-encoded (88 chars). Verification:
 *
 *     sodium_crypto_sign_verify_detached(
 *         base64_decode($signature),
 *         $payload,
 *         base64_decode($publicKeyBase64),
 *     )
 *
 * A receipt of a valid result is only as fresh as its issued_at_ms — the
 * application must bound how long a receipt stays acceptable (the challenge
 * lifetime bounds the result itself).
 */
final class ResultReceiptSigner
{
    private const SEED_BYTES = 32;

    private readonly string $seed;

    private readonly string $secretKey;

    private readonly string $publicKey;

    /**
     * @param string|null $seedBase64 base64 32-byte Ed25519 seed, or null to
     *                                disable receipt signing entirely
     *
     * @throws \InvalidArgumentException when the seed is present but not a
     *                                   base64-encoded 32-byte Ed25519 seed
     */
    public function __construct(
        ?string $seedBase64 = null,
    ) {
        if ($seedBase64 === null || $seedBase64 === '') {
            $this->seed = '';
            $this->secretKey = '';
            $this->publicKey = '';

            return;
        }
        $seed = base64_decode($seedBase64, true);
        if ($seed === false || \strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException(
                'result_receipt_signing_key must be a base64-encoded 32-byte Ed25519 seed'
            );
        }
        $this->seed = $seed;
        // The seed IS the Ed25519 secret key: the seed_keypair expansion
        // yields sk(64) || pk(32), the canonical keypair layout every sodium
        // implementation shares. The signing key stays in process memory;
        // only the PUBLIC half is ever exported.
        $keypair = \sodium_crypto_sign_seed_keypair($seed);
        $this->secretKey = \substr($keypair, 0, 64);
        $this->publicKey = \substr($keypair, 64, 32);
    }

    /** Whether signing is enabled (a valid seed is configured). */
    public function enabled(): bool
    {
        return $this->seed !== '';
    }

    /**
     * The public verification key (base64 32 bytes). Safe to hand to any
     * receipt verifier — it is the public half of the Ed25519 keypair; the
     * PRIVATE half (the seed) is the signing key and must never leave the
     * server.
     */
    public function publicKeyBase64(): string
    {
        return base64_encode($this->publicKey);
    }

    /**
     * Sign a valid verification result into a detached Ed25519 receipt.
     *
     * @return array{payload: string, signature: string}|null the canonical
     *         JSON payload and its base64 detached signature, or null when
     *         signing is disabled (risk.result_receipt_signing_key unset)
     */
    public function sign(string $jti, string $scope, ?string $binding, int $issuedAtMs): ?array
    {
        if (!$this->enabled()) {
            return null;
        }
        $payload = (string) json_encode([
            'jti' => $jti,
            'scope' => $scope,
            'binding' => $binding,
            'outcome' => 'valid',
            'issued_at_ms' => $issuedAtMs,
        ], JSON_UNESCAPED_SLASHES);

        $signature = \sodium_crypto_sign_detached($payload, $this->secretKey);

        return ['payload' => $payload, 'signature' => base64_encode($signature)];
    }
}
