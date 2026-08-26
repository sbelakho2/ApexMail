<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\ChallengeRecord;

/**
 * Optional Ed25519 signer for exported verification results.
 *
 * The result verification itself is central-only by design: the HMAC secret
 * never leaves the server, so a third party can never re-derive a
 * verification result on its own. What this signer enables is an asymmetric
 * receipt of a server-verified result. When
 * risk.result_receipt_signing_key (base64 32-byte Ed25519 seed) is
 * configured, the validator signs every valid verification into the
 * canonical payload below: the full replay-critical set taken from the
 * consumed record, see {@see ChallengeRecord} passed to {@see sign()}.
 *
 *     {jti, tenant, action, request_binding, issued_at, expires_at, issuer}
 *
 *   - jti             the challenge nonce (the single-use replay id).
 *   - tenant          the flow scope the challenge was minted for.
 *   - action          the PoW action the challenge required
 *                     (sha256 | argon2id, the record's algorithm).
 *   - request_binding the signed transaction binding (null when unbound).
 *   - issued_at       the record's issuance epoch (seconds, the record
 *                     wire unit, shared with the Rust schema).
 *   - expires_at      the record's expiry epoch (seconds); a receipt is
 *                     only acceptable while now <= expires_at (+ application
 *                     skew).
 *   - issuer          the deployment issuer; null when unset.
 *
 * with sodium_crypto_sign_detached, and the application can hand the payload
 * + signature to any party holding the public key (derived from the seed via
 * {@see publicKeyBase64()}), never the private key. The payload is fully
 * public by construction: no secret material, no client identity beyond what
 * the challenge already carried.
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
 * Single-use semantics: signature verification alone is not sufficient for
 * single-use actions — a valid signature proves the payload was signed by
 * the server, not that the jti has not already been consumed elsewhere. An
 * integrator accepting a receipt for a one-time action must additionally
 * record the jti atomically: insert-if-absent on an idempotency table
 * (`SET <key> NX`) or a unique constraint. Treat a pre-existing jti as a
 * replay: verify_and_consume — verify the signature, then atomically
 * insert the jti; only a first insert proceeds with the action. See the
 * `README` ("Asymmetric result receipts").
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
        // only the public half is ever exported.
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
     * private half (the seed) is the signing key and must never leave the
     * server.
     */
    public function publicKeyBase64(): string
    {
        return base64_encode($this->publicKey);
    }

    /**
     * Sign a valid verification result into a detached Ed25519 receipt.
     *
     * The payload carries the full replay-critical set from the consumed
     * record: jti (the nonce), tenant (the record's scope),
     * action (the record's PoW algorithm), request_binding, issued_at /
     * expires_at (epoch seconds, the record wire unit) and issuer. An
     * integrator can key its idempotency, freshness and scope checks on the
     * receipt alone.
     *
     * @return array{payload: string, signature: string}|null the canonical
     *         JSON payload and its base64 detached signature, or null when
     *         signing is disabled (risk.result_receipt_signing_key unset)
     */
    public function sign(ChallengeRecord $record): ?array
    {
        if (!$this->enabled()) {
            return null;
        }
        // The versioned v2 payload: an offline receiver must validate the
        // signature, the expected issuer/region, the policy epoch, the
        // scope, the request binding, the required proof/profile, the
        // expiry and the atomic first-seen JTI. v1 payloads (without the
        // version marker) are never treated as equivalent: a receiver
        // demanding v2 must refuse them.
        $payload = (string) json_encode([
            'v' => 2,
            'jti' => $record->nonce,
            'tenant' => $record->scope,
            'request_binding' => $record->requestBinding,
            'issued_at' => $record->issuedAt,
            'expires_at' => $record->expiresAt,
            'issuer' => $record->issuer,
            'region' => $record->region,
            'policy_version' => $record->policyVersion,
            'algorithm' => $record->algorithm->value,
            'target_bits' => $record->targetBits,
            'm_kib' => $record->mKib,
            't' => $record->t,
            'p' => $record->p,
        ], JSON_UNESCAPED_SLASHES);

        $signature = \sodium_crypto_sign_detached($payload, $this->secretKey);

        return ['payload' => $payload, 'signature' => base64_encode($signature)];
    }
}
