<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * An issued challenge, ready to serialize to the widget.
 *
 * Wire shape matches the Rust `IssuedChallenge` exactly so the widget (and the
 * WASM solver) behave identically regardless of the backend language.
 *
 * The optional `decoyField` is the server-issued decoy (honeypot)
 * form-field name armed for this challenge, when the deployment enables
 * the decoy surface, see {@see Issuer::issueWithDecoyField()}: a random
 * name from the server-side pool (`CSPRNG`-picked per issuance, matching
 * `[A-Za-z0-9_-]{1,64}`). The widget driver renders a hidden text input
 * with exactly this name next to the token input and never auto-fills
 * it. A submission that carries a value in it is bot evidence. The name
 * is authenticated: it is signed into the canonical payload as the
 * final `|<decoy_field>` segment, see {@see Issuer::canonicalPayload()},
 * so a client cannot strip or swap it without breaking the signature the
 * verifier re-checks.
 *
 * Wire compatibility: unarmed records are byte-identical to the
 * pre-decoy format — the `decoy_field` key is absent from `toArray()`
 * (and therefore the JSON) when no decoy is armed, never a JSON `null`,
 * and old payloads (no key) deserialize with null. An armed record is
 * protocol v3 (the decoy-capable canonical) and requires a v3-capable
 * verifier: an old verifier rejects version 3 as unknown. The grammar
 * is total: v2 => no decoy, v3 => decoy present. A stored version flip
 * can never change the effective protocol.
 *
 * An rsw challenge carries the optional `rsw_modulus` key: the public
 * 2048-bit composite in canonical base64, absent for every other
 * algorithm. The solver squares modulo it, and the value is not a
 * secret, since n is public by design.
 */
final class Challenge
{
    public function __construct(
        public readonly string $nonce,
        public readonly string $challenge,
        public readonly string $salt,
        public readonly PoWAlgorithm $algorithm,
        public readonly int $mKib,
        public readonly int $t,
        public readonly int $p,
        public readonly int $targetBits,
        public readonly int $ttlSecs,
        public readonly int $minDurationMs,
        public readonly string $prefix,
        // The armed decoy (honeypot) form-field name; null = no decoy
        // (the legacy wire shape — the key is omitted when null).
        public readonly ?string $decoyField = null,
        // The armed ExecutionChallengeV1 program (base64 of the bytecode
        // blob); null = no execution dimension (the legacy wire shape —
        // the key is omitted when null). Present only when the server
        // armed the dimension, see Issuer::issueWithExecutionField();
        // the driver runs it and presents the resulting digest with the
        // solution token.
        public readonly ?string $executionProgram = null,
        // The rsw modulus n (canonical standard base64 of the 2048-bit
        // composite), present only when the challenge algorithm is rsw:
        // the client solver squares modulo n. The key is omitted when
        // null, so every other response keeps its exact byte shape. The
        // trapdoor lambda never rides this surface.
        public readonly ?string $rswModulus = null,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $data = [
            'nonce' => $this->nonce,
            'challenge' => $this->challenge,
            'salt' => $this->salt,
            'algorithm' => $this->algorithm->value,
            'mKib' => $this->mKib,
            't' => $this->t,
            'p' => $this->p,
            'targetBits' => $this->targetBits,
            'ttlSecs' => $this->ttlSecs,
            'minDurationMs' => $this->minDurationMs,
            'prefix' => $this->prefix,
        ];
        // The decoy key is absent when no decoy is armed — the exact
        // mirror of the Rust `skip_serializing_if = "Option::is_none"`:
        // never a JSON `null` key, so old clients ignore the new key and
        // unarmed responses keep the exact pre-decoy byte format.
        if ($this->decoyField !== null) {
            $data['decoy_field'] = $this->decoyField;
        }
        // The execution program key is absent when the dimension is not
        // armed: old clients ignore the new key and unarmed responses
        // keep the exact pre-execution byte format.
        if ($this->executionProgram !== null) {
            $data['execution_program'] = $this->executionProgram;
        }
        // The rsw modulus key is absent unless the challenge is an rsw
        // challenge, the same skip-when-null rule: a sha256/argon2id
        // response keeps its exact byte format.
        if ($this->rswModulus !== null) {
            $data['rsw_modulus'] = $this->rswModulus;
        }

        return $data;
    }
}
