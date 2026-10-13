<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The server-side state record of one begun step-up challenge.
 *
 * The record is the authority of the challenge: everything the client
 * holds is the signed ticket naming the record id, so the client can
 * never alter the principal, the scope, the expiry or the attempt
 * count. The stored proof material is a keyed hash of the expected
 * code (never the code itself), so a store snapshot leaks no second
 * factor. Records carry only pseudonyms: the raw identifier of the
 * principal or target never reaches this object or its wire form.
 *
 * The demand binding (schema v2): an authorizing challenge names the
 * {@see StepUpDemand} it answers in `demandId`, and its proof can only
 * ever finalize that demand. Null is the pre-demand wire shape of the
 * drain period and the shape of the explicitly non-authorizing
 * ceremonies (the WebAuthn creation of enrollment/bootstrap, which
 * books no completion effect and restores no login). A demandless
 * record stores and verifies like any other, but it authorizes
 * nothing: the demand plane's completion refuses a demandless proof,
 * so demandless challenge completion can never invoke the
 * finalization, restore a pending login or authorize the original
 * action. Records of the earlier wire shape (version 1, no demand
 * binding at all) are refused during the drain period. The refusal is
 * bounded by the challenge TTL, and an upgrade must fail closed,
 * never verify against a record the new schema cannot fully
 * interpret.
 */
final class StepUpChallenge
{
    private const SCHEMA_VERSION = 2;

    /**
     * The plaintext of the client secret minted for a stateless begin.
     * Runtime-only: it is handed to the begin presentation exactly once
     * and never survives into {@see self::toArray()} (the only storage
     * form). Null for a session-bound challenge (which mints none).
     */
    private ?string $issuedClientSecret = null;

    private function __construct(
        public readonly string $id,
        public readonly StepUpChallengeKind $kind,
        public readonly string $principalPseudonym,
        public readonly ?string $targetPseudonym,
        public readonly string $scope,
        public readonly ?string $returnPath,
        public readonly string $reason,
        public readonly int $createdAt,
        public readonly int $expiresAt,
        public readonly int $maxAttempts,
        public readonly int $attempts,
        public readonly ?string $codeHash,
        public readonly ?string $ceremony = null,
        public readonly ?string $sessionHash = null,
        /**
         * The SHA-256 of a per-challenge client secret, minted only for
         * stateless begins (a begin request with no started session).
         * A session-bound challenge stores null: each challenge has
         * exactly one binding. The plaintext secret is returned once at
         * begin and never stored.
         */
        public readonly ?string $clientSecretHash = null,
        public readonly bool $targetOwned = false,
        /**
         * The creation challenge carries the bootstrap authorization it
         * was begun under. The grant is consumed at begin (single-use),
         * so the completion must read this flag, re-consulting the
         * gate would find nothing and refuse a legitimate bootstrap
         * enrollment at the finish line.
         */
        public readonly bool $bootstrapAuthorized = false,
        /**
         * The principal pseudonym the record belongs to, null when the
         * record's subject is not a principal. The email-ownership
         * family addresses its records by the email address pseudonym
         * in principalPseudonym (the consume key), so its subject is
         * an email, never an account. Every principal-keyed lookup
         * (an active-challenge search, a completion-credit scan) MUST
         * go through {@see self::principalSubject()}; an email-subject
         * record can then never answer for an account.
         */
        public readonly ?string $subjectPseudonym = null,
        /**
         * The demand the challenge answers: the id of the live
         * {@see StepUpDemand} record the plane minted for this step-up.
         * The proof of a consumed challenge finalizes exactly that
         * demand; an unbound challenge finalizes nothing. Absent on the
         * pre-demand wire shape (the decode derives null).
         */
        public readonly ?string $demandId = null,
        /**
         * The server-held factor snapshot: the factor identity the
         * record's completion proves, resolved once at begin and stored
         * on the record. The completion plane judges a demand's stored
         * requirement against this snapshot, never a caller argument,
         * so a buggy or hostile completion lane cannot claim a stronger
         * factor than the record was begun under. The family and the
         * rank are the kind's own ladder rung (a record never claims
         * another family than its proof material verifies). The factor
         * id is the handler identity that begun it, which a custom
         * handler names as its own. Null only on the pre-snapshot wire
         * shape (the decode derives the kind's rung).
         */
        public readonly ?FactorRequirement $factor = null,
    ) {
    }

    /**
     * A fresh challenge record. The id is minted by the caller (the
     * store, on create) and must match the ticket's signed challenge id
     * shape. The optional ceremony names the WebAuthn ceremony the
     * handler begun (creation or assertion); the other handlers carry
     * none.
     *
     * `$sessionId` binds the challenge to the session that began it
     * (stored as a hash, never the raw id). `$targetOwned` is the
     * caller's assertion that the principal owns the named target; only
     * then may completion clear the target's failure/lockout state.
     * `$demandId` is the demand the challenge answers; the proof of the
     * consumed challenge finalizes exactly that demand. `$factor` is
     * the factor snapshot the record carries: null derives it from the
     * kind, and an explicit snapshot must serve the kind's own family.
     * A custom handler names its identity inside its kind's rung, it
     * never claims another family's.
     */
    public static function begin(
        string $id,
        StepUpChallengeKind $kind,
        string $principalPseudonym,
        ?string $targetPseudonym,
        string $scope,
        ?string $returnPath,
        string $reason,
        int $now,
        int $ttlSecs,
        int $maxAttempts,
        ?string $codeHash,
        ?string $ceremony = null,
        ?string $sessionId = null,
        bool $targetOwned = false,
        bool $bootstrapAuthorized = false,
        ?string $subjectPseudonym = null,
        ?string $demandId = null,
        ?FactorRequirement $factor = null,
    ): self {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('A step-up challenge TTL must be positive');
        }
        if ($maxAttempts < 1) {
            throw new \InvalidArgumentException('A step-up challenge attempt cap must be positive');
        }
        if ($returnPath !== null && !StepUpContext::isSafeReturnPath($returnPath)) {
            throw new \InvalidArgumentException('A step-up challenge return path must be an absolute same-site path');
        }
        if ($ceremony !== null && !\in_array($ceremony, ['creation', 'assertion'], true)) {
            throw new \InvalidArgumentException('A step-up challenge ceremony must be creation or assertion');
        }
        if ($demandId !== null && preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1) {
            throw new \InvalidArgumentException('A step-up challenge demand id must be the base64url id shape');
        }
        if ($demandId !== null && $ceremony === 'creation') {
            throw new \InvalidArgumentException('An enrollment creation ceremony is explicitly non-authorizing and never binds a demand id');
        }
        // The factor snapshot: the server-held factor identity the
        // record's completion proves. Null derives the kind's own rung.
        // An explicit snapshot must serve that rung's family, so a
        // handler can name its custom identity inside its kind's family
        // but never claim a stronger family than its proof material
        // verifies.
        $rung = self::factorOfKind($kind);
        $snapshot = $factor ?? $rung;
        if ($snapshot->family !== $rung->family) {
            throw new \InvalidArgumentException('A step-up challenge factor snapshot must serve the family its kind proves');
        }
        // The subject is a principal pseudonym only when the record's
        // family is principal-keyed. The email-ownership family
        // addresses its records by the email pseudonym, so its subject
        // is never an account: the field stays null there, by
        // construction and by validation.
        if ($kind === StepUpChallengeKind::EmailOwnership) {
            $subjectPseudonym = null;
        } elseif ($subjectPseudonym !== null) {
            $subjectPseudonym = self::pseudonym('subject', $subjectPseudonym);
        } else {
            $subjectPseudonym = self::pseudonym('principal', $principalPseudonym);
        }

        $clientSecret = null;
        $clientSecretHash = null;
        // Exactly one binding: a session-bound challenge carries no
        // client secret, and a stateless begin mints one (returned once
        // through {@see self::issuedClientSecret()}, stored hashed).
        if ($sessionId === null || $sessionId === '') {
            $clientSecret = self::clientSecret();
            $clientSecretHash = self::clientSecretHash($clientSecret);
        }
        $challenge = new self(
            $id,
            $kind,
            self::pseudonym('principal', $principalPseudonym),
            $targetPseudonym === null ? null : self::targetPseudonym($targetPseudonym),
            self::token('scope', $scope),
            $returnPath,
            self::token('reason', $reason),
            $now,
            $now + $ttlSecs,
            $maxAttempts,
            0,
            $codeHash,
            $ceremony,
            self::sessionHash($sessionId),
            $clientSecretHash,
            $targetOwned && $targetPseudonym !== null,
            $bootstrapAuthorized,
            $subjectPseudonym,
            $demandId,
            $snapshot,
        );
        $challenge->issuedClientSecret = $clientSecret;

        return $challenge;
    }

    /**
     * The assurance rung a stored challenge kind proves: the ladder
     * family and rank the kind's proof material verifies, with the
     * handler identity the kind's own lane spells. The anonymous
     * email-ownership grant proves the email_otp rung spelled as the
     * grant lane's own factor identity. This derivation is the
     * authority the begin snapshot and the decode fallback share, and
     * the identity the completion stores judge the demand requirement
     * against.
     */
    public static function factorOfKind(StepUpChallengeKind $kind): FactorRequirement
    {
        return match ($kind) {
            StepUpChallengeKind::EmailOtp => new FactorRequirement(FactorRequirement::EMAIL_OTP, FactorRequirement::EMAIL_OTP, 1),
            StepUpChallengeKind::EmailOwnership => new FactorRequirement(FactorRequirement::EMAIL_OTP, StepUpFactorAssurance::EMAIL_OWNERSHIP, 1),
            StepUpChallengeKind::Totp => new FactorRequirement(FactorRequirement::TOTP, FactorRequirement::TOTP, 2),
            StepUpChallengeKind::WebAuthn => new FactorRequirement(FactorRequirement::WEBAUTHN, FactorRequirement::WEBAUTHN, 3),
        };
    }

    /**
     * The pseudonym a principal-keyed lookup may match on: the subject
     * principal of the record, or null when the record's subject is
     * not a principal (the email-ownership family). A lookup MUST use
     * this accessor and MUST treat null as no-match; the raw
     * principalPseudonym field of an email-ownership record carries an
     * email address pseudonym and can never answer for an account.
     */
    public function principalSubject(): ?string
    {
        return $this->subjectPseudonym;
    }

    /** Mint a plaintext secret for a stateless begin (returned once). */
    public static function clientSecret(): string
    {
        return bin2hex(random_bytes(16));
    }

    /** The stored form of a client secret: SHA-256 hex, never the secret. */
    public static function clientSecretHash(string $secret): string
    {
        return hash('sha256', $secret);
    }

    /**
     * The plaintext secret minted for a stateless begin, for the begin
     * response to return exactly once. Null for a session-bound
     * challenge. Never persisted: {@see self::toArray()} stores only
     * the hash.
     */
    public function issuedClientSecret(): ?string
    {
        return $this->issuedClientSecret;
    }

    /** Whether a presented plaintext secret matches the stored hash. */
    public function clientSecretMatches(string $presented): bool
    {
        return $this->clientSecretHash !== null && $this->clientSecretHash !== ''
            && hash_equals($this->clientSecretHash, self::clientSecretHash($presented));
    }

    public static function sessionHash(?string $sessionId): ?string
    {
        if ($sessionId === null || $sessionId === '') {
            return null;
        }

        return hash('sha256', $sessionId);
    }

    /**
     * Mint an unguessable challenge id: the base64url of 16 random
     * bytes, the same id alphabet and length family the chain tickets
     * use.
     */
    public static function mintId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    }

    public function withAttempts(int $attempts): self
    {
        return new self(
            $this->id,
            $this->kind,
            $this->principalPseudonym,
            $this->targetPseudonym,
            $this->scope,
            $this->returnPath,
            $this->reason,
            $this->createdAt,
            $this->expiresAt,
            $this->maxAttempts,
            $attempts,
            $this->codeHash,
            $this->ceremony,
            $this->sessionHash,
            $this->clientSecretHash,
            $this->targetOwned,
            $this->bootstrapAuthorized,
            $this->subjectPseudonym,
            $this->demandId,
            $this->factor,
        );
    }

    public function expired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * The canonical wire form: the exact JSON the stores persist. Only
     * pseudonym and bounded-token fields, never a raw identifier.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'v' => self::SCHEMA_VERSION,
            'id' => $this->id,
            'kind' => $this->kind->value,
            'principal' => $this->principalPseudonym,
            'target' => $this->targetPseudonym,
            'scope' => $this->scope,
            'return_path' => $this->returnPath,
            'reason' => $this->reason,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'attempts' => $this->attempts,
            'max_attempts' => $this->maxAttempts,
            'code_hash' => $this->codeHash,
            'ceremony' => $this->ceremony,
            'session_hash' => $this->sessionHash,
            'client_secret_hash' => $this->clientSecretHash,
            'bootstrap' => $this->bootstrapAuthorized ? 1 : 0,
            'target_owned' => $this->targetOwned,
            'subject' => $this->subjectPseudonym,
            'demand_id' => $this->demandId,
            'factor_family' => $this->factor?->family,
            'factor_id' => $this->factor?->factorId,
            'factor_rank' => $this->factor?->assuranceRank,
        ];
    }

    /**
     * The strict decode, all-or-nothing: a missing field, a wrong type,
     * a shape violation or an incoherent state throws
     * {@see MalformedStepUpChallengeException}, never a defaulted
     * record. Fail-closed on every lane.
     *
     * @param array<string, mixed> $record
     */
    public static function fromArray(array $record): self
    {
        $fail = static fn (string $what): MalformedStepUpChallengeException => new MalformedStepUpChallengeException(
            'The step-up challenge record is malformed: '.$what,
        );
        if (($record['v'] ?? null) !== self::SCHEMA_VERSION) {
            throw $fail('schema version must be 2');
        }
        foreach (['id', 'kind', 'principal', 'scope', 'reason'] as $field) {
            if (!\is_string($record[$field] ?? null) || $record[$field] === '') {
                throw $fail(sprintf('%s must be a non-empty string', $field));
            }
        }
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $record['id']) !== 1) {
            throw $fail('id must be the base64url challenge id shape');
        }
        try {
            $kind = StepUpChallengeKind::from((string) $record['kind']);
        } catch (\ValueError) {
            throw $fail('kind must name a handler family');
        }
        // The factor snapshot is a coherent triple when it rides at all:
        // a half snapshot is not a decodable record, and a snapshot that
        // claims another family than its kind proves is incoherent. A
        // record without the triple (the pre-snapshot wire shape) decodes
        // and derives the kind's own rung.
        $factor = null;
        $factorFamily = $record['factor_family'] ?? null;
        $factorId = $record['factor_id'] ?? null;
        $factorRank = $record['factor_rank'] ?? null;
        if ($factorFamily !== null || $factorId !== null || $factorRank !== null) {
            if (!\is_string($factorFamily) || !\is_string($factorId) || !\is_int($factorRank)) {
                throw $fail('the factor snapshot must be a coherent family, id and rank triple');
            }
            try {
                $factor = new FactorRequirement($factorFamily, $factorId, $factorRank);
            } catch (\InvalidArgumentException) {
                throw $fail('the factor snapshot must be a ladder family, its rank and a well-shaped factor id');
            }
            if ($factor->family !== self::factorOfKind($kind)->family) {
                throw $fail('the factor snapshot must serve the family its kind proves');
            }
        }
        // The subject rides the record verbatim: absent on the
        // pre-subject wire shape (the decode derives it), else a 32-hex
        // pseudonym, and never present on an email-ownership record
        // (its subject is an email, never an account).
        $subjectRaw = $record['subject'] ?? null;
        if ($subjectRaw !== null) {
            if (!\is_string($subjectRaw) || preg_match('/^[0-9a-f]{32}$/D', $subjectRaw) !== 1) {
                throw $fail('subject must be 32 lowercase hex chars');
            }
            if ($kind === StepUpChallengeKind::EmailOwnership) {
                throw $fail('an email-ownership record carries no principal subject');
            }
        } elseif ($kind !== StepUpChallengeKind::EmailOwnership) {
            $subjectRaw = \is_string($record['principal'] ?? null) ? $record['principal'] : null;
        }
        try {
            $challenge = self::begin(
                $record['id'],
                $kind,
                $record['principal'],
                \is_string($record['target'] ?? null) ? $record['target'] : null,
                $record['scope'],
                \is_string($record['return_path'] ?? null) ? $record['return_path'] : null,
                $record['reason'],
                \is_int($record['created_at'] ?? null) ? $record['created_at'] : 0,
                (\is_int($record['expires_at'] ?? null) ? $record['expires_at'] : 0)
                    - (\is_int($record['created_at'] ?? null) ? $record['created_at'] : 0),
                \is_int($record['max_attempts'] ?? null) ? $record['max_attempts'] : 0,
                \is_string($record['code_hash'] ?? null) && $record['code_hash'] !== '' ? $record['code_hash'] : null,
                ($record['ceremony'] ?? null) === null ? null : (is_string($record['ceremony']) ? $record['ceremony'] : 'not-a-string'),
                null,
                ($record['target_owned'] ?? false) === true,
                subjectPseudonym: $subjectRaw,
                demandId: \is_string($record['demand_id'] ?? null) && $record['demand_id'] !== '' ? $record['demand_id'] : null,
                factor: $factor,
            );
        } catch (\InvalidArgumentException $e) {
            throw new MalformedStepUpChallengeException('The step-up challenge record is malformed: '.$e->getMessage(), 0, $e);
        }
        // Restore the recorded session binding verbatim (the hash is
        // opaque; begin() would have re-hashed a raw id). A malformed
        // hash shape fails closed.
        $sessionHash = $record['session_hash'] ?? null;
        if ($sessionHash !== null) {
            if (!\is_string($sessionHash) || preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1) {
                throw $fail('session_hash must be a 64-char lowercase hex digest');
            }
        }
        $clientSecretHash = $record['client_secret_hash'] ?? null;
        if ($clientSecretHash !== null) {
            if (!\is_string($clientSecretHash) || preg_match('/^[0-9a-f]{64}$/D', $clientSecretHash) !== 1) {
                throw $fail('client_secret_hash must be a 64-char lowercase hex digest');
            }
        }
        // Exactly one binding per challenge: a record carrying both (or
        // neither) a session hash and a client-secret hash is incoherent
        // and refused. Fail closed on every lane.
        if (($sessionHash !== null) === ($clientSecretHash !== null)) {
            throw $fail('exactly one of session_hash / client_secret_hash must be present');
        }
        // Strict: when present, exactly the integer 0 or 1, never a
        // stringly-typed "1" / "1abc", a boolean, or null. Absent means
        // 0 (the pre-bootstrap wire shape). Every other field decodes
        // fail-closed; the bootstrap flag is no exception.
        if (\array_key_exists('bootstrap', $record)) {
            $bootstrapRaw = $record['bootstrap'];
            if (!\is_int($bootstrapRaw) || ($bootstrapRaw !== 0 && $bootstrapRaw !== 1)) {
                throw $fail('bootstrap must be the integer 0 or 1');
            }
            $bootstrapAuthorized = $bootstrapRaw === 1;
        } else {
            $bootstrapAuthorized = false;
        }
        $challenge = new self(
            $challenge->id,
            $challenge->kind,
            $challenge->principalPseudonym,
            $challenge->targetPseudonym,
            $challenge->scope,
            $challenge->returnPath,
            $challenge->reason,
            $challenge->createdAt,
            $challenge->expiresAt,
            $challenge->maxAttempts,
            $challenge->attempts,
            $challenge->codeHash,
            $challenge->ceremony,
            $sessionHash,
            $clientSecretHash,
            $challenge->targetOwned,
            $bootstrapAuthorized,
            $challenge->subjectPseudonym,
            $challenge->demandId,
            $challenge->factor,
        );
        $attempts = $record['attempts'] ?? null;
        if (!\is_int($attempts) || $attempts < 0 || $attempts > $challenge->maxAttempts) {
            throw $fail('attempts must be an integer within 0..max_attempts');
        }
        if ($challenge->kind === StepUpChallengeKind::EmailOtp && $challenge->codeHash === null) {
            throw $fail('an email_otp challenge must carry its code hash');
        }
        if ($challenge->kind === StepUpChallengeKind::Totp && $challenge->codeHash !== null) {
            throw $fail('a totp challenge carries no code hash');
        }
        if ($challenge->kind === StepUpChallengeKind::WebAuthn) {
            if ($challenge->codeHash === null || $challenge->ceremony === null) {
                throw $fail('a webauthn challenge must carry its ceremony challenge hash and its ceremony kind');
            }
        }
        if ($challenge->kind !== StepUpChallengeKind::WebAuthn && $challenge->ceremony !== null) {
            throw $fail('only a webauthn challenge carries a ceremony');
        }
        // The demand binding of the v2 wire shape. A demand id rides
        // only in its exact base64url shape, and only on a record that
        // can authorize: an enrollment creation ceremony is explicitly
        // non-authorizing and never binds one. A record without a
        // demand id decodes (the pre-demand wire shape of the drain
        // period), but it authorizes nothing: the demand plane's
        // completion refuses a demandless proof, so a stored
        // demandless challenge can never invoke the finalization,
        // restore a pending login or authorize the original action.
        $demandId = $record['demand_id'] ?? null;
        if ($challenge->ceremony === 'creation') {
            if ($demandId !== null) {
                throw $fail('a creation ceremony carries no demand id');
            }
        } elseif ($demandId !== null && preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1) {
            throw $fail('demand_id must be the base64url id shape');
        }

        return $challenge->withAttempts($attempts);
    }

    public static function fromJson(string $json): self
    {
        $decoded = json_decode($json, true, 16);
        if (!\is_array($decoded)) {
            throw new MalformedStepUpChallengeException('The step-up challenge record is malformed: not a JSON object');
        }

        return self::fromArray($decoded);
    }

    private static function pseudonym(string $name, string $value): string
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $value) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'The %s pseudonym of a step-up challenge must be 32 lowercase hex chars, never a raw identifier',
                $name,
            ));
        }

        return $value;
    }

    /**
     * The target pseudonym: the canonical full digest (64 hex chars),
     * never a raw identifier and never a truncated form.
     */
    private static function targetPseudonym(string $value): string
    {
        if (preg_match('/^[0-9a-f]{64}$/D', $value) !== 1) {
            throw new \InvalidArgumentException(
                'The target pseudonym of a step-up challenge must be 64 lowercase hex chars, never a raw identifier',
            );
        }

        return $value;
    }

    private static function token(string $name, string $value): string
    {
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
            throw new \InvalidArgumentException(sprintf('The %s of a step-up challenge must be 1-128 chars of [A-Za-z0-9._:-]', $name));
        }

        return $value;
    }
}
