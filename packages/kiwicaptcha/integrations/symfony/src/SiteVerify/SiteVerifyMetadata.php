<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Provider-compatible challenge metadata (Turnstile action / cData /
 * sitekey), bound to the challenge at issuance and returned from verified
 * server state. A backend Siteverify request can never supply these: the
 * trust direction is server-owned — the widget declares them at challenge
 * time, the server validates and persists them against the nonce, and the
 * verification response reads them back.
 *
 * The private chain fields (chainId / chainDepth) are server-stamped by
 * the stage-2 chain controller only: they never travel in the cdata, so
 * the application's own cdata is preserved untouched and the Siteverify
 * response keeps returning the app's value. The validator reads the
 * chainId to end a chain at stage 2. Old persisted records without the
 * fields parse with nulls/0.
 */
final readonly class SiteVerifyMetadata
{
    /**
     * @param string|null $action Turnstile action (regex ^[a-z0-9_-]{0,32}$).
     * @param string|null $cdata  Turnstile cData (regex ^[a-z0-9_-]{0,255}$).
     * @param string|null $sitekey the public sitekey the widget rendered for.
     * @param string|null $chainId the server-stamped chain id of a stage-2
     *                             issued challenge (private; null = not a
     *                             stage-2 chain challenge).
     * @param int         $chainDepth the chain depth of a stage-2 issued
     *                                challenge (2; 0 = not chained).
     */
    public function __construct(
        public ?string $action,
        public ?string $cdata,
        public ?string $sitekey,
        public ?string $chainId = null,
        public int $chainDepth = 0,
        public ?string $scope = null,
    ) {
    }

    /**
     * The versioned wire envelope: v:1 marks the shape so a malformed or
     * version-unknown record can never be mistaken for missing metadata.
     */
    public function toArray(): array
    {
        return [
            'v' => 1,
            'action' => $this->action,
            'cdata' => $this->cdata,
            'sitekey' => $this->sitekey,
            'scope' => $this->scope,
            'chainId' => $this->chainId,
            'chainDepth' => $this->chainDepth,
        ];
    }

    public static function fromArray(array $data): ?self
    {
        if (isset($data['v']) && $data['v'] !== 1) {
            throw new SiteVerifyMetadataCorruptException('unsupported metadata envelope version');
        }
        // A present non-null value of the wrong type is corrupt
        // persisted state, never a defaulted field: normalizing it
        // would silently answer replays with emptied metadata instead
        // of the retryable failure the corrupt-state contract
        // promises. Absent or null keys keep their legacy defaults
        // (records persisted before a field existed parse unchanged).
        $action = self::optionalString($data, 'action');
        $cdata = self::optionalString($data, 'cdata');
        $sitekey = self::optionalString($data, 'sitekey');
        $scope = self::optionalString($data, 'scope');
        $chainId = self::optionalString($data, 'chainId');
        $chainDepth = 0;
        if (\array_key_exists('chainDepth', $data) && $data['chainDepth'] !== null) {
            if (!\is_int($data['chainDepth'])) {
                throw new SiteVerifyMetadataCorruptException('metadata field "chainDepth" must be an integer when present');
            }
            $chainDepth = $data['chainDepth'];
        }
        // The semantic layer: every present value must fit the same
        // grammar its request-surface validation enforces, and the
        // chain coordinates must arrive as the exact pair the chain
        // controller stamps (a chain id sits at depth two; any other
        // combination is a coordinate nobody can legitimately produce).
        if ($action !== null && preg_match('/^[a-z0-9_-]{1,32}$/iD', $action) !== 1) {
            throw new SiteVerifyMetadataCorruptException('metadata field "action" does not match the action grammar ([a-z0-9_-]{1,32})');
        }
        if ($cdata !== null && preg_match('/^[a-z0-9_-]{1,255}$/iD', $cdata) !== 1) {
            throw new SiteVerifyMetadataCorruptException('metadata field "cdata" does not match the cdata grammar ([a-z0-9_-]{1,255})');
        }
        foreach (['sitekey', 'scope'] as $identifierField) {
            $value = ${$identifierField};
            if ($value !== null && preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $value) !== 1) {
                throw new SiteVerifyMetadataCorruptException(sprintf('metadata field "%s" does not match the identifier grammar ([A-Za-z0-9._:-]{1,128})', $identifierField));
            }
        }
        // The chain id carries the exact grammar the chain protocol
        // mints and every chain component validates (the shared
        // validator), never the looser identifier family: corrupted
        // persisted state shaped like a foreign id fails closed.
        if ($chainId !== null && !\BelConsulting\KiwiCaptchaBundle\Risk\ChainId::isValid($chainId)) {
            throw new SiteVerifyMetadataCorruptException('metadata field "chainId" does not match the chain-id grammar ([A-Za-z0-9_-]{1,64})');
        }
        if ($chainDepth !== 0 && $chainDepth !== 2) {
            throw new SiteVerifyMetadataCorruptException('metadata field "chainDepth" must be exactly 0 or 2');
        }
        if ($chainId === null && $chainDepth !== 0) {
            throw new SiteVerifyMetadataCorruptException('metadata "chainDepth" is set without a chainId: the chain coordinates arrive as a pair');
        }
        if ($chainId !== null && $chainDepth !== 2) {
            throw new SiteVerifyMetadataCorruptException('metadata "chainId" is set without chainDepth 2: the chain coordinates arrive as a pair');
        }
        if ($action === null && $cdata === null && $sitekey === null && $scope === null && $chainId === null && $chainDepth === 0) {
            return null;
        }

        return new self($action, $cdata, $sitekey, $chainId, $chainDepth, $scope);
    }

    /** A present non-string throws; an absent or null key stays null. */
    private static function optionalString(array $data, string $key): ?string
    {
        if (!\array_key_exists($key, $data) || $data[$key] === null) {
            return null;
        }
        if (!\is_string($data[$key])) {
            throw new SiteVerifyMetadataCorruptException(sprintf('metadata field "%s" must be a string when present', $key));
        }

        return $data[$key];
    }

    public function isEmpty(): bool
    {
        return $this->action === null && $this->cdata === null && $this->sitekey === null
            && $this->scope === null && $this->chainId === null && $this->chainDepth === 0;
    }
}
