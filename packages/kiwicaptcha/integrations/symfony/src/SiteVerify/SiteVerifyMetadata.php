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
    ) {
    }

    public function toArray(): array
    {
        return [
            'action' => $this->action,
            'cdata' => $this->cdata,
            'sitekey' => $this->sitekey,
            'chainId' => $this->chainId,
            'chainDepth' => $this->chainDepth,
        ];
    }

    public static function fromArray(array $data): ?self
    {
        $action = isset($data['action']) && \is_string($data['action']) ? $data['action'] : null;
        $cdata = isset($data['cdata']) && \is_string($data['cdata']) ? $data['cdata'] : null;
        $sitekey = isset($data['sitekey']) && \is_string($data['sitekey']) ? $data['sitekey'] : null;
        $chainId = isset($data['chainId']) && \is_string($data['chainId']) ? $data['chainId'] : null;
        $chainDepth = isset($data['chainDepth']) && \is_int($data['chainDepth']) ? $data['chainDepth'] : 0;
        if ($action === null && $cdata === null && $sitekey === null && $chainId === null && $chainDepth === 0) {
            return null;
        }

        return new self($action, $cdata, $sitekey, $chainId, $chainDepth);
    }

    public function isEmpty(): bool
    {
        return $this->action === null && $this->cdata === null && $this->sitekey === null
            && $this->chainId === null && $this->chainDepth === 0;
    }
}
