<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Provider-compatible challenge metadata (Turnstile action / cData /
 * sitekey), bound to the challenge at ISSUANCE and returned from verified
 * server state. A backend Siteverify request can NEVER supply these — the
 * trust direction is server-owned: the widget declares them at challenge
 * time, the server validates and persists them against the nonce, and the
 * verification response reads them back.
 */
final readonly class SiteVerifyMetadata
{
    /**
     * @param string|null $action Turnstile action (regex ^[a-z0-9_-]{0,32}$)
     * @param string|null $cdata  Turnstile cData (regex ^[a-z0-9_-]{0,255}$)
     * @param string|null $sitekey the public sitekey the widget rendered for
     */
    public function __construct(
        public ?string $action,
        public ?string $cdata,
        public ?string $sitekey,
    ) {
    }

    public function toArray(): array
    {
        return [
            'action' => $this->action,
            'cdata' => $this->cdata,
            'sitekey' => $this->sitekey,
        ];
    }

    public static function fromArray(array $data): ?self
    {
        $action = isset($data['action']) && \is_string($data['action']) ? $data['action'] : null;
        $cdata = isset($data['cdata']) && \is_string($data['cdata']) ? $data['cdata'] : null;
        $sitekey = isset($data['sitekey']) && \is_string($data['sitekey']) ? $data['sitekey'] : null;
        if ($action === null && $cdata === null && $sitekey === null) {
            return null;
        }

        return new self($action, $cdata, $sitekey);
    }

    public function isEmpty(): bool
    {
        return $this->action === null && $this->cdata === null && $this->sitekey === null;
    }
}
