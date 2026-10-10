<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use ParagonIE\ConstantTime\Base64UrlSafe;


/**
 * The durable credential registry of the WebAuthn step-up handler:
 * the PublicKeyCredentialSourceRepository the ceremonies resolve
 * credentials through. One record per enrolled credential, keyed by
 * the credential id's hash and tagged with the principal pseudonym, so
 * the assertion ceremony can list a principal's allowed credentials
 * and the counter check can hold the per-credential sign counter.
 *
 * The registry rides the risk Redis under the step-up namespace, the
 * same protection boundary as every other security-side state of this
 * plane. Records carry the credential's public material and counters,
 * never a raw identifier: the user handle of a source is the principal
 * pseudonym the contexts carry anyway.
 *
 * The class exists (and is only wired) when the web-auth/webauthn-lib
 * package is installed: the interface it implements lives there.
 */
final class WebAuthnCredentialRegistry implements PublicKeyCredentialSourceRepository
{
    private const KEY_PREFIX = 'credential:';

    public function __construct(
        private readonly \Predis\ClientInterface $redis,
        private readonly string $prefix,
        private readonly int $ttlSecs = 31_536_000,
    ) {
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $json = $this->redis->get($this->key($publicKeyCredentialId));
        if (!\is_string($json) || $json === '') {
            return null;
        }
        $decoded = json_decode($json, true);
        if (!\is_array($decoded)) {
            return null;
        }

        return PublicKeyCredentialSource::createFromArray($decoded);
    }

    public function findAllForUserEntity(\Webauthn\PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return $this->registeredCredentialsOf($publicKeyCredentialUserEntity->id);
    }

    /**
     * The enrolled credentials of a principal (the handler's allow-list
     * source and its creation/assertion branch decision).
     *
     * @return list<PublicKeyCredentialSource>
     */
    public function registeredCredentialsOf(string $principalPseudonym): array
    {
        $keys = $this->redis->keys($this->prefix.self::KEY_PREFIX.'*');
        if (!\is_array($keys) || $keys === []) {
            return [];
        }
        $found = [];
        foreach ($keys as $key) {
            $json = $this->redis->get((string) $key);
            if (!\is_string($json) || $json === '') {
                continue;
            }
            $decoded = json_decode($json, true);
            // The library's serializer stores the user handle base64url
            // encoded, so the filter compares the encoded principal.
            if (!\is_array($decoded) || ($decoded['userHandle'] ?? null) !== Base64UrlSafe::encodeUnpadded($principalPseudonym)) {
                continue;
            }
            $found[] = PublicKeyCredentialSource::createFromArray($decoded);
        }

        return $found;
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $key = $this->key($publicKeyCredentialSource->publicKeyCredentialId);
        // Counter rollback guard: a write that would lower the stored
        // sign count is refused (fail-closed). A cloned or raced
        // authenticator can then never rewind the counter and re-use an
        // old assertion slot.
        $existingJson = $this->redis->get($key);
        if (\is_string($existingJson) && $existingJson !== '') {
            $existing = json_decode($existingJson, true);
            if (\is_array($existing)) {
                try {
                    $existingSource = PublicKeyCredentialSource::createFromArray($existing);
                    if ($publicKeyCredentialSource->counter < $existingSource->counter) {
                        return;
                    }
                } catch (\Throwable) {
                    // Unreadable prior record: fall through and overwrite
                    // with the validated source (fail-closed on the
                    // counter is impossible without a readable prior).
                }
            }
        }
        $this->redis->setex(
            $key,
            $this->ttlSecs,
            (string) json_encode($publicKeyCredentialSource, JSON_THROW_ON_ERROR),
        );
    }

    private function key(string $credentialId): string
    {
        return $this->prefix.self::KEY_PREFIX.hash('sha256', $credentialId);
    }
}
