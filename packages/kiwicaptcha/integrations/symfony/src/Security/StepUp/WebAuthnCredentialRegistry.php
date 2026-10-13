<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * The durable credential registry of the WebAuthn step-up handler: the
 * credential store the ceremonies resolve credentials through. One
 * record per enrolled credential, keyed by the credential id's hash and
 * tagged with the principal pseudonym, so the assertion ceremony can
 * list a principal's allowed credentials and the counter check can hold
 * the per-credential sign counter.
 *
 * The registry rides the risk Redis under the step-up namespace, the
 * same protection boundary as every other security-side state of this
 * plane. Records carry the credential's public material and counters,
 * never a raw identifier: the user handle of a record is the principal
 * pseudonym the contexts carry anyway.
 *
 * The class exists (and is only wired) when the web-auth/webauthn-lib
 * package is installed: the {@see CredentialRecord} shape and the
 * library serializer live there.
 */
final class WebAuthnCredentialRegistry
{
    private const KEY_PREFIX = 'credential:';

    private readonly SerializerInterface $serializer;

    public function __construct(
        private readonly \Predis\ClientInterface $redis,
        private readonly string $prefix,
        private readonly int $ttlSecs = 31_536_000,
        ?SerializerInterface $serializer = null,
    ) {
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $json = $this->redis->get($this->key($publicKeyCredentialId));
        if (!\is_string($json) || $json === '') {
            return null;
        }
        try {
            $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
        } catch (\Throwable) {
            // An unreadable record is no credential: the ceremony answers
            // unknown-credential instead of trusting broken bytes.
            return null;
        }

        return $record instanceof CredentialRecord ? $record : null;
    }

    /**
     * The enrolled credentials of a principal (the handler's allow-list
     * source and its creation/assertion branch decision). The stored
     * user handle is the raw principal pseudonym, the same value the
     * assertion ceremony compares the authenticator's user handle
     * against.
     *
     * @return list<CredentialRecord>
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
            try {
                $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
            } catch (\Throwable) {
                continue;
            }
            if (!$record instanceof CredentialRecord || $record->userHandle !== $principalPseudonym) {
                continue;
            }
            $found[] = $record;
        }

        return $found;
    }

    public function saveCredentialSource(CredentialRecord $record): void
    {
        $key = $this->key($record->publicKeyCredentialId);
        // Counter rollback guard: a write that would lower the stored
        // sign count is refused (fail-closed). A cloned or raced
        // authenticator can then never rewind the counter and re-use an
        // old assertion slot.
        $existingJson = $this->redis->get($key);
        if (\is_string($existingJson) && $existingJson !== '') {
            try {
                $existing = $this->serializer->deserialize($existingJson, CredentialRecord::class, 'json');
                if ($existing instanceof CredentialRecord && $record->counter < $existing->counter) {
                    return;
                }
            } catch (\Throwable) {
                // Unreadable prior record: fall through and overwrite
                // with the validated record (fail-closed on the
                // counter is impossible without a readable prior).
            }
        }
        $this->redis->setex(
            $key,
            $this->ttlSecs,
            (string) $this->serializer->serialize($record, 'json'),
        );
    }

    private function key(string $credentialId): string
    {
        return $this->prefix.self::KEY_PREFIX.hash('sha256', $credentialId);
    }
}
