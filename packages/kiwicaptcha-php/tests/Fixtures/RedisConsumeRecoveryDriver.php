<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;

final class RedisConsumeRecoveryDriver implements ConsumeRecoveryDriver
{
    private const ISSUED_AT = 1_800_000_000;

    private readonly RedisStorage $storage;

    private readonly Issuer $issuer;

    private readonly Verifier $verifier;

    private readonly string $prefix;

    public function __construct(private readonly \Predis\Client $client)
    {
        $this->prefix = 'consume-walk-'.bin2hex(random_bytes(4)).'-';
        $this->storage = new RedisStorage($client, $this->prefix);
        $this->issuer = new Issuer(
            new Config(secretKey: ConsumeRecoveryWalk::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $this->storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $this->verifier = new Verifier($this->storage, now: static fn (): int => self::ISSUED_AT + 100);
    }

    public function issue(): string
    {
        return $this->issuer->issue('login', '198.51.100.7')->nonce;
    }

    public function consume(string $nonce, ?string $identity): ?array
    {
        $consumed = $identity !== null
            ? $this->storage->consumeWithOperationIdentity($nonce, $identity)
            : $this->storage->consume($nonce);
        if ($consumed === null) {
            return null;
        }

        return [
            'win' => $consumed->consumedNow,
            'lose' => $consumed->consumedBefore,
            'resultValid' => $consumed->consumedResult?->valid,
            'identity' => $consumed->operationIdentity,
        ];
    }

    public function commit(string $nonce, bool $valid, ?string $owner): bool
    {
        return $owner !== null
            ? $this->storage->commitResultResume($nonce, $valid, null, $owner)
            : $this->storage->commitResult($nonce, $valid, null);
    }

    public function claim(string $nonce, int $ttlSecs): ?string
    {
        return $this->storage->claimResumeDerivation($nonce, $ttlSecs);
    }

    public function expireClaim(string $nonce): bool
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || !str_contains($raw, '"resume_until"')) {
            return false;
        }
        $now = $this->now();
        if (preg_match('/"resume_until":(\d+)/', $raw, $match) === 1 && (int) $match[1] <= $now) {
            return false;
        }
        $past = $now - 1000;
        $rewritten = preg_replace('/,"resume_until":\d+}$/', ',"resume_until":'.$past.'}', $raw, 1);
        if ($rewritten === null || $rewritten === $raw) {
            return false;
        }
        $ttl = max(1, (int) $this->client->ttl($this->prefix.$nonce));
        $this->client->set($this->prefix.$nonce, $rewritten, 'EX', $ttl);

        return true;
    }

    public function release(string $nonce, string $owner): bool
    {
        return $this->storage->releaseResumeDerivation($nonce, $owner);
    }

    public function replay(string $nonce, ?string $operationIdentity): string
    {
        $token = SolutionToken::create($nonce, 0, 0, [])->encode();
        $outcome = $this->verifier->verify(
            $token,
            ConsumeRecoveryWalk::SECRET,
            'login',
            '198.51.100.7',
            (self::ISSUED_AT + 100) * 1_000_000,
            operationIdentity: $operationIdentity,
        );
        if ($outcome->isOk()) {
            return $outcome->fromStoredResult ? 'granted' : 'not_consumed';
        }
        if ($outcome->error === VerifyError::ConsumeIndeterminate) {
            return 'indeterminate';
        }
        if ($outcome->error === VerifyError::InsufficientWork) {
            return 'insufficient';
        }
        if ($outcome->error === VerifyError::AlreadyConsumed) {
            return 'already_consumed';
        }

        return 'not_consumed';
    }

    public function vanish(string $nonce): void
    {
        $this->client->del($this->prefix.$nonce);
    }

    public function cancel(string $nonce): ?string
    {
        return $this->storage->cancel($nonce)?->state;
    }

    public function readState(string $nonce): ?array
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($data)) {
            return null;
        }
        $consumed = str_contains($raw, '"state":"consumed"');
        $cancelled = str_contains($raw, '"state":"cancelled"');
        if ($cancelled) {
            $state = ConsumeRecoveryModel::CANCELLED;
        } elseif ($consumed) {
            $state = $data['consumed_result'] === null
                ? ConsumeRecoveryModel::CONSUMED_RESULTLESS
                : ((int) ($data['consumed_result']['valid'] ?? 0) === 1
                    ? ConsumeRecoveryModel::COMMITTED_VALID
                    : ConsumeRecoveryModel::COMMITTED_INVALID);
        } else {
            $state = ConsumeRecoveryModel::PENDING;
        }
        $resultValid = \is_array($data['consumed_result'] ?? null) ? (bool) ($data['consumed_result']['valid'] ?? false) : null;
        $claimOwner = \is_string($data['resume_owner'] ?? null) ? $data['resume_owner'] : null;
        $claimLive = \is_int($data['resume_until'] ?? null) && $data['resume_until'] > $this->now();

        return [
            'state' => $state,
            'identity' => \is_string($data['operation_identity'] ?? null) ? $data['operation_identity'] : null,
            'resultValid' => $resultValid,
            'claimOwner' => $claimOwner,
            'claimLive' => $claimLive,
        ];
    }

    private function now(): int
    {
        $time = $this->client->time();
        if (\is_array($time) && isset($time[0])) {
            return (int) $time[0];
        }

        return time();
    }
}
