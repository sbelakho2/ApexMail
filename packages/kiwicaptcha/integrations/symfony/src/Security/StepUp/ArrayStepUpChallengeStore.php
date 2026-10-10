<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * In-memory step-up store for test and dev semantics: single-process
 * only. The production wiring of the step-up plane always sits on the
 * Redis store (risk.enabled requires a risk Redis client), so this
 * implementation exists for unit tests and offline kernels.
 *
 * Mirrors the Redis store exactly, with an explicit clock: expiry is
 * evaluated on read, consume is a read-and-remove, and the attempt
 * accounting answers the same contract. Every record round-trips
 * through the strict wire decode, so this store observes the identical
 * schema the Redis store persists.
 */
final class ArrayStepUpChallengeStore implements StepUpChallengeStore
{
    /** @var array<string, array{record: StepUpChallenge, expiresAt: int}> */
    private array $challenges = [];

    /** @var array<string, int> */
    private array $beginWindows = [];

    /** @var array<string, string> */
    private array $totpSecrets = [];

    /** @var array<string, int> */
    private array $totpSteps = [];

    /** @var array<string, array{at: int, expires: int}> principal -> completion marker */
    private array $stepUpSuccess = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> failure count */
    private array $lockoutFailures = [];

    /** @var array<string, int> "<dimension>:<pseudonym>" -> lockout deadline (epoch secs) */
    private array $lockoutUntil = [];

    public function __construct(
        private readonly ?\Closure $now = null,
    ) {
    }

    public function create(StepUpChallenge $challenge, int $ttlSecs): string
    {
        $this->challenges[$challenge->id] = [
            'record' => StepUpChallenge::fromJson((string) json_encode($challenge->toArray(), JSON_UNESCAPED_SLASHES)),
            'expiresAt' => ($this->now()) + max(1, $ttlSecs),
        ];

        return $challenge->id;
    }

    public function read(string $challengeId): ?StepUpChallenge
    {
        return $this->live($challengeId);
    }

    public function consume(string $challengeId): ?StepUpChallenge
    {
        $record = $this->live($challengeId);
        if ($record !== null) {
            unset($this->challenges[$challengeId]);
        }

        return $record;
    }

    public function recordFailure(string $challengeId, int $maxAttempts): int
    {
        $record = $this->live($challengeId);
        if ($record === null) {
            return -1;
        }
        $attempts = $record->attempts + 1;
        if ($attempts >= max(1, $maxAttempts)) {
            unset($this->challenges[$challengeId]);

            return 0;
        }
        $this->challenges[$challengeId]['record'] = $record->withAttempts($attempts);

        return $attempts;
    }

    public function countBegin(string $principalPseudonym, int $windowSecs): int
    {
        $this->beginWindows[$principalPseudonym] = ($this->beginWindows[$principalPseudonym] ?? 0) + 1;

        return $this->beginWindows[$principalPseudonym];
    }

    public function saveTotpSecret(string $principalPseudonym, string $secretRaw): void
    {
        $this->totpSecrets[$principalPseudonym] = $secretRaw;
    }

    public function findTotpSecret(string $principalPseudonym): ?string
    {
        return $this->totpSecrets[$principalPseudonym] ?? null;
    }

    public function markTotpStep(string $principalPseudonym, int $step, int $ttlSecs): bool
    {
        if (($this->totpSteps[$principalPseudonym] ?? -1) >= $step) {
            return false;
        }
        $this->totpSteps[$principalPseudonym] = $step;

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function live(string $challengeId): ?StepUpChallenge
    {
        $entry = $this->challenges[$challengeId] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->now() >= $entry['expiresAt']) {
            unset($this->challenges[$challengeId]);

            return null;
        }

        return $entry['record'];
    }
    public function markStepUpSuccess(string $principalPseudonym, int $ttlSecs, int $now): void
    {
        $this->stepUpSuccess[$principalPseudonym] = ['at' => $now, 'expires' => $now + $ttlSecs];
    }

    public function recentStepUpSuccess(string $principalPseudonym, int $withinSecs, int $now): bool
    {
        $marker = $this->stepUpSuccess[$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now) {
            return false;
        }

        return ($now - $marker['at']) <= $withinSecs;
    }

    /** @var array<string, array{at: int, expires: int, factor: string}> */
    private array $sessionStepUpSuccess = [];

    public function markSessionStepUpSuccess(string $sessionId, string $principalPseudonym, string $factor, int $ttlSecs, int $now): void
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return;
        }
        $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] = [
            'at' => $now,
            'expires' => $now + $ttlSecs,
            'factor' => $factor,
        ];
    }

    public function recentSessionStepUpSuccess(string $sessionId, string $principalPseudonym, ?string $minFactor, int $withinSecs, int $now): bool
    {
        if ($sessionId === '' || $principalPseudonym === '') {
            return false;
        }
        $marker = $this->sessionStepUpSuccess[$sessionId."\0".$principalPseudonym] ?? null;
        if ($marker === null || $marker['expires'] <= $now || ($now - $marker['at']) > $withinSecs) {
            return false;
        }
        if ($minFactor !== null && self::factorRank($marker['factor']) < self::factorRank($minFactor)) {
            return false;
        }

        return true;
    }

    /** webauthn > totp > email_otp > unknown. */
    private static function factorRank(string $factor): int
    {
        return match ($factor) {
            'webauthn' => 3,
            'totp' => 2,
            'email_otp' => 1,
            default => 0,
        };
    }

    public function countLockoutFailure(string $dimension, string $pseudonym, int $windowSecs): int
    {
        $key = $dimension.':'.$pseudonym;
        $this->lockoutFailures[$key] = ($this->lockoutFailures[$key] ?? 0) + 1;

        return $this->lockoutFailures[$key];
    }

    public function lockoutUntil(string $dimension, string $pseudonym, int $now): int
    {
        $until = $this->lockoutUntil[$dimension.':'.$pseudonym] ?? 0;

        return $until > $now ? $until : 0;
    }

    public function armLockout(string $dimension, string $pseudonym, int $now, int $ttlSecs): void
    {
        $key = $dimension.':'.$pseudonym;
        $until = $now + max(1, $ttlSecs);
        if (($this->lockoutUntil[$key] ?? 0) < $until) {
            $this->lockoutUntil[$key] = $until;
        }
    }

    public function clearLockout(string $dimension, string $pseudonym): void
    {
        $key = $dimension.':'.$pseudonym;
        unset($this->lockoutFailures[$key], $this->lockoutUntil[$key]);
    }
}
