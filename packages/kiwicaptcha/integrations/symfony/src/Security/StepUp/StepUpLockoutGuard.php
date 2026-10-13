<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;

/**
 * The cross-challenge brute-force budget of the step-up plane. The
 * per-challenge attempt cap alone allows about 1440 guesses a day.
 * That is 3 begins per 15-minute window times 5 attempts times 96
 * windows. The verification failures feed an escalating lockout with
 * three budget keys. The context key is the pair of principal and
 * requesting session or network bucket. That is the primary ladder.
 * It locks the failing context only. The principal key is the
 * account-wide backstop. It escalates on the same ladder. Its
 * thresholds are multiplied by 5. The target key is the shared target
 * budget. It uses the same high-threshold ladder. A begin from the
 * owner trusted context bypasses the shared keys. The requesting
 * context budget is never bypassed. Each failure bumps the context
 * key and both shared keys. At every threshold the matching lockout
 * is armed. The owner is notified exactly when the ladder rung
 * changes.
 */
final class StepUpLockoutGuard
{
    public const DIMENSION_PRINCIPAL = 'principal';
    public const DIMENSION_TARGET = 'target';
    public const DIMENSION_CONTEXT = 'context';

    /**
     * The per-context escalation ladder: [failures within the window,
     * lockout seconds]. The default ladder walks 5 to 5 minutes, 15 to
     * 30 minutes, 40 to 2 hours, and 100 to 24 hours. A sustained
     * campaign ends in a full-day lockout of the failing context. A
     * handful of typos costs five minutes of that context only.
     */
    public const DEFAULT_LADDER = [
        [5, 300],
        [15, 1800],
        [40, 7200],
        [100, 86400],
    ];

    /** The fixed failure-counter window: one day, the brute-force budget horizon. */
    public const DEFAULT_WINDOW_SECS = 86400;

    /**
     * The shared (account-wide / target-wide) backstop multiplier:
     * those keys arm only at 5× the per-context thresholds, so one
     * attacking context can never lock the owner's account cheaply.
     */
    public const ACCOUNT_BACKSTOP_MULTIPLIER = 5;

    /** How far back a session's own completed step-up makes it trusted. */
    public const TRUSTED_LOOKBACK_SECS = 900;

    /** @var list<array{0: int, 1: int}> */
    private readonly array $ladder;

    /** @var list<array{0: int, 1: int}> */
    private readonly array $accountLadder;

    /**
     * @param list<array{0: int, 1: int}> $ladder       the per-context
     *                                             escalation ladder. It
     *                                             is ascending in both
     *                                             fields.
     * @param StepUpOwnerNotifier|null    $notifyOwner called when the
     *                                             ladder rung changes
     *                                             (a lockout is armed
     *                                             or extended), not on
     *                                             every failure past
     *                                             the threshold
     * @param \Closure|null               $now        the epoch-seconds
     *                                             clock override for
     *                                             tests
     */
    public function __construct(
        private readonly StepUpChallengeStore $store,
        array $ladder = self::DEFAULT_LADDER,
        private readonly int $windowSecs = self::DEFAULT_WINDOW_SECS,
        private readonly ?StepUpOwnerNotifier $notifyOwner = null,
        private readonly ?\Closure $now = null,
    ) {
        if ($ladder === []) {
            throw new \InvalidArgumentException('The step-up lockout ladder must not be empty');
        }
        $previousFailures = 0;
        $previousLockout = 0;
        foreach ($ladder as $rung) {
            if (!\is_array($rung) || \count($rung) !== 2 || $rung[0] <= $previousFailures || $rung[1] <= $previousLockout) {
                throw new \InvalidArgumentException('The step-up lockout ladder must be strictly ascending in failures and lockout seconds');
            }
            $previousFailures = (int) $rung[0];
            $previousLockout = (int) $rung[1];
        }
        $this->ladder = array_map(static fn (array $rung): array => [(int) $rung[0], (int) $rung[1]], $ladder);
        // The shared keys (account-wide, target-wide) arm only at a
        // high threshold: the same ladder with every failure count
        // multiplied by account_BACKSTOP_MULTIPLIER, same durations.
        $this->accountLadder = array_map(
            static fn (array $rung): array => [$rung[0] * self::ACCOUNT_BACKSTOP_MULTIPLIER, $rung[1]],
            $this->ladder,
        );
        if ($this->windowSecs < 1) {
            throw new \InvalidArgumentException('The step-up lockout window must be positive');
        }
    }

    /**
     * The budget key of the requesting context: the started session when
     * there is one, else the client's network bucket. Hashed, the store
     * keys carry opaque ids only, never a raw session id or address.
     */
    public static function contextKeyOf(Request $request): string
    {
        $sessionId = StepUpSessionBinding::sessionId($request);
        if ($sessionId !== '') {
            return 'sess:'.hash('sha256', $sessionId);
        }
        $ip = (string) ($request->getClientIp() ?? '');

        return $ip !== '' ? 'net:'.hash('sha256', $ip) : 'net:anonymous';
    }

    /**
     * The opaque (dimension, pseudonym) pair of the per-(principal,
     * context) budget. The composite is hashed so no raw session id or
     * address rides a store key.
     */
    private static function contextPseudonym(string $principalPseudonym, string $contextKey): string
    {
        return hash('sha256', $principalPseudonym.'|'.$contextKey);
    }

    /**
     * Whether the request rides the owner's trusted context: a session
     * that completed a step-up (any factor) within the lookback. Such a
     * begin — and its matching completion, may proceed despite an
     * attacker-induced lock on the shared keys. A stateless request can
     * never be trusted (fail closed).
     */
    public function isTrustedContext(Request $request, string $principalPseudonym, ?int $now = null): bool
    {
        $sessionId = StepUpSessionBinding::sessionId($request);
        if ($sessionId === '') {
            return false;
        }

        return $this->store->recentSessionStepUpSuccess(
            $sessionId,
            $principalPseudonym,
            null,
            self::TRUSTED_LOOKBACK_SECS,
            $now ?? $this->now(),
        );
    }

    /**
     * The seconds the request must still wait, 0 when admissible. The
     * requesting context's own deadline always applies; the shared
     * (account-wide, target-wide) deadlines apply only when the request
     * is not trusted, a trusted context or the WebAuthn assertion path
     * begins (and completes) despite an attacker-induced shared lock.
     */
    public function retryAfterSecs(
        string $principalPseudonym,
        ?string $targetPseudonym,
        ?int $now = null,
        ?string $contextKey = null,
        bool $bypassSharedLocks = false,
    ): int {
        $now ??= $this->now();
        $deadlines = [];
        if ($contextKey !== null && $contextKey !== '') {
            $deadlines[] = $this->store->lockoutUntil(
                self::DIMENSION_CONTEXT,
                self::contextPseudonym($principalPseudonym, $contextKey),
                $now,
            );
        }
        if (!$bypassSharedLocks) {
            $deadlines[] = $this->store->lockoutUntil(self::DIMENSION_PRINCIPAL, $principalPseudonym, $now);
            if ($targetPseudonym !== null && $targetPseudonym !== '') {
                $deadlines[] = $this->store->lockoutUntil(self::DIMENSION_TARGET, $targetPseudonym, $now);
            }
        }

        return max(0, max($deadlines === [] ? [0] : $deadlines) - $now);
    }

    /**
     * Record one failed verification: the requesting context's budget is
     * bumped on the primary ladder, and both shared keys on the
     * high-threshold backstop, so a single attacking context can never
     * arm the account-wide or target-wide lock cheaply.
     */
    public function registerFailure(string $principalPseudonym, ?string $targetPseudonym, ?string $contextKey = null): void
    {
        $now = $this->now();
        if ($contextKey !== null && $contextKey !== '') {
            $this->escalate(self::DIMENSION_CONTEXT, self::contextPseudonym($principalPseudonym, $contextKey), $now, $this->ladder);
        }
        $this->escalate(self::DIMENSION_PRINCIPAL, $principalPseudonym, $now, $this->accountLadder);
        if ($targetPseudonym !== null && $targetPseudonym !== '') {
            $this->escalate(self::DIMENSION_TARGET, $targetPseudonym, $now, $this->accountLadder);
        }
    }

    /**
     * Clear the budgets: called on a completed step-up, so the verified
     * owner is not kept out by earlier typos while the attacker's budget
     * never resets (they never complete).
     */
    public function registerSuccess(string $principalPseudonym, ?string $targetPseudonym, ?string $contextKey = null): void
    {
        if ($contextKey !== null && $contextKey !== '') {
            $this->store->clearLockout(self::DIMENSION_CONTEXT, self::contextPseudonym($principalPseudonym, $contextKey));
        }
        $this->store->clearLockout(self::DIMENSION_PRINCIPAL, $principalPseudonym);
        if ($targetPseudonym !== null && $targetPseudonym !== '') {
            $this->store->clearLockout(self::DIMENSION_TARGET, $targetPseudonym);
        }
    }

    /**
     * @param list<array{0: int, 1: int}> $ladder
     */
    private function escalate(string $dimension, string $pseudonym, int $now, array $ladder): void
    {
        $failures = $this->store->countLockoutFailure($dimension, $pseudonym, $this->windowSecs);
        $lockoutSecs = $this->rungFor($failures, $ladder);
        if ($lockoutSecs === null) {
            return;
        }
        $this->store->armLockout($dimension, $pseudonym, $now, $lockoutSecs);
        // Notify only when the ladder rung changes: the previous
        // failure's rung is the same for every further failure inside a
        // threshold, and a per-failure hook would spam the owner for the
        // whole campaign.
        if ($this->rungFor($failures - 1, $ladder) !== $lockoutSecs) {
            $this->notifyOwner?->notifyLockout($dimension, $pseudonym, $now + $lockoutSecs, $failures);
        }
    }

    /**
     * The lockout seconds of the highest ladder rung at or below the
     * failure count, null below the first rung.
     *
     * @param list<array{0: int, 1: int}> $ladder
     */
    private function rungFor(int $failures, array $ladder): ?int
    {
        $lockoutSecs = null;
        foreach ($ladder as [$threshold, $secs]) {
            if ($failures >= $threshold) {
                $lockoutSecs = $secs;
            }
        }

        return $lockoutSecs;
    }

    private function now(): int
    {
        return ($this->now) ? (int) ($this->now)() : time();
    }
}
