<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskReason;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

/**
 * Decisive attacker handling: the additive post-policy decision stage of
 * the marks plane (change.md 3.3.3). The stage runs after
 * RiskPolicy::decide() and only when a marks reader is wired into the
 * engine; the plain decision path of an unwired engine is identical to
 * before. Three rules, in order:
 *
 * 1. A mark on one of the requesting identity's own dimensions
 *    (session, principal, agent or the ASN bucket) escalates the chosen
 *    action to at least the ladder's maximum challenge rung (Argon64).
 *    StepUp and Deny keep their rank. A saturated argon backend
 *    re-escalates the rung to the interactive step-up exactly like the
 *    policy's own capacity check.
 * 2. A mark combined with corroborating attacker evidence on the same
 *    request denies for the remaining mark TTL. Corroborating evidence
 *    means bad-proof, replay or malformed traffic at the policy's
 *    corroboration floor, or decoy evidence. The deny holds while
 *    now < last_ms + mark TTL, and the decision's retry hint carries
 *    the saturated remainder.
 * 3. A mark on the login target the request presents (a login attempt
 *    against an attacked account) maps to StepUp and nothing stronger.
 *    Target evidence never escalates the requesting identity's own
 *    dimensions beyond the interactive step-up, so a victim can always
 *    finish logging in.
 *
 * Victim-protection invariant (property-tested): when only target-side
 * evidence fires, the final action equals the plain action or StepUp,
 * never Argon64 and never Deny.
 *
 * A mark outside its TTL window is inert: the stage treats it as absent
 * for both the rung and the deny rule, the belt to the store's own key
 * expiry for stores without one.
 *
 * Quarantine selection (change.md 1.3 and 3.3.4, see Marks\Quarantine):
 * the $quarantineSpamMarks flag arms the engine's decision-plane
 * posture. When every in-TTL own mark is the server-confirmed spam kind
 * with no corroboration and no target mark, a plain Allow decision
 * quarantines instead of escalating. The action stays Allow (wire
 * identical to allow end to end, same rung and pricing), the decision
 * carries the quarantine disposition and the spam_mark_quarantine
 * reason. A spam mark never runs the Argon64 floor: above the Allow
 * band the plain action stands (severity wins) with the ordinary
 * marked_identity reason. The deny, target and non-spam-mark rules keep
 * their precedence over quarantine. The legacy corpus
 * (attacker-denial-vectors.json) pins rules 1 to 3 with the selection
 * off; the quarantine corpus (quarantine-vectors.json) pins the
 * selection and its precedence with it on.
 */
final class MarksEscalation
{

    /** The D3.5 target-attack threshold (Rust mirror: marks::TARGET_ATTACK_THRESHOLD). */
    public const TARGET_ATTACK_THRESHOLD = 5;

    /**
     * The scope failure-ratio pressure floor for first-attempt login
     * escalation (Rust mirror: marks::`SCOPE_PRESSURE`_FLOOR): at/above
     * this global_pressure signal (or global level
     * `SCOPE_PRESSURE`_LEVEL) every login escalates to the interactive
     * step-up, not only the attacked target's.
     */
    public const SCOPE_PRESSURE_FLOOR = 300;

    /** The global hysteresis level at which scope pressure escalates first-attempt logins. */
    public const SCOPE_PRESSURE_LEVEL = 1;

    /** The whole-window default: the store's 90-day mark TTL in ms. */
    public const DEFAULT_MARK_TTL_MS = RedisRiskStateStore::DEFAULT_MARK_TTL_SECS * 1000;

    /**
     * The corroborating-evidence floor of the policy's own hard
     * overrides (bad_proof >= 300, replay >= 300, malformed >= 300).
     * The stage corroborates a mark with the identical threshold, so
     * the two cores and the policy never disagree about what counts as
     * attacker evidence.
     */
    public const CORROBORATION_FLOOR = 300;

    /**
     * Below this argon capacity the strongest rung re-escalates to
     * StepUp (the policy's own capacity check, applied to the mark rung
     * too).
     */
    private const ARGON_CAPACITY_FLOOR = 300;

    /**
     * True when the request's own evidence corroborates a mark: bad-proof,
     * replay or malformed traffic at the policy's corroboration floor, or
     * any decoy evidence (a honeypot event kind or the v2 context's
     * honeypot flag, supplied by the caller as $decoyEvidence).
     */
    public static function corroborated(SignalVector $s, bool $decoyEvidence): bool
    {
        return $s->badProof >= self::CORROBORATION_FLOOR
            || $s->malformed >= self::CORROBORATION_FLOOR
            || $s->replay >= self::CORROBORATION_FLOOR
            || $decoyEvidence;
    }

    /**
     * The decisive stage: combines the plain decision with the request's
     * marks view. Pure; the plain decision's score, band, policy
     * version, model revision, global level and decision id pass through
     * untouched. Stage reasons prepend exactly like the policy's hard
     * overrides, then deduplicate and cap at 4.
     *
     * $quarantineSpamMarks arms the quarantine selection (the engine's
     * decision-plane posture). The default false keeps the legacy rules
     * exactly, the posture the shared attacker-denial corpus pins.
     */
    public static function apply(
        RiskDecision $plain,
        MarksView $view,
        bool $corroborated,
        int $nowMs,
        int $markTtlMs,
        ResourcePressure $resources,
        bool $quarantineSpamMarks = false,
    ): RiskDecision {
        $action = $plain->action;
        $retryAfterMs = $plain->retryAfterMs;
        $quarantined = false;
        $stageReasons = [];

        // Rule 1 and 2: the requesting identity's own marks.
        $mark = $view->freshestOwnInTtl($nowMs, $markTtlMs);
        if ($mark !== null) {
            if ($corroborated) {
                $action = RiskAction::Deny;
                $deadline = $mark['last_ms'] + $markTtlMs;
                // inTtl guaranteed deadline > now, so the subtraction
                // cannot go negative; the u32 wire field saturates like
                // the cooldown hint.
                $retryAfterMs = min(4294967295, $deadline - $nowMs);
                $stageReasons[] = RiskReason::CorroboratedAbuse;
            } elseif (
                $quarantineSpamMarks
                && $action === RiskAction::Allow
                && Quarantine::selects($view, false, $nowMs, $markTtlMs)
            ) {
                // The quarantine disposition: server-confirmed spam, clean
                // request, plain Allow. The action stays Allow (never a
                // rung change, never a capacity re-escalation), so the
                // issued challenge is wire-identical to allow.
                $quarantined = true;
                $stageReasons[] = RiskReason::SpamMarkQuarantine;
            } else {
                $stageReasons[] = RiskReason::MarkedIdentity;
                // The Argon64 floor belongs to the non-spam marks: a
                // spam-only identity is the quarantine plane's subject, so
                // above the Allow band its plain action stands (severity
                // wins) and the stage adds no rung of its own.
                if (!$quarantineSpamMarks || !Quarantine::spamOnly($view, $nowMs, $markTtlMs)) {
                    if ($action->rank() < RiskAction::Argon64->rank()) {
                        $action = RiskAction::Argon64;
                        if ($resources->argonCapacity < self::ARGON_CAPACITY_FLOOR) {
                            $action = RiskAction::StepUp;
                            $stageReasons[] = RiskReason::CapacityPressure;
                        }
                    }
                }
            }
        }

        // Rule 3: the presented target. The guard is the victim
        // protection: target evidence tops out at StepUp, so an attacked
        // account's owner can always finish the interactive login. The
        // step-up outranks the quarantine disposition, so a target mark
        // drops it.
        if ($view->targetInTtl($nowMs, $markTtlMs) !== null) {
            $quarantined = false;
            if ($action->rank() < RiskAction::StepUp->rank()) {
                $action = RiskAction::StepUp;
            }
            $stageReasons[] = RiskReason::TargetUnderAttack;
        }

        // Rule 4: first-attempt prevention (P0-1). A valid credential on
        // its very first attempt carries no marks and no target history,
        // so rules 1-3 stay silent — exactly the D3.5 hole. Any of the
        // three signals (novel network, a known-breached credential, or
        // scope failure-ratio pressure at/above the floor) forces the
        // interactive step-up before any session credit, and tops out at
        // StepUp like target evidence: the legitimate owner must always
        // be able to finish the login (never Deny, never a rung).
        $firstAttempt = $view->firstAttempt();
        if ($firstAttempt->requiresStepUp()) {
            $quarantined = false;
            if ($action->rank() < RiskAction::StepUp->rank()) {
                $action = RiskAction::StepUp;
            }
            if ($firstAttempt->novelNetwork) {
                $stageReasons[] = RiskReason::NovelNetwork;
            }
            if ($firstAttempt->breachedCredential) {
                $stageReasons[] = RiskReason::BreachedCredential;
            }
            if ($firstAttempt->scopePressure) {
                $stageReasons[] = RiskReason::GlobalAttack;
            }
        }

        if ($stageReasons === []) {
            return $plain;
        }

        $reasons = $stageReasons;
        foreach ($plain->reasons as $reason) {
            if (!in_array($reason, $reasons, true)) {
                $reasons[] = $reason;
            }
        }

        return new RiskDecision(
            score: $plain->score,
            action: $action,
            reasons: array_slice($reasons, 0, 4),
            policyVersion: $plain->policyVersion,
            globalLevel: $plain->globalLevel,
            retryAfterMs: $retryAfterMs,
            band: $plain->band,
            decisionId: $plain->decisionId,
            modelRevision: $plain->modelRevision,
            quarantined: $quarantined,
        );
    }

    /**
     * The fail-closed fallback for an unreadable marks surface: the
     * request is treated as a marked identity with an unknown window.
     * The action floors at the maximum challenge rung (capacity-aware),
     * but no deny is fabricated from evidence that could not be read.
     */
    public static function applyUnreadable(
        RiskDecision $plain,
        int $nowMs,
        ResourcePressure $resources,
    ): RiskDecision {
        $view = MarksView::fromParts(
            ['session' => ['kind' => 'unreadable', 'last_kind' => 'unreadable', 'count' => 1, 'first_ms' => $nowMs, 'last_ms' => $nowMs]],
            null,
        );

        return self::apply($plain, $view, false, $nowMs, 1, $resources);
    }
}
