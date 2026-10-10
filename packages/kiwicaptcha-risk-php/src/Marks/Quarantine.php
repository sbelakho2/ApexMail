<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

/**
 * The quarantine selection of the marks plane (change.md 1.3 and 3.3.4).
 *
 * Quarantine is a decision disposition, never a ladder rung. The
 * decision plane emits it on top of the Allow action for a
 * server-confirmed spam identity, and the wire stays indistinguishable
 * from allow end to end (same challenge bytes shape, same difficulty,
 * same timing within the noise floor). The app accepts the submission
 * and withholds it from publication; the app-facing surfaces carry the
 * flag (kiwi.quarantine), never the HTTP responses.
 *
 * The selection rule is exact. Every in-TTL own-dimension mark of the
 * request carries the server-confirmed spam kind (spamReported, the
 * mark the outcomes plane writes for the SpamReported outcome). At
 * least one such mark exists. No target-dimension mark is in TTL, and
 * the request carries no corroborating attacker evidence. Under those
 * conditions and a plain Allow decision the marks stage quarantines
 * instead of escalating.
 *
 * The precedence is severity-monotonic, so the more severe disposition
 * always wins:
 *
 * - Spam marks only, plain Allow, clean request: quarantine.
 * - Corroborating evidence next to any own mark: deny.
 * - Any non-spam own mark in TTL: the marked-identity rung floor.
 * - A target mark in TTL: the step-up victim ceiling.
 * - A plain action above Allow: that action, unchanged.
 * - A mark outside its TTL window: plain allow, never quarantine.
 * - A later stage that raises the action: the raised action wins and
 *   the quarantine flag drops.
 *
 * A mixed picture (a spam mark next to a fraudConfirmed mark, or a
 * target mark) is never a quarantine: the stronger treatment of the
 * other mark wins. A spam mark alone above the Allow band changes
 * nothing: the plain action stands and the stage only adds its
 * marked-identity reason, exactly like the legacy rules.
 */
final class Quarantine
{
    /** The mark kind the outcomes plane writes for the SpamReported outcome. */
    public const SPAM_MARK_KIND = 'spamReported';

    /**
     * True when the view selects quarantine: at least one in-TTL own
     * mark, every in-TTL own mark of the spam kind, no in-TTL target
     * mark and no corroboration. The plain Allow requirement is the
     * caller's (the stage checks it against the decision).
     */
    public static function selects(MarksView $view, bool $corroborated, int $nowMs, int $markTtlMs): bool
    {
        if ($corroborated) {
            return false;
        }

        return self::spamOnly($view, $nowMs, $markTtlMs)
            && $view->targetInTtl($nowMs, $markTtlMs) === null;
    }

    /**
     * True when the identity's live mark set is spam-only: at least one
     * in-TTL own mark and every in-TTL own mark of the spam kind. The
     * stage uses this to keep the Argon64 floor a non-spam treatment: a
     * spam-only identity above the Allow band keeps its plain action.
     */
    public static function spamOnly(MarksView $view, int $nowMs, int $markTtlMs): bool
    {
        $own = $view->ownInTtl($nowMs, $markTtlMs);
        if ($own === []) {
            return false;
        }
        foreach ($own as $mark) {
            if ($mark['kind'] !== self::SPAM_MARK_KIND) {
                return false;
            }
        }

        return true;
    }
}
