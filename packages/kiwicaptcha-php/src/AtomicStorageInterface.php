<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Marker interface for storage backends that guarantee STRICT single-use
 * under concurrency (round 29 wording — this describes the ACTUAL
 * retained consumed-state protocol, not a load-and-delete model):
 *
 * `consume()` performs an ATOMIC pending->consumed TRANSITION. The record
 * is NOT deleted — it is kept (until TTL) marked consumed, so a later
 * caller observes `consumedBefore = true` and, when the first consumer has
 * committed, the stored deterministic result. Exactly ONE concurrent
 * caller can win `consumedNow`; the others see the committed outcome
 * without re-deriving a proof. This is what makes the PHP verifier's
 * deterministic replay path correct: the second call does NOT return null
 * and does NOT re-verify — it resolves to the stored outcome.
 *
 * Plain {@see StorageInterface} implementations (e.g. PSR-6 pools) are
 * best-effort: consume() reads and writes the retained record, but the
 * read and the write cannot be fused, so two racing requests can both
 * observe the pending state and BOTH win `consumedNow` (the documented
 * PSR-6 race — refused for production verification by the Symfony bundle
 * unless the explicitly-named best-effort escape hatch is chosen, and
 * refused for Siteverify outright).
 */
interface AtomicStorageInterface extends StorageInterface
{
}
