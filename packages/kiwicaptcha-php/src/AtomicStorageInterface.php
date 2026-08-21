<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Marker interface for storage backends that guarantee strict single-use
 * under concurrency. This describes the actual retained consumed-state
 * protocol, not a load-and-delete model.
 *
 * `consume()` performs an atomic pending->consumed transition. The record
 * is not deleted; it is kept (until TTL) marked consumed, so a later
 * caller observes `consumedBefore = true` and, when the first consumer
 * has committed, the stored deterministic result. Exactly one concurrent
 * caller can win `consumedNow`; the others see the committed outcome
 * without re-deriving a proof. This is what makes the PHP verifier's
 * deterministic replay path correct: the second call does not return
 * null and does not re-verify; it resolves to the stored outcome.
 *
 * Plain {@see StorageInterface} implementations (e.g. PSR-6 pools) are
 * best-effort: consume() reads and writes the retained record, but the
 * read and the write cannot be fused, so two racing requests can both
 * observe the pending state and both win `consumedNow`. That documented
 * PSR-6 race is refused for production verification by the Symfony
 * bundle unless the explicitly-named best-effort escape hatch is chosen,
 * and refused for Siteverify outright.
 */
interface AtomicStorageInterface extends StorageInterface
{
}
