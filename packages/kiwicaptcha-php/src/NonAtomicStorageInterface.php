<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Capability marker for storage backends whose consume() transition is
 * NOT atomic under concurrency: two racing requests can both observe
 * the pending state before either marks it consumed (both may win
 * consumedNow). This is the negative of
 * {@see AtomicStorageInterface}: a backend is either one or neither.
 *
 * Consumers that need strict single-use (replay protection that holds
 * under concurrency — Siteverify, any authorization-grade redemption)
 * must test for this marker and refuse the backend, exactly as the
 * Symfony bundle refuses non-{@see AtomicStorageInterface} storages for
 * Siteverify. The plain {@see Verifier} still works with a non-atomic
 * backend (best-effort single-use plus the proof-phase re-check that
 * fails a swapped record closed as MalformedRecord), but it emits a
 * one-time loud deprecation warning at construction so a
 * misconfiguration cannot stay silent.
 *
 * PSR-6 pools are the canonical example ({@see \KiwiCaptcha\Storage\Psr6Storage}):
 * the read and the write cannot be fused, so the one-shot transition is
 * best-effort by design.
 */
interface NonAtomicStorageInterface extends StorageInterface
{
}
