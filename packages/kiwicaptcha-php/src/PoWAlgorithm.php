<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The proof-of-work algorithm a challenge uses.
 *
 * The algorithm is carried explicitly on every challenge (never inferred
 * from a numeric flag), so the solver and the verifier can never
 * disagree about which computation to run.
 */
enum PoWAlgorithm: string
{
    /** Classic CPU-bound SHA-256 proof-of-work. */
    case Sha256 = 'sha256';

    /** Memory-hard Argon2id proof-of-work (asic/gpu resistant). */
    case Argon2id = 'argon2id';
}
