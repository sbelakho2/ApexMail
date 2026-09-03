<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

use KiwiCaptcha\Rsw;

/**
 * Test-only RSW fixture keys and the browser-equivalent sequential
 * solver.
 *
 * The modulus and lambda below are a fixed 2048-bit pair generated for
 * the suites: n = p*q with two 1024-bit primes, and lambda =
 * lcm(p-1, q-1). The primes themselves are not kept anywhere in the
 * repository, so the trapdoor cannot be reconstructed from these
 * files; the values are fixtures, never production secrets.
 *
 * This surface exists because no production API may solve an rsw
 * challenge: solving is the client's sequential work. The browser
 * driver performs it in the worker asset, and tests need an
 * equivalent to prove the round trip. The solver here performs the
 * T sequential modular squarings exactly like the worker, so a
 * fixture token is byte-equivalent to a browser token. Never call
 * this class from a production path.
 */
final class RswFixture
{
    /** The shared 2048-bit modulus n (canonical standard base64). */
    public const MODULUS_N_B64 = 'sL1Mk2YZ4BnznBgWe2YB3uOZ+KFN/VETl1T0H9zuWkP54/nAN8sgPhqozDrRCVQxdJc5IDgkh9EemAGzYjku+zqv2fdryfy5iHbtQEhkHJVt+5f/6yxrZDvHUMhgDRAmLe7rRjEIZC8GqcfcbQyVECgxzNfd3FE+ATeuxc8wKafjUtQ/rvizFBJCo5L0r4U67JDooXVt4yTLtRsoFK3WZBOKIOSZ+E0vZJDt2ddeDSluS/qaqZ5C3dSVeaSyaelX8dGpmovr8xClC+9SKsFnMc+6m9WBo2CsCSpJGk3LZM2847HM5/r2gfmNdN5zRecjEY5MLLEQ/34JinuMtMJpuw==';

    /** The shared secret lambda = lcm(p-1, q-1) (canonical standard base64). */
    public const LAMBDA_B64 = 'WF6mSbMM8Az5zgwLPbMA73HM/FCm/qiJy6p6D+53LSH88fzgG+WQHw1UZh1ohKoYukuckBwSQ+iPTADZsRyXfZ1X7Pu15P5cxDt2oCQyDkq2/cv/9ZY1sh3jqGQwBogTFvd1oxiEMheDVOPuNoZKiBQY5mvu7iifAJvXYueYFNMcEwMJdHQi8lgNFBJMwNN+267oViuNdvXRtCLx0MeOSiIPOvDNnLU0Ba4bJg5mTXLY9llIMPtOuHU5BiN8E7IY8kKCdYlpJTgGqv+uu5aNS/SPQl3sMR8dIo3zn7wZhcsMyzJ1n/dLZHNSwXs3QX6XQU+Bx8OVz5pmJYPTJUdsEA==';

    /**
     * The browser-equivalent final value of an rsw challenge: base
     * squared T times modulo n, rendered as the fixed 512-hex wire
     * form. The base derivation is the shared challenge-derived rule.
     */
    public static function sequentialProof(string $prefix, string $nonce, int $t): string
    {
        $modulus = gmp_init(bin2hex(base64_decode(self::MODULUS_N_B64, true)), 16);
        $base = Rsw::deriveBase($prefix, $nonce, $modulus);
        for ($i = 0; $i < $t; ++$i) {
            $base = gmp_mod(gmp_mul($base, $base), $modulus);
        }

        return Rsw::proofHex($base);
    }
}
